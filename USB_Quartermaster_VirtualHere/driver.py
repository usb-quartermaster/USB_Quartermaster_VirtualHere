import logging
import platform
import re
import time
from multiprocessing import Process
from multiprocessing import Queue
from pathlib import Path
from queue import Empty
from typing import Optional, NamedTuple, Dict, Iterable
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from USB_Quartermaster_common import AbstractRemoteHostDriver, AbstractShareableDeviceDriver, CommandResponse, \
    AbstractLocalDriver

logger = logging.getLogger(__name__)

DEFAULT_CLIENT_LINUX = "vhclientx86_64"
DEFAULT_CLIENT_MAC = "/Applications/VirtualHere.app/Contents/MacOS/VirtualHere"
DEFAULT_CLIENT_WINDOWS = "vhui64.exe"
WINDOWS_PIPE = Path('\\\\.\\PIPE\\vhclient')
POSIX_SEND_PIPE = Path('/tmp/vhclient')
POSIX_RECV_PIPE = Path('/tmp/vhclient_response')


class DeviceInfo(NamedTuple):
    address: str
    nickname: str
    online: bool
    shared: bool


class DriverMetaData(object):
    SUPPORTED_COMMUNICATORS = {'SSH'}
    SUPPORTED_HOST_TYPES = {"Darwin", "Linux_AMD64", "Windows"}
    IDENTIFIER = "VirtualHere"


class VirtualHereOverSSHHost(AbstractRemoteHostDriver, DriverMetaData):
    class VirtualHereDriverError(AbstractShareableDeviceDriver.DeviceCommandError):
        pass

    class VirtualHereExecutionError(VirtualHereDriverError):
        pass

    @property
    def vh_client_cmd(self):
        if "virtualhere_command" in self.host.config:
            return self.host.config["virtualhere_command"]
        elif self.host.type == "Linux_AMD64":
            return DEFAULT_CLIENT_LINUX
        elif self.host.type == "Windows":
            return DEFAULT_CLIENT_WINDOWS
        elif self.host.type == "Darwin":
            return DEFAULT_CLIENT_MAC

    def ssh(self, command: str) -> CommandResponse:
        response = self.communicator.execute_command(command=command)
        if response.return_code != 0:
            message = f'Error: host={self.host.address}, command={command}, rc={response.return_code}, ' \
                      f'stdout={response.stdout}, stderr={response.stderr}'
            logger.error(message)
            raise self.HostCommandError(message)
        return response

    def client_service_not_running(self, output: str) -> bool:
        for error in (
                'IPC client, server response open failed', 'An existing client is not running.',
                'No response from IPC server'):
            if error in output:
                return True
        return False

    def vh_command(self, command) -> CommandResponse:
        if self.host.type == "Windows":
            # This forces the the command shell to wait for the executable to exit before exiting ensuring
            # we get the output from VirtualHere.
            full_command = f'start "quartermaster" /W {self.vh_client_cmd} -t "{command}" -r "quartermaster.tmp"' \
                           f' & type quartermaster.tmp ' \
                           f'& del quartermaster.tmp'
        else:
            full_command = f'{self.vh_client_cmd} -t "{command}"'

        try:
            response = self.ssh(full_command)
            return response
        except self.HostCommandError as e:
            if self.client_service_not_running(e.message):
                raise self.VirtualHereExecutionError(
                    f"VirtualHere client service is needed but does not appear to be running on {self.host.address}")
            else:
                raise e

    def _find_localhost_hostname(self, tree: Element) -> Optional[str]:
        """
        Given the parsed `GET CLIENT STATE` output look for a connection to the localhost server (on the remote host)

        :param tree: ElementTree.Element
        :return: The name of the localhost server or None if not found
        """
        connection: Element
        for connection in tree.iter('connection'):
            if connection.attrib['ip'] == '127.0.0.1':
                return connection.attrib['hostname']
        return None

    def _get_state_data(self) -> Element:
        vh_resp = self.vh_command('GET CLIENT STATE')
        try:
            return ElementTree.fromstring(vh_resp.stdout)
        except ElementTree.ParseError:
            raise self.VirtualHereExecutionError(f"Error parsing VirtualHere client status, "
                                                 f"host={self.host.communicator}:{self.host.address} "
                                                 f"xml=>>{vh_resp.stdout}<< stderr=>>{vh_resp.stderr}<<")

    def get_states(self) -> Dict[str, DeviceInfo]:
        state_data = self._get_state_data()
        hostname = self._find_localhost_hostname(state_data)

        # Sometimes the client doesn't have the local hub registered. I have seen this on Windows.
        # This will, if a localhost hub is not found, add one and try one more time
        if hostname is None:
            response = self.vh_command('MANUAL HUB ADD,127.0.0.1')
            if response.stdout.startswith('OK'):
                state_data = self._get_state_data()
                hostname = self._find_localhost_hostname(state_data)
            else:
                raise self.VirtualHereExecutionError(
                    f"Error, {response}, when trying to add connection to local server, {self.host}.")

        if hostname is None:
            raise self.VirtualHereExecutionError(
                f"Could not find device on local machine, is this running the VirtualHere server? {self.host}")

        devices = {}
        device: Element
        for device in state_data.iter('device'):
            address = f"{hostname}.{device.attrib['address']}"
            shared: bool
            devices[address] = DeviceInfo(
                address=address,
                nickname=device.attrib['nickname'],
                online=True,  # If we see then it has to be online
                shared=device.attrib['state'] != "1"  # So far as I can tell, 1=Unused, 3=Used
            )
        return devices

    def update_device_states(self, devices: Iterable['Device']):
        states = self.get_states()
        for device in devices:
            try:
                state_info = states[device.config['device_address']]
            except KeyError:
                # If we don't see the device in the state info then it is offline
                device.online = False
                device.save()
                continue
            else:
                if not device.online:
                    device.online = True
                    device.save()

            # Devices are always shared, just disconnect users who don't have them reserved.
            if not device.in_use and state_info.shared:
                device_driver = self.get_device_driver(device)
                device_driver.unshare()


class VirtualHereOverSSH(AbstractShareableDeviceDriver, DriverMetaData):
    USER_MATCHER = re.compile("^IN USE BY: (?P<user>.+)$", flags=re.MULTILINE)
    OK_MATCHER = re.compile("^OK$", flags=re.MULTILINE)
    NICKNAME_MATCHER = re.compile("^NICKNAME: (?P<nickname>.+)$", flags=re.MULTILINE)
    CONFIGURATION_KEYS = ("device_address",)
    CMD_TIMEOUT_SEC = 10

    host_driver: 'VirtualHereOverSSHHost'

    class VirtualHereDriverError(AbstractShareableDeviceDriver.DeviceCommandError):
        pass

    class VirtualHereExecutionError(VirtualHereDriverError):
        pass

    def get_share_state(self) -> bool:
        device_address = self.device.config['device_address']
        states = self.host_driver.get_states()
        if device_address in states:
            return states[device_address].shared
        else:
            raise self.DeviceNotFound(f"Did not find {device_address} on {self.device.host}")

    def get_online_state(self) -> bool:
        device_address = self.device.config['device_address']
        states = self.host_driver.get_states()
        return device_address in states

    def get_nickname(self) -> Optional[str]:
        device_address = self.device.config['device_address']
        states = self.host_driver.get_states()
        try:
            return states[device_address].nickname
        except KeyError:
            raise self.DeviceNotFound(f"Did not find {device_address} on {self.device.host}")

    def set_nickname(self) -> None:
        self.host_driver.vh_command(f"DEVICE RENAME,{self.device.config['device_address']},{self.device.name}")

    def start_sharing(self) -> None:
        # FIXME: Make this do something
        # shares are always available and are controlled by knowing the password if enabled
        pass

    def stop_sharing(self) -> None:
        states: Dict[str, DeviceInfo] = self.host_driver.get_states()
        if states[self.device.config['device_address']].shared:
            self.host_driver.vh_command(f"STOP USING,{self.device.config['device_address']}")


################################################################################
#
# This is being done to prevent circular dependencies
VirtualHereOverSSH.HOST_CLASS = VirtualHereOverSSHHost
VirtualHereOverSSHHost.DEVICE_CLASS = VirtualHereOverSSH


def windows_pipe_interactor(cmd: str, queue: Queue, named_pipe: Path = WINDOWS_PIPE):
    """ This function is meant to be run in a separate process. This is to ensure it works on
        windows where non-blocking reads of pipes is hard. I get around this block by isolating
        the blocking susceptible code in separate process which we can terminate even when it is blocked.

        Additionally windows VirtualHere is implement
        """
    with named_pipe.open('rb+') as pipe:
        logger.debug(f"Sending {cmd} to VirtualHere")
        pipe.write(cmd.encode('ascii'))
        while True:
            # I pull in 1 byte at time because the reads block until
            # they get the target number of bytes
            queue.put(pipe.read(1).decode('ascii'))


def posix_pipe_interactor(cmd: str,
                          queue: Queue,
                          send_pipe: Path = POSIX_SEND_PIPE,
                          recv_pipe: Path = POSIX_RECV_PIPE):
    with send_pipe.open(mode='wb') as sp:
        logger.debug(f"Sending {cmd} to VirtualHere")
        sp.write(cmd.encode('ascii'))

    with recv_pipe.open(mode="rb") as rp:
        queue.put(rp.read().decode('ascii'))


def time_limited_vh_request(cmd: str, timeout_secs: int = 5):
    """
    There are ways to do this on some platforms would resorting to using "Process"es.
    The problem is the way to do this varies across platforms. I use Process
    to drive up code reuse across platforms and make things, overall, simpler.

    :param cmd: Command to executed
    :param timeout_secs: Max time to wait for output
    :return: The output
    """
    output_started = False
    start_time = time.time()
    q = Queue()
    if platform.system() == "Windows":
        p = Process(target=windows_pipe_interactor, args=(cmd, q))
    else:
        p = Process(target=posix_pipe_interactor, args=(cmd, q))
    p.daemon = True
    p.start()

    # read without blocking
    response = ''
    while (time.time() - start_time) < timeout_secs:
        # This is bit more complicated than might seem necessary
        # On posix systems the read returns all of the output at once
        # but on Windows output comes one byte a time so we could
        # look at the queue before it is done being filled
        try:
            chunk = q.get(timeout=.1)
            response += chunk
            logger.debug(f"Got >>{chunk}<< from Virtualhere")
            output_started = True
        except Empty:
            if output_started:
                break
    p.terminate()
    return response


class VirtualHereLocal(AbstractLocalDriver, DriverMetaData):
    OK_MATCHER = re.compile("^OK$", flags=re.MULTILINE)

    def __init__(self, conf):
        self.conf = conf

    def preflight_check(self):
        # Confirm VirtualHere client is installed and running
        # If we cannot get help text assume we re not running
        help_text = time_limited_vh_request('help')
        if not help_text:
            raise self.DriverError(
                "Could not connect to VirtualHere. Ensure the VirtualHere client service running")
        self.attach_hub()

    def run_vh(self, cmd: str) -> str:
        return time_limited_vh_request(cmd)

    def attach_hub(self):
        vh_resp = self.run_vh('MANUAL HUB LIST')
        for hub in vh_resp.splitlines():
            if hub.startswith(self.conf['host_address']):  # Hub already connected
                break
        else:
            vh_resp = self.run_vh(f"MANUAL HUB ADD,{self.conf['host_address']}")
            if not self.OK_MATCHER.search(vh_resp):
                raise self.DriverError(
                    f"VirtualHere did not return 'OK' when connecting hub '{self.conf['host_address']}', "
                    f"instead I got '{vh_resp}'"
                )

    def connect(self):
        vh_resp = self.run_vh(f"USE,{self.conf['device_address']}")
        if not self.OK_MATCHER.search(vh_resp):
            raise self.DriverError(f"VirtualHere did not return 'OK' when connecting device, instead I got "
                                   f"'{vh_resp}'")

    def disconnect(self):
        vh_resp = self.run_vh(f"STOP USING,{self.conf['device_address']}")
        if not self.OK_MATCHER.search(vh_resp):
            raise self.DriverError(
                f"VirtualHere did not return 'OK' when disconnecting device, instead I got '{vh_resp}'")

    def connected(self) -> bool:
        """
        # vhclientx86_64 -t 'device info,spf3-topaz-1.17'
        ADDRESS: spf3-topaz-1.17
        VENDOR: Android
        VENDOR ID: 0x05c6
        PRODUCT: Android
        PRODUCT ID: 0x901d
        SERIAL: 1f53203a
        NICKNAME: KonaFrames01
        IN USE BY: NO ONE
        """
        vh_resp = self.run_vh(f"DEVICE INFO,{self.conf['device_address']}")
        return "IN USE BY: NO ONE" not in vh_resp

    def setup_information(self):
        return "To use these Virtual here resources you must have the VirtualHere client installed and running. " \
               "You can download the client at https://virtualhere.com/usb_client_software"
