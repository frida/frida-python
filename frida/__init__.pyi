from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union

from . import core

__version__: str

class Relay:
    address: str
    kind: str
    password: str
    username: str
    def __init__(
        self,
        address: str,
        username: str,
        password: str,
        kind: Literal["turn-udp", "turn-tcp", "turn-tls"],
    ): ...

class EndpointParameters:
    def __init__(
        self,
        address: Optional[str] = None,
        port: Optional[int] = None,
        certificate: Optional[str] = None,
        origin: Optional[str] = None,
        authentication_token: Optional[str] = None,
        authentication_callback: Optional[Callable[[str], Any]] = None,
        assert_root: Optional[str] = None,
    ): ...

class PortalService:
    def __init__(
        self,
        cluster_params: EndpointParameters,
        control_params: Optional[EndpointParameters] = None,
    ): ...
    @property
    def device(self) -> core.Device:
        """
        Device for in-process control.
        """
        ...
    def start(self):
        """
        Start listening for incoming connections.

        :raises InvalidOperationError: if the service isn't stopped
        :raises AddressInUseError: if the given address is already in use
        """
        ...
    def stop(self):
        """
        Stop listening for incoming connections, and kick any connected clients.

        :raises InvalidOperationError: if the service is already stopped
        """
        ...
    def kick(self, connection_id: int):
        """
        Kick out a specific connection.
        """
        ...
    def post(self, connection_id: int, message: str, data: Optional[Union[str, bytes]] = None):
        """
        Post a JSON message to a specific control channel.
        """
        ...
    def narrowcast(self, tag: str, message: str, data: Optional[Union[str, bytes]] = None):
        """
        Post a JSON message to control channels with a specific tag.
        """
        ...
    def broadcast(self, message: str, data: Optional[Union[str, bytes]] = None):
        """
        Broadcast a JSON message to all control channels.
        """
        ...
    def enumerate_tags(self, connection_id: int) -> List[str]:
        """
        Enumerate tags of a specific connection.
        """
        ...
    def tag(self, connection_id: int, tag: str):
        """
        Tag a specific control channel.
        """
        ...
    def untag(self, connection_id: int, tag: str):
        """
        Untag a specific control channel.
        """
        ...

class FileMonitor:
    def __init__(self, path: str): ...
    def enable(self):
        """
        Enable the file monitor.

        :raises InvalidOperationError: if the object is already enabled or because of an internal error
        """
        ...
    def disable(self):
        """
        Disable the file monitor.

        :raises InvalidOperationError: if the object is already disabled
        """
        ...

class Cancellable:
    def __init__(self): ...
    @property
    def is_cancelled(self) -> bool:
        """
        Query whether cancellable has been cancelled.
        """
        ...
    def raise_if_cancelled(self):
        """
        Raise an exception if cancelled.

        :raises OperationCancelledError:
        """
        ...
    def get_fd(self) -> int:
        """
        Get file descriptor for integrating with an event loop.
        """
        ...
    def release_fd(self):
        """
        Release a resource previously allocated by get_fd().
        """
        ...
    @classmethod
    def get_current(cls) -> "Cancellable":
        """
        Get the top cancellable from the stack.
        """
        ...
    def push_current(self):
        """
        Push cancellable onto the cancellable stack.
        """
        ...
    def pop_current(self):
        """
        Pop cancellable off the cancellable stack.

        :raises InvalidOperationError:
        """
        ...
    def connect(self, callback: Callable) -> int:
        """
        Register notification callback.

        :returns: the created handler id
        """
        ...
    def disconnect(self, handler_id: int):
        """
        Unregister notification callback.
        """
        ...
    def cancel(self):
        """
        Set cancellable to cancelled.
        """
        ...

class ServerNotRunningError(Exception): ...
class ExecutableNotFoundError: ...
class ExecutableNotSupportedError: ...
class ProcessNotFoundError: ...
class ProcessNotRespondingError: ...
class InvalidArgumentError: ...
class InvalidOperationError: ...
class PermissionDeniedError: ...
class AddressInUseError: ...
class TimedOutError: ...
class NotSupportedError: ...
class ProtocolError: ...
class TransportError: ...
class OperationCancelledError: ...

def query_system_parameters() -> Dict[str, Any]: ...
def spawn(
    program: Union[str, List, Tuple],
    argv: Optional[Union[List, Tuple]] = None,
    envp: Optional[Dict[str, str]] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    stdio: Optional[str] = None,
    **kwargs
): ...
def resume(target: Union[int, str]): ...
def kill(target: Union[int, str]): ...
def attach(
    target: Union[int, str], realm: Optional[str] = None, persist_timeout: Optional[int] = None
) -> core.Session: ...
def inject_library_file(target: Union[int, str], path: str, entrypoint: str, data: str) -> int: ...
def inject_library_blob(target: Union[int, str], blob: bytes, entrypoint: str, data: str) -> int: ...
def get_local_device(timeout: int = 0) -> core.Device: ...
def get_remote_device(timeout: int = 0) -> core.Device: ...
def get_usb_device(timeout: int = 0) -> core.Device: ...
def get_device(id, timeout: int = 0, **kwargs) -> core.Device: ...
def get_device_matching(predicate: Callable[[core.Device], bool], timeout: int = 0):
    """
    Get device matching predicate.

    :params predicate: a function to filter the devices
    :params timeout: operation timeout in seconds
    """
    ...

def enumerate_devices() -> List[core.Device]:
    """
    Enumerate devices.
    """
    ...

def shutdown(): ...
def get_device_manager() -> core.DeviceManager: ...
