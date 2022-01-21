# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Tuple, Union

import _frida

def cancellable(f: Callable) -> Callable: ...

class Bus(object):
    def attach(self):
        """
        Attach to the bus.
        """
        ...
    def post(self, message: Any, data: Optional[Union[str, bytes]] = None):
        """
        Post a JSON-encoded message to the bus.
        """
        ...
    def on(self, signal: str, callback: Callable):
        """
        Add a signal handler.
        """
        ...
    def off(self, signal: str, callback: Callable):
        """
        Remove a signal handler.
        """
        ...

class Device(object):
    @property
    def id(self) -> Optional[str]:
        """
        Device ID.
        """
        ...
    @property
    def name(self) -> Optional[str]:
        """
        Human-readable device name.
        """
        ...
    @property
    def icon(self) -> Optional[Any]:
        """
        Icon.
        """
        ...
    @property
    def type(self) -> Optional[Literal["local", "remote", "usb"]]:
        """
        Device type. One of: local, remote, usb.
        """
        ...
    @property
    def bus(self) -> Optional[Bus]:
        """
        Message bus.
        """
        ...
    @property
    def is_lost(self) -> bool:
        """
        Query whether the device has been lost.
        """
        ...
    def query_system_parameters(self) -> Dict[str, Any]:
        """
        Returns a dictionary of information about the host system.
        """
        ...
    def get_frontmost_application(self, scope: Optional[str] = None) -> Optional[Application]:
        """
        Get details about the frontmost application.
        """
        ...
    def enumerate_applications(
        self, identifiers: Optional[Sequence[str]] = None, scope: Optional[str] = None
    ) -> List[Application]:
        """
        Enumerate applications.
        """
        ...
    def enumerate_processes(self, pids: Optional[Sequence[int]] = None, scope: Optional[str] = None) -> List[Process]:
        """
        Enumerate processes.
        """
        ...
    def get_process(self, process_name: str) -> Process:
        """
        Get the process with the given name

        :raises ProcessNotFoundError: if the process was not found or there were more than one process with the given name
        """
        ...
    def enable_spawn_gating(self):
        """
        Enable spawn gating.
        """
        ...
    def disable_spawn_gating(self):
        """
        Disable spawn gating.
        """
        ...
    def enumerate_pending_spawn(self) -> List[Spawn]:
        """
        Enumerate pending spawn.
        """
        ...
    def enumerate_pending_children(self) -> List[Child]:
        """
        Enumerate pending children.
        """
        ...
    def spawn(
        self,
        program: Union[str, List, Tuple],
        argv: Optional[Union[List, Tuple]] = None,
        envp: Optional[Dict[str, str]] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        stdio: Optional[str] = None,
        **kwargs
    ):
        """
        Spawn a process into an attachable state.
        """
        ...
    def input(self, target: Union[int, str], data: bytes):
        """
        Input data on stdin of a spawned process.

        :params target: the PID or name of the process
        """
        ...
    def resume(self, target: Union[int, str]):
        """
        Resume a process from the attachable state.

        :params target: the PID or name of the process
        """
        ...
    def kill(self, target: Union[int, str]):
        """
        Kill a process.

        :params target: the PID or name of the process
        """
        ...
    def attach(
        self,
        target: Union[int, str],
        realm: Optional[str] = None,
        persist_timeout: Optional[int] = None,
    ) -> Session:
        """
        Attach to a process.

        :params target: the PID or name of the process
        """
        ...
    def inject_library_file(self, target: Union[int, str], path: str, entrypoint: str, data: str) -> int:
        """
        Inject a library file to a process.

        :params target: the PID or name of the process
        """
        ...
    def inject_library_blob(self, target: Union[int, str], blob: bytes, entrypoint: str, data: str) -> int:
        """
        Inject a library blob to a process.

        :params target: the PID or name of the process
        """
        ...
    def open_channel(self, address: str) -> IOStream:
        """
        Open a device-specific communication channel.
        """
        ...
    def get_bus(self) -> Bus: ...
    def on(self, signal: str, callback: Callable):
        """
        Add a signal handler.
        """
        ...
    def off(self, signal: str, callback: Callable):
        """
        Remove a signal handler.
        """
        ...

class DeviceManager(object):
    def get_local_device(self) -> Device: ...
    def get_remote_device(self) -> Device: ...
    def get_usb_device(self, timeout=0) -> Device: ...
    def get_device(self, id, timeout: int = 0, **kwargs) -> Device: ...
    def get_device_matching(self, predicate: Callable[[Device], bool], timeout: int = 0) -> Device:
        """
        Get device matching predicate.

        :params predicate: a function to filter the devices
        :params timeout: operation timeout in seconds
        """
        ...
    def enumerate_devices(self) -> List[Device]:
        """
        Enumerate devices.
        """
        ...
    def add_remote_device(
        self,
        address: str,
        certificate: Optional[str] = None,
        origin: Optional[str] = None,
        token: Optional[str] = None,
        keepalive_interval: Optional[int] = None,
    ) -> Device:
        """
        Add a remote device.
        """
        ...
    def remove_remote_device(self, address: str):
        """
        Remove a remote device.
        """
        ...
    def on(self, signal: str, callback: Callable):
        """
        Add a signal handler.
        """
        ...
    def off(self, signal: str, callback: Callable):
        """
        Remove a signal handler.
        """
        ...

class Session(object):
    @property
    def is_detached(self) -> bool:
        """
        Query whether the session is detached.
        """
        ...
    def detach(self):
        """
        Detach session from the process.
        """
        ...
    def resume(self):
        """
        Resume session after network error.
        """
        ...
    def enable_child_gating(self):
        """
        Enable child gating.
        """
        ...
    def disable_child_gating(self):
        """
        Disable child gating.
        """
        ...
    def create_script(self, source: str, name: Optional[str] = None, runtime: Optional[str] = None) -> Script:
        """
        Create a new script.
        """
        ...
    def create_script_from_bytes(
        self, data: bytes, name: Optional[str] = None, runtime: Optional[str] = None
    ) -> Script:
        """
        Create a new script from bytecode.
        """
        ...
    def compile_script(self, source: str, name: Optional[str] = None, runtime: Optional[str] = None) -> bytes:
        """
        Compile script source code to bytecode.
        """
        ...
    def enable_debugger(self, port: int):
        """
        Enable the Node.js compatible script debugger.
        """
        ...
    def disable_debugger(self):
        """
        Disable the Node.js compatible script debugger.
        """
        ...
    def setup_peer_connection(self, stun_server, relays: Sequence[_frida.Relay]):
        """
        Set up a peer connection with the target process.
        """
        ...
    def join_portal(
        self,
        address: str,
        certificate: Optional[str] = None,
        token: Optional[str] = None,
        acl: Union[List[str], Tuple[str]] = None,
    ) -> PortalMembership:
        """
        Join a portal.
        """
        ...
    def on(self, signal: str, callback: Callable):
        """
        Add a signal handler.
        """
        ...
    def off(self, signal: str, callback: Callable):
        """
        Remove a signal handler.
        """
        ...

class Script(object):
    @property
    def is_destroyed(self) -> bool:
        """
        Query whether the script has been destroyed.
        """
        ...
    def load(self):
        """
        Load the script.
        """
        ...
    def unload(self):
        """
        Unload the script.
        """
        ...
    def eternalize(self):
        """
        Eternalize the script.
        """
        ...
    def post(self, message: Any, data: Optional[str] = None):
        """
        Post a JSON-encoded message to the script.
        """
        ...
    def on(self, signal: str, callback: Callable):
        """
        Add a signal handler.
        """
        ...
    def off(self, signal: str, callback: Callable):
        """
        Remove a signal handler.
        """
        ...
    def get_log_handler(self) -> Callable[[str, str], None]: ...
    def set_log_handler(self, handler: Callable[[str, str], None]): ...
    def default_log_handler(self, level: str, text: str): ...
    def list_exports(self) -> Any: ...

class RPCException(Exception): ...

class ScriptExports(object):
    def __init__(self, script: Script): ...
    def __getattr__(self, name: str) -> Any: ...

class PortalMembership(object):
    def terminate(self):
        """
        Terminate the membership.
        """
        ...

class EndpointParameters(object):
    def __init__(
        self,
        address: Optional[str] = None,
        port: Optional[int] = None,
        certificate: Optional[str] = None,
        origin: Optional[str] = None,
        authentication: Optional[Tuple[str, Union[str, Callable[[str], Any]]]] = None,
        assert_root: Optional[str] = None,
    ): ...

class PortalService(object):
    def __init__(
        self,
        cluster_params: Optional[EndpointParameters] = EndpointParameters(),
        control_params: Optional[EndpointParameters] = None,
    ): ...
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
    def post(self, connection_id: int, message: Any, data: Optional[Union[str, bytes]] = None):
        """
        Post a message to a specific control channel.
        """
        ...
    def narrowcast(self, tag: str, message: Any, data: Optional[Union[str, bytes]] = None):
        """
        Post a message to control channels with a specific tag.
        """
        ...
    def broadcast(self, message: Any, data: Optional[Union[str, bytes]] = None):
        """
        Broadcast a message to all control channels.
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
    def on(self, signal: str, callback: Callable):
        """
        Add a signal handler.
        """
        ...
    def off(self, signal: str, callback: Callable):
        """
        Remove a signal handler.
        """
        ...

class IOStream(object):
    @property
    def is_closed(self) -> bool:
        """
        Query whether the stream is closed.
        """
        ...
    def close(self):
        """
        Close the stream.
        """
        ...
    def read(self, count: int) -> bytes:
        """
        Read up to the specified number of bytes from the stream.
        """
        ...
    def read_all(self, count: int) -> bytes:
        """
        Read exactly the specified number of bytes from the stream.
        """
        ...
    def write(self, data: bytes):
        """
        Write as much as possible of the provided data to the stream.
        """
        ...
    def write_all(self, data: bytes):
        """
        Write all of the provided data to the stream.
        """
        ...

class Cancellable(object):
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
    def get_pollfd(self) -> CancellablePollFD: ...
    @classmethod
    def get_current(cls) -> Cancellable:
        """
        Get the top cancellable from the stack.
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

class CancellablePollFD(object):
    def release(self): ...
    def __enter__(self) -> int: ...

def make_auth_callback(callback: Callable) -> Callable: ...
