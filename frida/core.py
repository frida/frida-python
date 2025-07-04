from __future__ import annotations

import asyncio
import dataclasses
import fnmatch
import functools
import json
import sys
import threading
import traceback
import warnings
from types import TracebackType
from typing import (
    Any,
    AnyStr,
    Awaitable,
    Callable,
    Dict,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

if sys.version_info >= (3, 8):
    from typing import Literal, TypedDict
else:
    from typing_extensions import Literal, TypedDict

if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired

from . import _frida

_device_manager = None

_Cancellable = _frida.Cancellable

ProcessTarget = Union[int, str]
Spawn = _frida.Spawn


@dataclasses.dataclass
class RPCResult:
    finished: bool = False
    value: Any = None
    error: Optional[Exception] = None


def get_device_manager() -> "DeviceManager":
    """
    Get or create a singleton DeviceManager that let you manage all the devices
    """

    global _device_manager
    if _device_manager is None:
        _device_manager = DeviceManager(_frida.DeviceManager())
    return _device_manager


def _filter_missing_kwargs(d: MutableMapping[Any, Any]) -> None:
    for key in list(d.keys()):
        if d[key] is None:
            d.pop(key)


R = TypeVar("R")


def cancellable(f: Callable[..., R]) -> Callable[..., R]:
    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> R:
        cancellable = kwargs.pop("cancellable", None)
        if cancellable is not None:
            with cancellable:
                return f(*args, **kwargs)

        return f(*args, **kwargs)

    return wrapper


class IOStream:
    """
    Frida's own implementation of an input/output stream
    """

    def __init__(self, impl: _frida.IOStream) -> None:
        self._impl = impl

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_closed(self) -> bool:
        """
        Query whether the stream is closed
        """

        return self._impl.is_closed()

    @cancellable
    def close(self) -> None:
        """
        Close the stream.
        """

        self._impl.close()

    @cancellable
    def read(self, count: int) -> bytes:
        """
        Read up to the specified number of bytes from the stream
        """

        return self._impl.read(count)

    @cancellable
    def read_all(self, count: int) -> bytes:
        """
        Read exactly the specified number of bytes from the stream
        """

        return self._impl.read_all(count)

    @cancellable
    def write(self, data: bytes) -> int:
        """
        Write as much as possible of the provided data to the stream
        """

        return self._impl.write(data)

    @cancellable
    def write_all(self, data: bytes) -> None:
        """
        Write all of the provided data to the stream
        """

        self._impl.write_all(data)


class PortalMembership:
    def __init__(self, impl: _frida.PortalMembership) -> None:
        self._impl = impl

    @cancellable
    def terminate(self) -> None:
        """
        Terminate the membership
        """

        self._impl.terminate()


class ScriptExportsSync:
    """
    Proxy object that expose all the RPC exports of a script as attributes on this class

    A method named exampleMethod in a script will be called with instance.example_method on this object
    """

    def __init__(self, script: "Script") -> None:
        self._script = script

    def __getattr__(self, name: str) -> Callable[..., Any]:
        script = self._script
        js_name = _to_camel_case(name)

        def method(*args: Any, **kwargs: Any) -> Any:
            request, data = make_rpc_call_request(js_name, args)
            return script._rpc_request(request, data, **kwargs)

        return method

    def __dir__(self) -> List[str]:
        return self._script.list_exports_sync()


ScriptExports = ScriptExportsSync


class ScriptExportsAsync:
    """
    Proxy object that expose all the RPC exports of a script as attributes on this class

    A method named exampleMethod in a script will be called with instance.example_method on this object
    """

    def __init__(self, script: "Script") -> None:
        self._script = script

    def __getattr__(self, name: str) -> Callable[..., Awaitable[Any]]:
        script = self._script
        js_name = _to_camel_case(name)

        async def method(*args: Any, **kwargs: Any) -> Any:
            request, data = make_rpc_call_request(js_name, args)
            return await script._rpc_request_async(request, data, **kwargs)

        return method

    def __dir__(self) -> List[str]:
        return self._script.list_exports_sync()


def make_rpc_call_request(js_name: str, args: Sequence[Any]) -> Tuple[List[Any], Optional[bytes]]:
    if args and isinstance(args[-1], bytes):
        raw_args = args[:-1]
        data = args[-1]
    else:
        raw_args = args
        data = None
    return (["call", js_name, raw_args], data)


class ScriptErrorMessage(TypedDict):
    type: Literal["error"]
    description: str
    stack: NotRequired[str]
    fileName: NotRequired[str]
    lineNumber: NotRequired[int]
    columnNumber: NotRequired[int]


class ScriptPayloadMessage(TypedDict):
    type: Literal["send"]
    payload: NotRequired[Any]


ScriptMessage = Union[ScriptPayloadMessage, ScriptErrorMessage]
ScriptMessageCallback = Callable[[ScriptMessage, Optional[bytes]], None]
ScriptDestroyedCallback = Callable[[], None]


class RPCException(Exception):
    """
    Wraps remote errors from the script RPC
    """

    def __str__(self) -> str:
        return str(self.args[2]) if len(self.args) >= 3 else str(self.args[0])


class Script:
    def __init__(self, impl: _frida.Script) -> None:
        self.exports_sync = ScriptExportsSync(self)
        self.exports_async = ScriptExportsAsync(self)

        self._impl = impl

        self._on_message_callbacks: List[ScriptMessageCallback] = []
        self._log_handler: Callable[[str, str], None] = self.default_log_handler

        self._pending: Dict[
            int, Callable[[Optional[Any], Optional[Union[RPCException, _frida.InvalidOperationError]]], None]
        ] = {}
        self._next_request_id = 1
        self._cond = threading.Condition()

        impl.on("destroyed", self._on_destroyed)
        impl.on("message", self._on_message)

    @property
    def exports(self) -> ScriptExportsSync:
        """
        The old way of retrieving the synchronous exports caller
        """

        warnings.warn(
            "Script.exports will become asynchronous in the future, use the explicit Script.exports_sync instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.exports_sync

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_destroyed(self) -> bool:
        """
        Query whether the script has been destroyed
        """

        return self._impl.is_destroyed()

    @cancellable
    def load(self) -> None:
        """
        Load the script.
        """

        self._impl.load()

    @cancellable
    def unload(self) -> None:
        """
        Unload the script
        """

        self._impl.unload()

    @cancellable
    def eternalize(self) -> None:
        """
        Eternalize the script
        """

        self._impl.eternalize()

    def post(self, message: Any, data: Optional[AnyStr] = None) -> None:
        """
        Post a JSON-encoded message to the script
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.post(raw_message, **kwargs)

    @cancellable
    def enable_debugger(self, port: Optional[int] = None) -> None:
        """
        Enable the Node.js compatible script debugger
        """

        kwargs = {"port": port}
        _filter_missing_kwargs(kwargs)
        self._impl.enable_debugger(**kwargs)

    @cancellable
    def disable_debugger(self) -> None:
        """
        Disable the Node.js compatible script debugger
        """

        self._impl.disable_debugger()

    @overload
    def on(self, signal: Literal["destroyed"], callback: ScriptDestroyedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["message"], callback: ScriptMessageCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        if signal == "message":
            self._on_message_callbacks.append(callback)
        else:
            self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["destroyed"], callback: ScriptDestroyedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["message"], callback: ScriptMessageCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        if signal == "message":
            self._on_message_callbacks.remove(callback)
        else:
            self._impl.off(signal, callback)

    def get_log_handler(self) -> Callable[[str, str], None]:
        """
        Get the method that handles the script logs
        """

        return self._log_handler

    def set_log_handler(self, handler: Callable[[str, str], None]) -> None:
        """
        Set the method that handles the script logs
        :param handler: a callable that accepts two parameters:
                        1. the log level name
                        2. the log message
        """

        self._log_handler = handler

    def default_log_handler(self, level: str, text: str) -> None:
        """
        The default implementation of the log handler, prints the message to stdout
        or stderr, depending on the level
        """

        if level == "info":
            print(text, file=sys.stdout)
        else:
            print(text, file=sys.stderr)

    async def list_exports_async(self) -> List[str]:
        """
        Asynchronously list all the exported attributes from the script's rpc
        """

        result = await self._rpc_request_async(["list"])
        assert isinstance(result, list)
        return result

    def list_exports_sync(self) -> List[str]:
        """
        List all the exported attributes from the script's rpc
        """

        result = self._rpc_request(["list"])
        assert isinstance(result, list)
        return result

    def list_exports(self) -> List[str]:
        """
        List all the exported attributes from the script's rpc
        """

        warnings.warn(
            "Script.list_exports will become asynchronous in the future, use the explicit Script.list_exports_sync instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.list_exports_sync()

    def _rpc_request_async(self, args: Any, data: Optional[bytes] = None) -> asyncio.Future[Any]:
        loop = asyncio.get_event_loop()
        future: asyncio.Future[Any] = asyncio.Future()

        def on_complete(value: Any, error: Optional[Union[RPCException, _frida.InvalidOperationError]]) -> None:
            if error is not None:
                loop.call_soon_threadsafe(future.set_exception, error)
            else:
                loop.call_soon_threadsafe(future.set_result, value)

        request_id = self._append_pending(on_complete)

        if not self.is_destroyed:
            self._send_rpc_call(request_id, args, data)
        else:
            self._on_destroyed()

        return future

    @cancellable
    def _rpc_request(self, args: Any, data: Optional[bytes] = None) -> Any:
        result = RPCResult()

        def on_complete(value: Any, error: Optional[Union[RPCException, _frida.InvalidOperationError]]) -> None:
            with self._cond:
                result.finished = True
                result.value = value
                result.error = error
                self._cond.notify_all()

        def on_cancelled() -> None:
            self._pending.pop(request_id, None)
            on_complete(None, None)

        request_id = self._append_pending(on_complete)

        if not self.is_destroyed:
            self._send_rpc_call(request_id, args, data)

            cancellable = Cancellable.get_current()
            cancel_handler = cancellable.connect(on_cancelled)
            try:
                with self._cond:
                    while not result.finished:
                        self._cond.wait()
            finally:
                cancellable.disconnect(cancel_handler)

            cancellable.raise_if_cancelled()
        else:
            self._on_destroyed()

        if result.error is not None:
            raise result.error

        return result.value

    def _append_pending(
        self, callback: Callable[[Any, Optional[Union[RPCException, _frida.InvalidOperationError]]], None]
    ) -> int:
        with self._cond:
            request_id = self._next_request_id
            self._next_request_id += 1
            self._pending[request_id] = callback
        return request_id

    def _send_rpc_call(self, request_id: int, args: Any, data: Optional[bytes]) -> None:
        self.post(["frida:rpc", request_id, *args], data)

    def _on_rpc_message(self, request_id: int, operation: str, params: List[Any], data: Optional[Any]) -> None:
        if operation in ("ok", "error"):
            callback = self._pending.pop(request_id, None)
            if callback is None:
                return

            value = None
            error = None
            if operation == "ok":
                if data is not None:
                    value = (params[1], data) if len(params) > 1 else data
                else:
                    value = params[0]
            else:
                error = RPCException(*params[0:3])

            callback(value, error)

    def _on_destroyed(self) -> None:
        while True:
            next_pending = None

            with self._cond:
                pending_ids = list(self._pending.keys())
                if len(pending_ids) > 0:
                    next_pending = self._pending.pop(pending_ids[0])

            if next_pending is None:
                break

            next_pending(None, _frida.InvalidOperationError("script has been destroyed"))

    def _on_message(self, raw_message: str, data: Optional[bytes]) -> None:
        message = json.loads(raw_message)

        mtype = message["type"]
        payload = message.get("payload", None)
        if mtype == "log":
            level = message["level"]
            text = payload
            self._log_handler(level, text)
        elif mtype == "send" and isinstance(payload, list) and len(payload) > 0 and payload[0] == "frida:rpc":
            request_id = payload[1]
            operation = payload[2]
            params = payload[3:]
            self._on_rpc_message(request_id, operation, params, data)
        else:
            for callback in self._on_message_callbacks[:]:
                try:
                    callback(message, data)
                except:
                    traceback.print_exc()


SessionDetachedCallback = Callable[
    [
        Literal[
            "application-requested", "process-replaced", "process-terminated", "connection-terminated", "device-lost"
        ],
        Optional[_frida.Crash],
    ],
    None,
]


class Session:
    def __init__(self, impl: _frida.Session) -> None:
        self._impl = impl

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_detached(self) -> bool:
        """
        Query whether the session is detached
        """

        return self._impl.is_detached()

    @cancellable
    def detach(self) -> None:
        """
        Detach session from the process
        """

        self._impl.detach()

    @cancellable
    def resume(self) -> None:
        """
        Resume session after network error
        """

        self._impl.resume()

    @cancellable
    def enable_child_gating(self) -> None:
        """
        Enable child gating
        """

        self._impl.enable_child_gating()

    @cancellable
    def disable_child_gating(self) -> None:
        """
        Disable child gating
        """

        self._impl.disable_child_gating()

    @cancellable
    def create_script(
        self, source: str, name: Optional[str] = None, snapshot: Optional[bytes] = None, runtime: Optional[str] = None
    ) -> Script:
        """
        Create a new script
        """

        kwargs = {"name": name, "snapshot": snapshot, "runtime": runtime}
        _filter_missing_kwargs(kwargs)
        return Script(self._impl.create_script(source, **kwargs))  # type: ignore

    @cancellable
    def create_script_from_bytes(
        self, data: bytes, name: Optional[str] = None, snapshot: Optional[bytes] = None, runtime: Optional[str] = None
    ) -> Script:
        """
        Create a new script from bytecode
        """

        kwargs = {"name": name, "snapshot": snapshot, "runtime": runtime}
        _filter_missing_kwargs(kwargs)
        return Script(self._impl.create_script_from_bytes(data, **kwargs))  # type: ignore

    @cancellable
    def compile_script(self, source: str, name: Optional[str] = None, runtime: Optional[str] = None) -> bytes:
        """
        Compile script source code to bytecode
        """

        kwargs = {"name": name, "runtime": runtime}
        _filter_missing_kwargs(kwargs)
        return self._impl.compile_script(source, **kwargs)

    @cancellable
    def snapshot_script(self, embed_script: str, warmup_script: Optional[str], runtime: Optional[str] = None) -> bytes:
        """
        Evaluate script and snapshot the resulting VM state
        """
        kwargs = {"warmup_script": warmup_script, "runtime": runtime}
        _filter_missing_kwargs(kwargs)
        return self._impl.snapshot_script(embed_script, **kwargs)

    @cancellable
    def setup_peer_connection(
        self, stun_server: Optional[str] = None, relays: Optional[Sequence[_frida.Relay]] = None
    ) -> None:
        """
        Set up a peer connection with the target process
        """

        kwargs = {"stun_server": stun_server, "relays": relays}
        _filter_missing_kwargs(kwargs)
        self._impl.setup_peer_connection(**kwargs)  # type: ignore

    @cancellable
    def join_portal(
        self,
        address: str,
        certificate: Optional[str] = None,
        token: Optional[str] = None,
        acl: Union[None, List[str], Tuple[str]] = None,
    ) -> PortalMembership:
        """
        Join a portal
        """

        kwargs: Dict[str, Any] = {"certificate": certificate, "token": token, "acl": acl}
        _filter_missing_kwargs(kwargs)
        return PortalMembership(self._impl.join_portal(address, **kwargs))

    @overload
    def on(
        self,
        signal: Literal["detached"],
        callback: SessionDetachedCallback,
    ) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        self._impl.on(signal, callback)

    @overload
    def off(
        self,
        signal: Literal["detached"],
        callback: SessionDetachedCallback,
    ) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        self._impl.off(signal, callback)


BusDetachedCallback = Callable[[], None]
BusMessageCallback = Callable[[Mapping[Any, Any], Optional[bytes]], None]


class Bus:
    def __init__(self, impl: _frida.Bus) -> None:
        self._impl = impl
        self._on_message_callbacks: List[Callable[..., Any]] = []

        impl.on("message", self._on_message)

    @cancellable
    def attach(self) -> None:
        """
        Attach to the bus
        """

        self._impl.attach()

    def post(self, message: Any, data: Optional[Union[str, bytes]] = None) -> None:
        """
        Post a JSON-encoded message to the bus
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.post(raw_message, **kwargs)

    @overload
    def on(self, signal: Literal["detached"], callback: BusDetachedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["message"], callback: BusMessageCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        if signal == "message":
            self._on_message_callbacks.append(callback)
        else:
            self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["detached"], callback: BusDetachedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["message"], callback: BusMessageCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        if signal == "message":
            self._on_message_callbacks.remove(callback)
        else:
            self._impl.off(signal, callback)

    def _on_message(self, raw_message: str, data: Any) -> None:
        message = json.loads(raw_message)

        for callback in self._on_message_callbacks[:]:
            try:
                callback(message, data)
            except:
                traceback.print_exc()


ServiceCloseCallback = Callable[[], None]
ServiceMessageCallback = Callable[[Any], None]


class Service:
    def __init__(self, impl: _frida.Service) -> None:
        self._impl = impl

    @cancellable
    def activate(self) -> None:
        """
        Activate the service
        """

        self._impl.activate()

    @cancellable
    def cancel(self) -> None:
        """
        Cancel the service
        """

        self._impl.cancel()

    def request(self, parameters: Any) -> Any:
        """
        Perform a request
        """

        return self._impl.request(parameters)

    @overload
    def on(self, signal: Literal["close"], callback: ServiceCloseCallback) -> None: ...

    @overload
    def on(self, signal: Literal["message"], callback: ServiceMessageCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["close"], callback: ServiceCloseCallback) -> None: ...

    @overload
    def off(self, signal: Literal["message"], callback: ServiceMessageCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        self._impl.off(signal, callback)


DeviceSpawnAddedCallback = Callable[[_frida.Spawn], None]
DeviceSpawnRemovedCallback = Callable[[_frida.Spawn], None]
DeviceChildAddedCallback = Callable[[_frida.Child], None]
DeviceChildRemovedCallback = Callable[[_frida.Child], None]
DeviceProcessCrashedCallback = Callable[[_frida.Crash], None]
DeviceOutputCallback = Callable[[int, int, bytes], None]
DeviceUninjectedCallback = Callable[[int], None]
DeviceLostCallback = Callable[[], None]


class Device:
    """
    Represents a device that Frida connects to
    """

    def __init__(self, device: _frida.Device) -> None:
        assert device.bus is not None
        self.id = device.id
        self.name = device.name
        self.icon = device.icon
        self.type = device.type
        self.bus = Bus(device.bus)

        self._impl = device

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_lost(self) -> bool:
        """
        Query whether the device has been lost
        """

        return self._impl.is_lost()

    @cancellable
    def query_system_parameters(self) -> Dict[str, Any]:
        """
        Returns a dictionary of information about the host system
        """

        return self._impl.query_system_parameters()

    @cancellable
    def get_frontmost_application(self, scope: Optional[str] = None) -> Optional[_frida.Application]:
        """
        Get details about the frontmost application
        """

        kwargs = {"scope": scope}
        _filter_missing_kwargs(kwargs)
        return self._impl.get_frontmost_application(**kwargs)

    @cancellable
    def enumerate_applications(
        self, identifiers: Optional[Sequence[str]] = None, scope: Optional[str] = None
    ) -> List[_frida.Application]:
        """
        Enumerate applications
        """

        kwargs = {"identifiers": identifiers, "scope": scope}
        _filter_missing_kwargs(kwargs)
        return self._impl.enumerate_applications(**kwargs)  # type: ignore

    @cancellable
    def enumerate_processes(
        self, pids: Optional[Sequence[int]] = None, scope: Optional[str] = None
    ) -> List[_frida.Process]:
        """
        Enumerate processes
        """

        kwargs = {"pids": pids, "scope": scope}
        _filter_missing_kwargs(kwargs)
        return self._impl.enumerate_processes(**kwargs)  # type: ignore

    @cancellable
    def get_process(self, process_name: str) -> _frida.Process:
        """
        Get the process with the given name
        :raises ProcessNotFoundError: if the process was not found or there were more than one process with the given name
        """

        process_name_lc = process_name.lower()
        matching = [
            process
            for process in self._impl.enumerate_processes()
            if fnmatch.fnmatchcase(process.name.lower(), process_name_lc)
        ]
        if len(matching) == 1:
            return matching[0]
        elif len(matching) > 1:
            matches_list = ", ".join([f"{process.name} (pid: {process.pid})" for process in matching])
            raise _frida.ProcessNotFoundError(f"ambiguous name; it matches: {matches_list}")
        else:
            raise _frida.ProcessNotFoundError(f"unable to find process with name '{process_name}'")

    @cancellable
    def enable_spawn_gating(self) -> None:
        """
        Enable spawn gating
        """

        self._impl.enable_spawn_gating()

    @cancellable
    def disable_spawn_gating(self) -> None:
        """
        Disable spawn gating
        """

        self._impl.disable_spawn_gating()

    @cancellable
    def enumerate_pending_spawn(self) -> List[_frida.Spawn]:
        """
        Enumerate pending spawn
        """

        return self._impl.enumerate_pending_spawn()

    @cancellable
    def enumerate_pending_children(self) -> List[_frida.Child]:
        """
        Enumerate pending children
        """

        return self._impl.enumerate_pending_children()

    @cancellable
    def spawn(
        self,
        program: Union[str, List[Union[str, bytes]], Tuple[Union[str, bytes]]],
        argv: Union[None, List[Union[str, bytes]], Tuple[Union[str, bytes]]] = None,
        envp: Optional[Dict[str, str]] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        stdio: Optional[str] = None,
        **kwargs: Any,
    ) -> int:
        """
        Spawn a process into an attachable state
        """

        if not isinstance(program, str):
            argv = program
            if isinstance(argv[0], bytes):
                program = argv[0].decode()
            else:
                program = argv[0]
            if len(argv) == 1:
                argv = None

        kwargs = {"argv": argv, "envp": envp, "env": env, "cwd": cwd, "stdio": stdio, "aux": kwargs}
        _filter_missing_kwargs(kwargs)
        return self._impl.spawn(program, **kwargs)

    @cancellable
    def input(self, target: ProcessTarget, data: bytes) -> None:
        """
        Input data on stdin of a spawned process
        :param target: the PID or name of the process
        """

        self._impl.input(self._pid_of(target), data)

    @cancellable
    def resume(self, target: ProcessTarget) -> None:
        """
        Resume a process from the attachable state
        :param target: the PID or name of the process
        """

        self._impl.resume(self._pid_of(target))

    @cancellable
    def kill(self, target: ProcessTarget) -> None:
        """
        Kill a process
        :param target: the PID or name of the process
        """
        self._impl.kill(self._pid_of(target))

    @cancellable
    def attach(
        self,
        target: ProcessTarget,
        realm: Optional[str] = None,
        persist_timeout: Optional[int] = None,
    ) -> Session:
        """
        Attach to a process
        :param target: the PID or name of the process
        """

        kwargs = {"realm": realm, "persist_timeout": persist_timeout}
        _filter_missing_kwargs(kwargs)
        return Session(self._impl.attach(self._pid_of(target), **kwargs))  # type: ignore

    @cancellable
    def inject_library_file(self, target: ProcessTarget, path: str, entrypoint: str, data: str) -> int:
        """
        Inject a library file to a process
        :param target: the PID or name of the process
        """

        return self._impl.inject_library_file(self._pid_of(target), path, entrypoint, data)

    @cancellable
    def inject_library_blob(self, target: ProcessTarget, blob: bytes, entrypoint: str, data: str) -> int:
        """
        Inject a library blob to a process
        :param target: the PID or name of the process
        """

        return self._impl.inject_library_blob(self._pid_of(target), blob, entrypoint, data)

    @cancellable
    def open_channel(self, address: str) -> IOStream:
        """
        Open a device-specific communication channel
        """

        return IOStream(self._impl.open_channel(address))

    @cancellable
    def open_service(self, address: str) -> Service:
        """
        Open a device-specific service
        """

        return Service(self._impl.open_service(address))

    @cancellable
    def unpair(self) -> None:
        """
        Unpair device
        """

        self._impl.unpair()

    @cancellable
    def get_bus(self) -> Bus:
        """
        Get the message bus of the device
        """

        return self.bus

    @overload
    def on(self, signal: Literal["spawn-added"], callback: DeviceSpawnAddedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["spawn-removed"], callback: DeviceSpawnRemovedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["child-added"], callback: DeviceChildAddedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["child-removed"], callback: DeviceChildRemovedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["process-crashed"], callback: DeviceProcessCrashedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["output"], callback: DeviceOutputCallback) -> None: ...

    @overload
    def on(self, signal: Literal["uninjected"], callback: DeviceUninjectedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["lost"], callback: DeviceLostCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["spawn-added"], callback: DeviceSpawnAddedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["spawn-removed"], callback: DeviceSpawnRemovedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["child-added"], callback: DeviceChildAddedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["child-removed"], callback: DeviceChildRemovedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["process-crashed"], callback: DeviceProcessCrashedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["output"], callback: DeviceOutputCallback) -> None: ...

    @overload
    def off(self, signal: Literal["uninjected"], callback: DeviceUninjectedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["lost"], callback: DeviceLostCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        self._impl.off(signal, callback)

    def _pid_of(self, target: ProcessTarget) -> int:
        if isinstance(target, str):
            return self.get_process(target).pid
        else:
            return target


DeviceManagerAddedCallback = Callable[[_frida.Device], None]
DeviceManagerRemovedCallback = Callable[[_frida.Device], None]
DeviceManagerChangedCallback = Callable[[], None]


class DeviceManager:
    def __init__(self, impl: _frida.DeviceManager) -> None:
        self._impl = impl

    def __repr__(self) -> str:
        return repr(self._impl)

    def get_local_device(self) -> Device:
        """
        Get the local device
        """

        return self.get_device_matching(lambda d: d.type == "local", timeout=0)

    def get_remote_device(self) -> Device:
        """
        Get the first remote device in the devices list
        """

        return self.get_device_matching(lambda d: d.type == "remote", timeout=0)

    def get_usb_device(self, timeout: int = 0) -> Device:
        """
        Get the first device connected over USB in the devices list
        """

        return self.get_device_matching(lambda d: d.type == "usb", timeout)

    def get_device(self, id: Optional[str], timeout: int = 0) -> Device:
        """
        Get a device by its id
        """

        return self.get_device_matching(lambda d: d.id == id, timeout)

    @cancellable
    def get_device_matching(self, predicate: Callable[[Device], bool], timeout: int = 0) -> Device:
        """
        Get device matching predicate
        :param predicate: a function to filter the devices
        :param timeout: operation timeout in seconds
        """

        if timeout < 0:
            raw_timeout = -1
        elif timeout == 0:
            raw_timeout = 0
        else:
            raw_timeout = int(timeout * 1000.0)
        return Device(self._impl.get_device_matching(lambda d: predicate(Device(d)), raw_timeout))

    @cancellable
    def enumerate_devices(self) -> List[Device]:
        """
        Enumerate devices
        """

        return [Device(device) for device in self._impl.enumerate_devices()]

    @cancellable
    def add_remote_device(
        self,
        address: str,
        certificate: Optional[str] = None,
        origin: Optional[str] = None,
        token: Optional[str] = None,
        keepalive_interval: Optional[int] = None,
    ) -> Device:
        """
        Add a remote device
        """

        kwargs: Dict[str, Any] = {
            "certificate": certificate,
            "origin": origin,
            "token": token,
            "keepalive_interval": keepalive_interval,
        }
        _filter_missing_kwargs(kwargs)
        return Device(self._impl.add_remote_device(address, **kwargs))

    @cancellable
    def remove_remote_device(self, address: str) -> None:
        """
        Remove a remote device
        """

        self._impl.remove_remote_device(address=address)

    @overload
    def on(self, signal: Literal["added"], callback: DeviceManagerAddedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["removed"], callback: DeviceManagerRemovedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["changed"], callback: DeviceManagerChangedCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["added"], callback: DeviceManagerAddedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["removed"], callback: DeviceManagerRemovedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["changed"], callback: DeviceManagerChangedCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        self._impl.off(signal, callback)


class EndpointParameters:
    def __init__(
        self,
        address: Optional[str] = None,
        port: Optional[int] = None,
        certificate: Optional[str] = None,
        origin: Optional[str] = None,
        authentication: Optional[Tuple[str, Union[str, Callable[[str], Any]]]] = None,
        asset_root: Optional[str] = None,
    ):
        kwargs: Dict[str, Any] = {"address": address, "port": port, "certificate": certificate, "origin": origin}
        if asset_root is not None:
            kwargs["asset_root"] = str(asset_root)
        _filter_missing_kwargs(kwargs)

        if authentication is not None:
            (auth_scheme, auth_data) = authentication
            if auth_scheme == "token":
                kwargs["auth_token"] = auth_data
            elif auth_scheme == "callback":
                if not callable(auth_data):
                    raise ValueError(
                        "Authentication data must provide a Callable if the authentication scheme is callback"
                    )
                kwargs["auth_callback"] = make_auth_callback(auth_data)
            else:
                raise ValueError("invalid authentication scheme")

        self._impl = _frida.EndpointParameters(**kwargs)


PortalServiceNodeJoinedCallback = Callable[[int, _frida.Application], None]
PortalServiceNodeLeftCallback = Callable[[int, _frida.Application], None]
PortalServiceNodeConnectedCallback = Callable[[int, Tuple[str, int]], None]
PortalServiceNodeDisconnectedCallback = Callable[[int, Tuple[str, int]], None]
PortalServiceControllerConnectedCallback = Callable[[int, Tuple[str, int]], None]
PortalServiceControllerDisconnectedCallback = Callable[[int, Tuple[str, int]], None]
PortalServiceAuthenticatedCallback = Callable[[int, Mapping[Any, Any]], None]
PortalServiceSubscribeCallback = Callable[[int], None]
PortalServiceMessageCallback = Callable[[int, Mapping[Any, Any], Optional[bytes]], None]


class PortalService:
    def __init__(
        self,
        cluster_params: EndpointParameters = EndpointParameters(),
        control_params: Optional[EndpointParameters] = None,
    ) -> None:
        args = [cluster_params._impl]
        if control_params is not None:
            args.append(control_params._impl)
        impl = _frida.PortalService(*args)

        self.device = impl.device
        self._impl = impl
        self._on_authenticated_callbacks: List[PortalServiceAuthenticatedCallback] = []
        self._on_message_callbacks: List[PortalServiceMessageCallback] = []

        impl.on("authenticated", self._on_authenticated)
        impl.on("message", self._on_message)

    @cancellable
    def start(self) -> None:
        """
        Start listening for incoming connections
        :raises InvalidOperationError: if the service isn't stopped
        :raises AddressInUseError: if the given address is already in use
        """

        self._impl.start()

    @cancellable
    def stop(self) -> None:
        """
        Stop listening for incoming connections, and kick any connected clients
        :raises InvalidOperationError: if the service is already stopped
        """

        self._impl.stop()

    def post(self, connection_id: int, message: Any, data: Optional[Union[str, bytes]] = None) -> None:
        """
        Post a message to a specific control channel.
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.post(connection_id, raw_message, **kwargs)

    def narrowcast(self, tag: str, message: Any, data: Optional[Union[str, bytes]] = None) -> None:
        """
        Post a message to control channels with a specific tag
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.narrowcast(tag, raw_message, **kwargs)

    def broadcast(self, message: Any, data: Optional[Union[str, bytes]] = None) -> None:
        """
        Broadcast a message to all control channels
        """

        raw_message = json.dumps(message)
        kwargs = {"data": data}
        _filter_missing_kwargs(kwargs)
        self._impl.broadcast(raw_message, **kwargs)

    def enumerate_tags(self, connection_id: int) -> List[str]:
        """
        Enumerate tags of a specific connection
        """

        return self._impl.enumerate_tags(connection_id)

    def tag(self, connection_id: int, tag: str) -> None:
        """
        Tag a specific control channel
        """

        self._impl.tag(connection_id, tag)

    def untag(self, connection_id: int, tag: str) -> None:
        """
        Untag a specific control channel
        """

        self._impl.untag(connection_id, tag)

    @overload
    def on(self, signal: Literal["node-joined"], callback: PortalServiceNodeJoinedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["node-left"], callback: PortalServiceNodeLeftCallback) -> None: ...

    @overload
    def on(
        self, signal: Literal["controller-connected"], callback: PortalServiceControllerConnectedCallback
    ) -> None: ...

    @overload
    def on(
        self, signal: Literal["controller-disconnected"], callback: PortalServiceControllerDisconnectedCallback
    ) -> None: ...

    @overload
    def on(self, signal: Literal["node-connected"], callback: PortalServiceNodeConnectedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["node-disconnected"], callback: PortalServiceNodeDisconnectedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["authenticated"], callback: PortalServiceAuthenticatedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["subscribe"], callback: PortalServiceSubscribeCallback) -> None: ...

    @overload
    def on(self, signal: Literal["message"], callback: PortalServiceMessageCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Add a signal handler
        """

        if signal == "authenticated":
            self._on_authenticated_callbacks.append(callback)
        elif signal == "message":
            self._on_message_callbacks.append(callback)
        else:
            self._impl.on(signal, callback)

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        """
        Remove a signal handler
        """

        if signal == "authenticated":
            self._on_authenticated_callbacks.remove(callback)
        elif signal == "message":
            self._on_message_callbacks.remove(callback)
        else:
            self._impl.off(signal, callback)

    def _on_authenticated(self, connection_id: int, raw_session_info: str) -> None:
        session_info = json.loads(raw_session_info)

        for callback in self._on_authenticated_callbacks[:]:
            try:
                callback(connection_id, session_info)
            except:
                traceback.print_exc()

    def _on_message(self, connection_id: int, raw_message: str, data: Optional[bytes]) -> None:
        message = json.loads(raw_message)

        for callback in self._on_message_callbacks[:]:
            try:
                callback(connection_id, message, data)
            except:
                traceback.print_exc()


class CompilerDiagnosticFile(TypedDict):
    path: str
    line: int
    character: int


class CompilerDiagnostic(TypedDict):
    category: str
    code: int
    file: NotRequired[CompilerDiagnosticFile]
    text: str


CompilerStartingCallback = Callable[[], None]
CompilerFinishedCallback = Callable[[], None]
CompilerOutputCallback = Callable[[str], None]
CompilerDiagnosticsCallback = Callable[[List[CompilerDiagnostic]], None]


class Compiler:
    def __init__(self) -> None:
        self._impl = _frida.Compiler()

    def __repr__(self) -> str:
        return repr(self._impl)

    @cancellable
    def build(
        self,
        entrypoint: str,
        project_root: Optional[str] = None,
        output_format: Optional[str] = None,
        bundle_format: Optional[str] = None,
        type_check: Optional[str] = None,
        source_maps: Optional[str] = None,
        compression: Optional[str] = None,
    ) -> str:
        kwargs = {
            "project_root": project_root,
            "output_format": output_format,
            "bundle_format": bundle_format,
            "type_check": type_check,
            "source_maps": source_maps,
            "compression": compression,
        }
        _filter_missing_kwargs(kwargs)
        return self._impl.build(entrypoint, **kwargs)

    @cancellable
    def watch(
        self,
        entrypoint: str,
        project_root: Optional[str] = None,
        output_format: Optional[str] = None,
        bundle_format: Optional[str] = None,
        type_check: Optional[str] = None,
        source_maps: Optional[str] = None,
        compression: Optional[str] = None,
    ) -> None:
        kwargs = {
            "project_root": project_root,
            "output_format": output_format,
            "bundle_format": bundle_format,
            "type_check": type_check,
            "source_maps": source_maps,
            "compression": compression,
        }
        _filter_missing_kwargs(kwargs)
        return self._impl.watch(entrypoint, **kwargs)

    @overload
    def on(self, signal: Literal["starting"], callback: CompilerStartingCallback) -> None: ...

    @overload
    def on(self, signal: Literal["finished"], callback: CompilerFinishedCallback) -> None: ...

    @overload
    def on(self, signal: Literal["output"], callback: CompilerOutputCallback) -> None: ...

    @overload
    def on(self, signal: Literal["diagnostics"], callback: CompilerDiagnosticsCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["starting"], callback: CompilerStartingCallback) -> None: ...

    @overload
    def off(self, signal: Literal["finished"], callback: CompilerFinishedCallback) -> None: ...

    @overload
    def off(self, signal: Literal["output"], callback: CompilerOutputCallback) -> None: ...

    @overload
    def off(self, signal: Literal["diagnostics"], callback: CompilerDiagnosticsCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        self._impl.off(signal, callback)


PackageManagerInstallProgressCallback = Callable[
    [
        Literal[
            "initializing",
            "preparing-dependencies",
            "resolving-package",
            "fetching-resource",
            "package-already-installed",
            "downloading-package",
            "package-installed",
            "resolving-and-installing-all",
            "complete",
        ],
        float,
        Optional[str],
    ],
    None,
]

PackageRole = Literal["runtime", "development", "optional", "peer"]


class PackageManager:
    def __init__(self) -> None:
        self._impl = _frida.PackageManager()

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def registry(self):
        return self._impl.registry

    @registry.setter
    def registry(self, value):
        self._impl.registry = value

    @cancellable
    def search(
        self,
        query: str,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> _frida.PackageSearchResult:
        kwargs = {
            "offset": offset,
            "limit": limit,
        }
        _filter_missing_kwargs(kwargs)
        return self._impl.search(query, **kwargs)

    @cancellable
    def install(
        self,
        project_root: Optional[str] = None,
        role: Optional[PackageRole] = None,
        specs: Optional[Sequence[str]] = None,
        omits: Optional[Sequence[PackageRole]] = None,
    ) -> _frida.PackageInstallResult:
        kwargs: Dict[str, Any] = {
            "project_root": project_root,
            "role": role,
            "specs": specs,
            "omits": omits,
        }
        _filter_missing_kwargs(kwargs)
        return self._impl.install(**kwargs)

    @overload
    def on(self, signal: Literal["install-progress"], callback: PackageManagerInstallProgressCallback) -> None: ...

    @overload
    def on(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        self._impl.on(signal, callback)

    @overload
    def off(self, signal: Literal["install-progress"], callback: PackageManagerInstallProgressCallback) -> None: ...

    @overload
    def off(self, signal: str, callback: Callable[..., Any]) -> None: ...

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        self._impl.off(signal, callback)


class CancellablePollFD:
    def __init__(self, cancellable: _Cancellable) -> None:
        self.handle = cancellable.get_fd()
        self._cancellable: Optional[_Cancellable] = cancellable

    def __del__(self) -> None:
        self.release()

    def release(self) -> None:
        if self._cancellable is not None:
            if self.handle != -1:
                self._cancellable.release_fd()
                self.handle = -1
            self._cancellable = None

    def __repr__(self) -> str:
        return repr(self.handle)

    def __enter__(self) -> int:
        return self.handle

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        trace: Optional[TracebackType],
    ) -> None:
        self.release()


class Cancellable:
    def __init__(self) -> None:
        self._impl = _Cancellable()

    def __repr__(self) -> str:
        return repr(self._impl)

    @property
    def is_cancelled(self) -> bool:
        """
        Query whether cancellable has been cancelled
        """

        return self._impl.is_cancelled()

    def raise_if_cancelled(self) -> None:
        """
        Raise an exception if cancelled
        :raises OperationCancelledError:
        """

        self._impl.raise_if_cancelled()

    def get_pollfd(self) -> CancellablePollFD:
        return CancellablePollFD(self._impl)

    @classmethod
    def get_current(cls) -> _frida.Cancellable:
        """
        Get the top cancellable from the stack
        """

        return _Cancellable.get_current()

    def __enter__(self) -> None:
        self._impl.push_current()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        trace: Optional[TracebackType],
    ) -> None:
        self._impl.pop_current()

    def connect(self, callback: Callable[..., Any]) -> int:
        """
        Register notification callback
        :returns: the created handler id
        """

        return self._impl.connect(callback)

    def disconnect(self, handler_id: int) -> None:
        """
        Unregister notification callback.
        """

        self._impl.disconnect(handler_id)

    def cancel(self) -> None:
        """
        Set cancellable to cancelled
        """

        self._impl.cancel()


def make_auth_callback(callback: Callable[[str], Any]) -> Callable[[Any], str]:
    """
    Wraps authenticated callbacks with JSON marshaling
    """

    def authenticate(token: str) -> str:
        session_info = callback(token)
        return json.dumps(session_info)

    return authenticate


def _to_camel_case(name: str) -> str:
    result = ""
    uppercase_next = False
    for c in name:
        if c == "_":
            uppercase_next = True
        elif uppercase_next:
            result += c.upper()
            uppercase_next = False
        else:
            result += c.lower()
    return result
