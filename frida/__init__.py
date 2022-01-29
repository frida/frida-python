from typing import Any, Callable, Dict, List, Optional, Tuple, Union

try:
    import _frida
except Exception as ex:
    print("")
    print("***")
    if str(ex).startswith("No module named "):
        print("Frida native extension not found")
        print("Please check your PYTHONPATH.")
    else:
        print(f"Failed to load the Frida native extension: {ex}")
        print("Please ensure that the extension was compiled correctly")
    print("***")
    print("")
    raise ex
from . import core

__version__: str = _frida.__version__

get_device_manager = core.get_device_manager
Relay = _frida.Relay
PortalService = core.PortalService
EndpointParameters = core.EndpointParameters
Compiler = core.Compiler
FileMonitor = _frida.FileMonitor
Cancellable = core.Cancellable

ServerNotRunningError = _frida.ServerNotRunningError
ExecutableNotFoundError = _frida.ExecutableNotFoundError
ExecutableNotSupportedError = _frida.ExecutableNotSupportedError
ProcessNotFoundError = _frida.ProcessNotFoundError
ProcessNotRespondingError = _frida.ProcessNotRespondingError
InvalidArgumentError = _frida.InvalidArgumentError
InvalidOperationError = _frida.InvalidOperationError
PermissionDeniedError = _frida.PermissionDeniedError
AddressInUseError = _frida.AddressInUseError
TimedOutError = _frida.TimedOutError
NotSupportedError = _frida.NotSupportedError
ProtocolError = _frida.ProtocolError
TransportError = _frida.TransportError
OperationCancelledError = _frida.OperationCancelledError


def query_system_parameters() -> Dict[str, Any]:
    return get_local_device().query_system_parameters()


def spawn(
    program: Union[str, List[Union[str, bytes]], Tuple[Union[str, bytes]]],
    argv: Union[None, List[Union[str, bytes]], Tuple[Union[str, bytes]]] = None,
    envp: Optional[Dict[str, str]] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    stdio: Optional[str] = None,
    **kwargs: Any,
) -> int:
    return get_local_device().spawn(program=program, argv=argv, envp=envp, env=env, cwd=cwd, stdio=stdio, **kwargs)


def resume(target: core.ProcessTarget) -> None:
    get_local_device().resume(target)


def kill(target: core.ProcessTarget) -> None:
    get_local_device().kill(target)


def attach(target: Union[int, str], realm: Optional[str] = None, persist_timeout: Optional[int] = None) -> core.Session:
    return get_local_device().attach(target, realm=realm, persist_timeout=persist_timeout)


def inject_library_file(target: Union[int, str], path: str, entrypoint: str, data: str) -> int:
    return get_local_device().inject_library_file(target, path, entrypoint, data)


def inject_library_blob(target: Union[int, str], blob: bytes, entrypoint: str, data: str) -> int:
    return get_local_device().inject_library_blob(target, blob, entrypoint, data)


def get_local_device() -> core.Device:
    return get_device_matching(lambda d: d.type == "local", timeout=0)


def get_remote_device() -> core.Device:
    return get_device_matching(lambda d: d.type == "remote", timeout=0)


def get_usb_device(timeout: int = 0) -> core.Device:
    return get_device_matching(lambda d: d.type == "usb", timeout)


def get_device(id: Optional[str], timeout: int = 0) -> core.Device:
    return get_device_manager().get_device(id, timeout)


def get_device_matching(predicate: Callable[[core.Device], bool], timeout: int = 0) -> core.Device:
    return get_device_manager().get_device_matching(predicate, timeout)


def enumerate_devices() -> List[core.Device]:
    return get_device_manager().enumerate_devices()


@core.cancellable
def shutdown() -> None:
    get_device_manager()._impl.close()
