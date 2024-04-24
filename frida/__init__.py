from typing import Any, Callable, Dict, List, Optional, Tuple, Union

try:
    from . import _frida
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
    """
    Returns a dictionary of information about the host system
    """

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
    """
    Spawn a process into an attachable state
    """

    return get_local_device().spawn(program=program, argv=argv, envp=envp, env=env, cwd=cwd, stdio=stdio, **kwargs)


def resume(target: core.ProcessTarget) -> None:
    """
    Resume a process from the attachable state
    :param target: the PID or name of the process
    """

    get_local_device().resume(target)


def kill(target: core.ProcessTarget) -> None:
    """
    Kill a process
    :param target: the PID or name of the process
    """

    get_local_device().kill(target)


def attach(
    target: core.ProcessTarget, realm: Optional[str] = None, persist_timeout: Optional[int] = None
) -> core.Session:
    """
    Attach to a process
    :param target: the PID or name of the process
    """

    return get_local_device().attach(target, realm=realm, persist_timeout=persist_timeout)


def inject_library_file(target: core.ProcessTarget, path: str, entrypoint: str, data: str) -> int:
    """
    Inject a library file to a process.
    :param target: the PID or name of the process
    """

    return get_local_device().inject_library_file(target, path, entrypoint, data)


def inject_library_blob(target: core.ProcessTarget, blob: bytes, entrypoint: str, data: str) -> int:
    """
    Inject a library blob to a process
    :param target: the PID or name of the process
    """

    return get_local_device().inject_library_blob(target, blob, entrypoint, data)


def get_local_device() -> core.Device:
    """
    Get the local device
    """

    return get_device_manager().get_local_device()


def get_remote_device() -> core.Device:
    """
    Get the first remote device in the devices list
    """

    return get_device_manager().get_remote_device()


def get_usb_device(timeout: int = 0) -> core.Device:
    """
    Get the first device connected over USB in the devices list
    """

    return get_device_manager().get_usb_device(timeout)


def get_device(id: Optional[str], timeout: int = 0) -> core.Device:
    """
    Get a device by its id
    """

    return get_device_manager().get_device(id, timeout)


def get_device_matching(predicate: Callable[[core.Device], bool], timeout: int = 0) -> core.Device:
    """
    Get device matching predicate.
    :param predicate: a function to filter the devices
    :param timeout: operation timeout in seconds
    """

    return get_device_manager().get_device_matching(predicate, timeout)


def enumerate_devices() -> List[core.Device]:
    """
    Enumerate all the devices from the device manager
    """

    return get_device_manager().enumerate_devices()


@core.cancellable
def shutdown() -> None:
    """
    Shutdown the main device manager
    """

    get_device_manager()._impl.close()
