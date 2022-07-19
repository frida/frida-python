# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import threading

try:
    import _frida
except Exception as ex:
    import sys
    print("")
    print("***")
    if str(ex).startswith("No module named "):
        print("Frida native extension not found")
        print("Please check your PYTHONPATH.")
    else:
        print("Failed to load the Frida native extension: %s" % ex)
        if sys.version_info[0] == 2:
            current_python_version = "%d.%d" % sys.version_info[:2]
        else:
            current_python_version = "%d.x" % sys.version_info[0]
        print("Please ensure that the extension was compiled for Python " + current_python_version + ".")
    print("***")
    print("")
    raise ex
from . import core


__version__ = _frida.__version__

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


def query_system_parameters(**kwargs):
    return get_local_device().query_system_parameters(**kwargs)


def spawn(*args, **kwargs):
    return get_local_device().spawn(*args, **kwargs)


def resume(target, **kwargs):
    get_local_device().resume(target, **kwargs)


def kill(target, **kwargs):
    get_local_device().kill(target, **kwargs)


def attach(target, *args, **kwargs):
    return get_local_device().attach(target, *args, **kwargs)


def inject_library_file(target, path, entrypoint, data, **kwargs):
    return get_local_device().inject_library_file(target, path, entrypoint, data, **kwargs)


def inject_library_blob(target, blob, entrypoint, data, **kwargs):
    return get_local_device().inject_library_blob(target, blob, entrypoint, data, **kwargs)


def get_local_device(**kwargs):
    return get_device_matching(lambda d: d.type == 'local', timeout=0, **kwargs)


def get_remote_device(**kwargs):
    return get_device_matching(lambda d: d.type == 'remote', timeout=0, **kwargs)


def get_usb_device(timeout=0, **kwargs):
    return get_device_matching(lambda d: d.type == 'usb', timeout, **kwargs)


def get_device(id, timeout=0, **kwargs):
    return get_device_manager().get_device(id, timeout, **kwargs)


def get_device_matching(predicate, timeout=0, **kwargs):
    return get_device_manager().get_device_matching(predicate, timeout, **kwargs)


def enumerate_devices(**kwargs):
    return get_device_manager().enumerate_devices(**kwargs)


@core.cancellable
def shutdown():
    get_device_manager()._impl.close()
