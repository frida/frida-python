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


__version__ = _frida.__version__

FileMonitor = _frida.FileMonitor

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


def spawn(*args, **kwargs):
    return get_local_device().spawn(*args, **kwargs)


def resume(target):
    get_local_device().resume(target)


def kill(target):
    get_local_device().kill(target)


def attach(target):
    return get_local_device().attach(target)


def inject_library_file(target, path, entrypoint, data):
    return get_local_device().inject_library_file(target, path, entrypoint, data)


def inject_library_blob(target, blob, entrypoint, data):
    return get_local_device().inject_library_blob(target, blob, entrypoint, data)


def enumerate_devices():
    return get_device_manager().enumerate_devices()


def get_local_device():
    return _get_device(lambda device: device.type == 'local', timeout=0)


def get_remote_device():
    return _get_device(lambda device: device.type == 'remote', timeout=0)


def get_usb_device(timeout = 0):
    return _get_device(lambda device: device.type == 'usb', timeout)


def get_device(id, timeout = 0):
    return _get_device(lambda device: device.id == id, timeout)


def _get_device(predicate, timeout):
    mgr = get_device_manager()
    def find_matching_device():
        usb_devices = [device for device in mgr.enumerate_devices() if predicate(device)]
        if len(usb_devices) > 0:
            return usb_devices[0]
        else:
            return None
    device = find_matching_device()
    if device is None:
        result = [None]
        event = threading.Event()
        def on_devices_changed():
            result[0] = find_matching_device()
            if result[0] is not None:
                event.set()
        mgr.on('changed', on_devices_changed)
        device = find_matching_device()
        if device is None:
            event.wait(timeout)
            device = result[0]
        mgr.off('changed', on_devices_changed)
        if device is None:
            raise TimedOutError("timed out while waiting for device to appear")
    return device


def shutdown():
    get_device_manager()._impl.close()


global _device_manager
_device_manager = None
def get_device_manager():
    global _device_manager
    if _device_manager is None:
        from . import core
        _device_manager = core.DeviceManager(_frida.DeviceManager())
    return _device_manager
