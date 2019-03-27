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
    return get_device_matching(lambda device: device.type == 'local', timeout=0)


def get_remote_device():
    return get_device_matching(lambda device: device.type == 'remote', timeout=0)


def get_usb_device(timeout = 0):
    return get_device_matching(lambda device: device.type == 'usb', timeout)


def get_device(id, timeout = 0):
    return get_device_matching(lambda device: device.id == id, timeout)


def get_device_matching(predicate, timeout = 0):
    matches = []
    lock = threading.Lock()
    done = threading.Event()

    def on_device_added(device):
        if predicate(device):
            with lock:
                matches.append(device)
            done.set()

    manager = get_device_manager()
    manager.on('added', on_device_added)
    try:
        initial_matches = [device for device in manager.enumerate_devices() if predicate(device)]
        if len(initial_matches) > 0:
            return initial_matches[0]

        done.wait(timeout)

        with lock:
            if len(matches) == 0:
                if timeout == 0:
                    raise InvalidArgumentError("device not found")
                else:
                    raise TimedOutError("timed out while waiting for device to appear")

            return matches[0]
    finally:
        manager.off('added', on_device_added)


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
