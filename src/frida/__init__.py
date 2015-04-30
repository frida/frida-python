# -*- coding: utf-8 -*-

import threading
try:
    import _frida
except Exception as ex:
    import colorama
    from colorama import Back, Fore, Style
    import sys
    colorama.init(autoreset=True)
    print("")
    print("***")
    if str(ex).startswith("No module named "):
        print(Back.RED + Fore.WHITE + Style.BRIGHT + "Frida native extension not found" + Style.RESET_ALL)
        print(Fore.WHITE + Style.BRIGHT + "Please check your PYTHONPATH." + Style.RESET_ALL)
    else:
        print(Back.RED + Fore.WHITE + Style.BRIGHT + "Failed to load the Frida native extension: %s" % ex + Style.RESET_ALL)
        if sys.version_info[0] == 2:
            current_python_version = "%d.%d" % sys.version_info[:2]
        else:
            current_python_version = "%d.x" % sys.version_info[0]
        print(Fore.WHITE + Style.BRIGHT + "Please ensure that the extension was compiled for Python " + current_python_version + "." + Style.RESET_ALL)
    print("***")
    print("")
    raise ex


__version__ = _frida.__version__

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

def spawn(argv, device_id = None):
    return get_device_manager().get_device(device_id).spawn(argv)

def resume(target, device_id = None):
    get_device_manager().get_device(device_id).resume(target)

def kill(target, device_id = None):
    get_device_manager().get_device(device_id).kill(target)

def attach(target, device_id = None):
    return get_device_manager().get_device(device_id).attach(target)

def get_usb_device(timeout = 0):
    return _get_device('tether', timeout)

def get_remote_device(timeout = 0):
    return _get_device('remote', timeout)

def _get_device(type, timeout):
    mgr = get_device_manager()
    def find_usb_device():
        usb_devices = [device for device in mgr.enumerate_devices() if device.type == type]
        if len(usb_devices) > 0:
            return usb_devices[0]
        else:
            return None
    device = find_usb_device()
    if device is None:
        result = [None]
        event = threading.Event()
        def on_devices_changed():
            result[0] = find_usb_device()
            if result[0] is not None:
                event.set()
        mgr.on('changed', on_devices_changed)
        device = find_usb_device()
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
