# -*- coding: utf-8 -*-

def spawn(command_line, device_id = None):
    return get_device_manager().get_device(device_id).spawn(command_line)

def resume(target, device_id = None):
    return get_device_manager().get_device(device_id).resume(target)

def attach(target, device_id = None):
    return get_device_manager().get_device(device_id).attach(target)

def shutdown():
    get_device_manager()._manager.close()


global _device_manager
_device_manager = None
def get_device_manager():
    global _device_manager
    if _device_manager is None:
        from . import core
        import _frida
        _device_manager = core.DeviceManager(_frida.DeviceManager())
        _device_manager.enumerate_devices() # warm up
    return _device_manager
