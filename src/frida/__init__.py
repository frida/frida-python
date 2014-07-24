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
                print(Back.RED + Fore.WHITE + Style.BRIGHT + "Frida native extension not found")
                print(Fore.WHITE + Style.BRIGHT + "Please check your PYTHONPATH.")
            else:
                print(Back.RED + Fore.WHITE + Style.BRIGHT + "Failed to load the Frida native extension: %s" % ex)
                if sys.version_info[0] == 2:
                    current_python_version = "%d.%d" % sys.version_info[:2]
                else:
                    current_python_version = "%d.x" % sys.version_info[0]
                print(Fore.WHITE + Style.BRIGHT + "Please ensure that the extension was compiled for Python " + current_python_version + ".")
            print("***")
            print("")
            raise ex
        _device_manager = core.DeviceManager(_frida.DeviceManager())
        _device_manager.enumerate_devices() # warm up
    return _device_manager
