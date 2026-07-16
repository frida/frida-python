__version__ = _frida.__version__


def get_device_manager():
    return _wrap(_frida.get_device_manager())


def get_device(id, timeout=0):
    return get_device_manager().get_device_by_id(id, int(timeout * 1000))


def get_device_matching(predicate, timeout=0):
    return get_device_manager().get_device_matching(predicate, timeout)


def get_local_device():
    return get_device_manager().get_device_by_type("local", 0)


def get_remote_device():
    return get_device_manager().get_device_by_type("remote", 0)


def get_usb_device(timeout=0):
    return get_device_manager().get_device_by_type("usb", int(timeout * 1000))


def enumerate_devices():
    return get_device_manager().enumerate_devices()


def query_system_parameters():
    return get_local_device().query_system_parameters()


def spawn(program, argv=None, envp=None, env=None, cwd=None, stdio=None, **aux):
    return get_local_device().spawn(
        program, argv=argv, envp=envp, env=env, cwd=cwd, stdio=stdio, **aux
    )


def resume(target):
    return get_local_device().resume(target)


def kill(target):
    return get_local_device().kill(target)


def attach(target, **kwargs):
    return get_local_device().attach(target, **kwargs)


def inject_library_file(target, path, entrypoint, data):
    return get_local_device().inject_library_file(target, path, entrypoint, data)


def inject_library_blob(target, blob, entrypoint, data):
    return get_local_device().inject_library_blob(target, blob, entrypoint, data)


def shutdown():
    get_device_manager().close()
