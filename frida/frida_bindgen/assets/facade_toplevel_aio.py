__version__ = _frida.__version__


def get_device_manager():
    return _wrap(_frida.get_device_manager())


async def get_device(id, timeout=0):
    return await get_device_manager().get_device_by_id(id, int(timeout * 1000))


async def get_device_matching(predicate, timeout=0):
    return await get_device_manager().get_device_matching(predicate, timeout)


async def get_local_device():
    return await get_device_manager().get_device_by_type("local", 0)


async def get_remote_device():
    return await get_device_manager().get_device_by_type("remote", 0)


async def get_usb_device(timeout=0):
    return await get_device_manager().get_device_by_type("usb", int(timeout * 1000))


async def enumerate_devices():
    return await get_device_manager().enumerate_devices()


async def query_system_parameters():
    return await (await get_local_device()).query_system_parameters()


async def spawn(program, argv=None, envp=None, env=None, cwd=None, stdio=None, **aux):
    device = await get_local_device()
    return await device.spawn(
        program, argv=argv, envp=envp, env=env, cwd=cwd, stdio=stdio, **aux
    )


async def resume(target):
    return await (await get_local_device()).resume(target)


async def kill(target):
    return await (await get_local_device()).kill(target)


async def attach(target, **kwargs):
    return await (await get_local_device()).attach(target, **kwargs)


async def inject_library_file(target, path, entrypoint, data):
    return await (await get_local_device()).inject_library_file(target, path, entrypoint, data)


async def inject_library_blob(target, blob, entrypoint, data):
    return await (await get_local_device()).inject_library_blob(target, blob, entrypoint, data)


async def shutdown():
    await get_device_manager().close()
