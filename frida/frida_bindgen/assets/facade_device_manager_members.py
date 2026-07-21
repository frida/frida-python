def get_device_matching(self, predicate: Callable[["Device"], bool], timeout: Union[int, float] = 0) -> "Device":
    deadline = time.monotonic() + timeout
    while True:
        for device in self.enumerate_devices():
            if predicate(device):
                return device
        if time.monotonic() >= deadline:
            raise _frida.InvalidArgumentError("no matching device found")
        time.sleep(0.05)
