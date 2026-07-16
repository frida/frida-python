def __enter__(self):
    self._token = _current_cancellable.set(self)
    return self

def __exit__(self, *exc):
    _current_cancellable.reset(self._token)
    return False

@classmethod
def get_current(cls):
    return _current_cancellable.get()

def raise_if_cancelled(self):
    if self._impl.is_cancelled():
        raise _frida.OperationCancelledError("operation was cancelled")

def get_pollfd(self):
    return CancellablePollFD(self._impl)
