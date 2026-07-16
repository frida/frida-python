def __enter__(self):
    stack = getattr(_current_cancellable, "stack", None)
    if stack is None:
        stack = []
        _current_cancellable.stack = stack
    stack.append(self)
    return self

def __exit__(self, *exc):
    _current_cancellable.stack.pop()
    return False

@classmethod
def get_current(cls):
    return _current_cancellable_get()

def raise_if_cancelled(self):
    if self._impl.is_cancelled():
        raise _frida.OperationCancelledError("operation was cancelled")

def get_pollfd(self):
    return CancellablePollFD(self._impl)
