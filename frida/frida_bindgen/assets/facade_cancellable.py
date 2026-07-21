def __enter__(self) -> "Cancellable":
    stack = getattr(_current_cancellable, "stack", None)
    if stack is None:
        stack = []
        _current_cancellable.stack = stack
    stack.append(self)
    return self

def __exit__(self, *exc: Any) -> Literal[False]:
    _current_cancellable.stack.pop()
    return False

@classmethod
def get_current(cls) -> "Cancellable":
    return _current_cancellable_get()

def raise_if_cancelled(self) -> None:
    if self._impl.is_cancelled():
        raise _frida.OperationCancelledError("operation was cancelled")

def get_pollfd(self) -> "CancellablePollFD":
    return CancellablePollFD(self._impl)
