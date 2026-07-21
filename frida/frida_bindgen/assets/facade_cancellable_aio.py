def __enter__(self) -> "Cancellable":
    self._token = _current_cancellable.set(self)
    return self

def __exit__(self, *exc: Any) -> Literal[False]:
    _current_cancellable.reset(self._token)
    return False

@classmethod
def get_current(cls) -> "Cancellable":
    return _current_cancellable.get()

def raise_if_cancelled(self) -> None:
    if self._impl.is_cancelled():
        raise _frida.OperationCancelledError("operation was cancelled")

def get_pollfd(self) -> "CancellablePollFD":
    return CancellablePollFD(self._impl)
