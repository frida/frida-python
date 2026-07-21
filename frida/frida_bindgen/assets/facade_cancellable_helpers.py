class CancellablePollFD:
    def __init__(self, cancellable: _frida.Cancellable) -> None:
        self.handle = cancellable.get_fd()
        self._cancellable: Optional[_frida.Cancellable] = cancellable

    def __del__(self) -> None:
        self.release()

    def release(self) -> None:
        if self._cancellable is not None:
            if self.handle != -1:
                self._cancellable.release_fd()
                self.handle = -1
            self._cancellable = None

    def __repr__(self) -> str:
        return repr(self.handle)

    def __enter__(self) -> int:
        return self.handle

    def __exit__(self, *exc: Any) -> None:
        self.release()
