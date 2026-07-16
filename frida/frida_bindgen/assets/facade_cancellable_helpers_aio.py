class CancellablePollFD:
    def __init__(self, cancellable):
        self.handle = cancellable.get_fd()
        self._cancellable = cancellable

    def __del__(self):
        self.release()

    def release(self):
        if self._cancellable is not None:
            if self.handle != -1:
                self._cancellable.release_fd()
                self.handle = -1
            self._cancellable = None

    def __repr__(self):
        return repr(self.handle)

    def __enter__(self):
        return self.handle

    def __exit__(self, *exc):
        self.release()
