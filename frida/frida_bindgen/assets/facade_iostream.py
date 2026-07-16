def close(self):
    _invoke(self._impl.close_async, (0,))

def read(self, count):
    return _invoke(self._impl.input_stream.read_bytes_async, (count, 0))

def read_all(self, count):
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = _invoke(self._impl.input_stream.read_bytes_async, (remaining, 0))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def write(self, data):
    return _invoke(self._impl.output_stream.write_bytes_async, (data, 0))

def write_all(self, data):
    view = memoryview(data)
    while len(view) != 0:
        written = _invoke(self._impl.output_stream.write_bytes_async, (bytes(view), 0))
        view = view[written:]
