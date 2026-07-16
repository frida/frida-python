def _setup(self):
    self._message_handlers = []
    self._impl.on("message", self._on_message)

def on(self, signal, callback):
    if signal == "message":
        self._message_handlers.append(callback)
    else:
        self._impl.on(signal, _make_signal_handler(callback))

def off(self, signal, callback):
    if signal == "message":
        self._message_handlers.remove(callback)
    else:
        self._impl.off(signal, callback)

def _on_message(self, raw_message, data):
    message = json.loads(raw_message)
    for handler in list(self._message_handlers):
        try:
            handler(message, data)
        except Exception:
            traceback.print_exc()
