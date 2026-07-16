def _setup(self):
    self._authenticated_handlers = []
    self._message_handlers = []
    self._impl.on("authenticated", self._on_authenticated)
    self._impl.on("message", self._on_message)

def on(self, signal, callback):
    if signal == "authenticated":
        self._authenticated_handlers.append(callback)
    elif signal == "message":
        self._message_handlers.append(callback)
    else:
        self._impl.on(signal, _make_signal_handler(callback))

def off(self, signal, callback):
    if signal == "authenticated":
        self._authenticated_handlers.remove(callback)
    elif signal == "message":
        self._message_handlers.remove(callback)
    else:
        self._impl.off(signal, callback)

def _on_authenticated(self, connection_id, raw_session_info):
    session_info = json.loads(raw_session_info)
    for handler in list(self._authenticated_handlers):
        try:
            handler(connection_id, session_info)
        except Exception:
            traceback.print_exc()

def _on_message(self, connection_id, raw_message, data):
    message = json.loads(raw_message)
    for handler in list(self._message_handlers):
        try:
            handler(connection_id, message, data)
        except Exception:
            traceback.print_exc()
