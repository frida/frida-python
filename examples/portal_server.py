# -*- coding: utf-8 -*-
import frida
from frida_tools.application import Reactor
import hashlib
import hmac


ENABLE_CONTROL_INTERFACE = True


class Application(object):
    def __init__(self):
        self._reactor = Reactor(run_until_return=self._process_input)

        cluster_params = frida.EndpointParameters(address="unix:/Users/oleavr/src/cluster",
                                                  certificate="/Users/oleavr/src/identity2.pem",
                                                  authentication=('token', "wow-such-secret"))

        if ENABLE_CONTROL_INTERFACE:
            control_params = frida.EndpointParameters(address="::1",
                                                      port=27042,
                                                      certificate="/Users/oleavr/src/identity.pem",
                                                      authentication=('callback', self._authenticate))
        else:
            control_params = None

        service = frida.PortalService(cluster_params, control_params)
        self._service = service
        self._device = service.device

        service.on('node-connected', lambda *args: self._reactor.schedule(lambda: self._on_node_connected(*args)))
        service.on('node-joined', lambda *args: self._reactor.schedule(lambda: self._on_node_joined(*args)))
        service.on('node-left', lambda *args: self._reactor.schedule(lambda: self._on_node_left(*args)))
        service.on('node-disconnected', lambda *args: self._reactor.schedule(lambda: self._on_node_disconnected(*args)))
        service.on('controller-connected', lambda *args: self._reactor.schedule(lambda: self._on_controller_connected(*args)))
        service.on('controller-disconnected', lambda *args: self._reactor.schedule(lambda: self._on_controller_disconnected(*args)))
        service.on('message', lambda *args: self._reactor.schedule(lambda: self._on_message(*args)))

    def run(self):
        self._reactor.schedule(self._start)
        self._reactor.run()
        print("Out")

    def _start(self):
        self._service.start()

        self._device.enable_spawn_gating()

    def _stop(self):
        self._service.stop()
        print("Stopped")

    def _process_input(self, reactor):
        while True:
            try:
                command = input("Enter command: ").strip()
            except KeyboardInterrupt:
                self._reactor.cancel_io()
                return

            if len(command) == 0:
                print("Processes:", self._device.enumerate_processes())
                continue

            if command == "stop":
                self._reactor.schedule(self._stop)
                break

    def _on_node_connected(self, connection_id, remote_address):
        print("on_node_connected()", connection_id, remote_address)

    def _on_node_joined(self, connection_id, application):
        print("on_node_joined()", connection_id, application)

    def _on_node_left(self, connection_id, application):
        print("on_node_left()", connection_id, application)

    def _on_node_disconnected(self, connection_id, remote_address):
        print("on_node_disconnected()", connection_id, remote_address)

    def _on_controller_connected(self, connection_id, remote_address):
        print("on_controller_connected()", connection_id, remote_address)

    def _on_controller_disconnected(self, connection_id, remote_address):
        print("on_controller_disconnected()", connection_id, remote_address)

    def _on_message(self, connection_id, message, data):
        if message['type'] != 'chat':
            print("Unhandled message:", message)
            return

        text = message['text']

        self._service.post(connection_id, {
            'type': 'ack'
        })
        self._service.broadcast({
            'type': 'chat',
            'sender': connection_id,
            'text': text
        })

    def _authenticate(self, token):
        provided = hashlib.sha1(token.encode('utf-8')).digest()
        expected = hashlib.sha1("knock-knock".encode('utf-8')).digest()
        if not hmac.compare_digest(provided, expected):
            raise ValueError("get outta here")


if __name__ == '__main__':
    app = Application()
    app.run()
