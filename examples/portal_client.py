import frida
from frida_tools.application import Reactor
import json
import sys
import threading


class Application:
    def __init__(self, nick):
        self._reactor = Reactor(run_until_return=self._process_input)

        token = {
            'nick': nick,
            'secret': "knock-knock"
        }
        self._device = frida.get_device_manager().add_remote_device("::1",
                                                                    certificate="/Users/oleavr/src/cert.pem",
                                                                    token=json.dumps(token))

        self._bus = self._device.get_bus()
        self._bus.on('message', lambda *args: self._reactor.schedule(lambda: self._on_bus_message(*args)))

        self._prompt = "> "
        self._ack_received = threading.Event()

    def run(self):
        self._reactor.schedule(self._start)
        self._reactor.run()

    def _start(self):
        self._bus.subscribe()

    def _process_input(self, reactor):
        while True:
            sys.stdout.write("\r")
            try:
                message = input(self._prompt).strip()
            except:
                self._reactor.cancel_io()
                return
            sys.stdout.write("\033[1A\033[K")
            sys.stdout.flush()

            if len(message) == 0:
                print("Processes:", self._device.enumerate_processes())
                continue

            self._bus.post({
                'type': 'chat',
                'text': message
            })

            self._ack_received.wait()
            self._ack_received.clear()

    def _on_bus_message(self, message, data):
        mtype = message['type']
        if mtype == 'chat':
            print("\r\033[K<{}> {}".format(message['sender'], message['text']))
            sys.stdout.write(self._prompt)
            sys.stdout.flush()
        elif mtype == 'ack':
            self._ack_received.set()
        elif mtype == 'history':
            for item in message['items']:
                self._on_bus_message(item, None)
        else:
            print("Unhandled message:", message)


if __name__ == '__main__':
    nick = sys.argv[1]
    app = Application(nick)
    app.run()
