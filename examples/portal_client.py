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

        self._bus = self._device.bus
        self._bus.on('message', lambda *args: self._reactor.schedule(lambda: self._on_bus_message(*args)))

        self._channel = None
        self._prompt = "> "
        self._ack_received = threading.Event()

    def run(self):
        self._reactor.schedule(self._start)
        self._reactor.run()

    def _start(self):
        self._bus.attach()

    def _process_input(self, reactor):
        while True:
            sys.stdout.write("\r")
            try:
                text = input(self._prompt).strip()
            except:
                self._reactor.cancel_io()
                return
            sys.stdout.write("\033[1A\033[K")
            sys.stdout.flush()

            if text.startswith("/join "):
                if self._channel is not None:
                    self._bus.post({
                        'type': 'leave',
                        'channel': self._channel
                    })
                channel = text[6:]
                self._channel = channel
                self._prompt = "{} > ".format(channel)
                self._bus.post({
                    'type': 'join',
                    'channel': channel
                })
                self._print("*** Joined", channel)
                continue

            if len(text) == 0:
                self._print("Processes:", self._device.enumerate_processes())
                continue

            if self._channel is not None:
                self._bus.post({
                    'channel': self._channel,
                    'type': 'chat',
                    'text': text
                })

                self._ack_received.wait()
                self._ack_received.clear()
            else:
                self._print("*** Need to /join a channel first")

    def _on_bus_message(self, message, data):
        mtype = message['type']
        if mtype == 'chat':
            self._print("<{}> {}".format(message['sender'], message['text']))
        elif mtype == 'ack':
            self._ack_received.set()
        elif mtype == 'history':
            for item in message['items']:
                self._on_bus_message(item, None)
        elif mtype == 'welcome':
            self._print("*** Welcome! Available channels:", repr(message['channels']))
        else:
            self._print("Unhandled message:", message)

    def _print(self, *words):
        print("\r\033[K" + " ".join(words))
        sys.stdout.write(self._prompt)
        sys.stdout.flush()


if __name__ == '__main__':
    nick = sys.argv[1]
    app = Application(nick)
    app.run()
