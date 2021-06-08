# -*- coding: utf-8 -*-
import frida
from frida_tools.application import Reactor
from pathlib import Path


class Application(object):
    def __init__(self):
        self._reactor = Reactor(run_until_return=self._process_input)

        gateway_params = frida.EndpointParameters(port=8080)
        www = Path(__file__).parent.resolve() / "web_client" / "dist"

        self._service = frida.WebGatewayService(gateway_params, root=www)

    def run(self):
        self._reactor.schedule(self._start)
        self._reactor.run()

    def _start(self):
        self._service.start()

    def _stop(self):
        self._service.stop()

    def _process_input(self, reactor):
        while True:
            try:
                command = input("Enter command: ").strip()
            except KeyboardInterrupt:
                self._reactor.cancel_io()
                return

            if command == "stop":
                self._reactor.schedule(self._stop)
                break


if __name__ == '__main__':
    app = Application()
    app.run()
