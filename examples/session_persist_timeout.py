# -*- coding: utf-8 -*-
import frida
from frida_tools.application import Reactor


class Application(object):
    def __init__(self):
        self._reactor = Reactor(run_until_return=self._process_input)

        self._device = None
        self._session = None

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        device = frida.get_remote_device()
        self._device = device

        print(">>> attach()")
        session = self._device.attach("hello2", session_persist_timeout=30)
        print("<<< attach()")
        self._session = session
        session.on('detached', lambda *args: self._reactor.schedule(lambda: self._on_detached(*args)))

        print(">>> create_script()")
        script = session.create_script("""
let _puts = null;

Interceptor.attach(DebugSymbol.getFunctionByName('f'), {
  onEnter(args) {
    const n = args[0].toInt32();
    send(n);
  }
});

rpc.exports.dispose = () => {
  puts('Script unloaded');
};

let serial = 1;
setInterval(() => {
  puts(`Agent still here! serial=${serial++}`);
}, 5000);

function puts(s) {
  if (_puts === null) {
    _puts = new NativeFunction(Module.getExportByName(null, 'puts'), 'int', ['pointer']);
  }
  _puts(Memory.allocUtf8String(s));
}
""")
        print("<<< create_script()")
        self._script = script
        script.on('message', lambda *args: self._reactor.schedule(lambda: self._on_message(*args)))
        print(">>> load()")
        script.load()
        print("<<< load()")

    def _process_input(self, reactor):
        while True:
            try:
                command = input("> ").strip()
            except:
                self._reactor.cancel_io()
                return

            if command == "resume":
                try:
                    print(">>> resume()")
                    self._session.resume()
                    print("<<< resume()")
                except Exception as e:
                    print("!!!", e)
            else:
                print("Unknown command")

    def _on_detached(self, reason, crash):
        print("⚡ detached: reason={}, crash={}".format(reason, crash))

    def _on_message(self, message, data):
        print("⚡ message: {}".format(message))


app = Application()
app.run()
