def main():
    from frida.application import ConsoleApplication
    import json
    try:
        import readline
        HAVE_READLINE = True
    except:
        HAVE_READLINE = False
    import sys
    import threading

    class REPLApplication(ConsoleApplication):
        def __init__(self):
            if HAVE_READLINE:
                readline.parse_and_bind("tab: complete")
            self._idle = threading.Event()
            super(REPLApplication, self).__init__(self._process_input)

        def _usage(self):
            return "usage: %prog [options]"

        def _target_specifier(self, parser, options, args):
            if len(args) != 1:
                parser.error("process name or id must be specified")
            return args[0]

        def _start(self):
            def on_message(message, data):
                self._reactor.schedule(lambda: self._process_message(message, data))
            self._script = self._process.session.create_script(self._create_repl_script())
            self._script.on("message", on_message)
            self._script.load()
            self._idle.set()

        def _stop(self):
            self._script.unload()

        def _create_repl_script(self):
            return """\

Object.defineProperty(this, 'modules', {
    enumerable: true,
    get: function () {
        var result = [];
        Process.enumerateModules({
            onMatch: function onMatch(mod) {
                result.push(mod);
            },
            onComplete: function onComplete() {
            }
        });
        return result;
    }
});

function onExpression(expression) {
    try {
        var result;
        eval("result = " + expression);
        var sentRaw = false;
        if (result && result.hasOwnProperty('length')) {
            try {
                send({ name: '+result', payload: "OOB" }, result);
                sentRaw = true;
            } catch (e) {
            }
        }
        if (!sentRaw) {
            send({ name: '+result', payload: result });
        }
    } catch (e) {
        send({ name: '+error', payload: e.toString() });
    }
    recv(onExpression);
}
recv(onExpression);
"""

        def _process_input(self):
            if sys.version_info[0] >= 3:
                input_impl = input
            else:
                input_impl = raw_input
            while True:
                self._idle.wait()
                expression = ""
                line = ""
                while len(expression) == 0 or line.endswith("\\"):
                    try:
                        if len(expression) == 0:
                            line = input_impl(">>> ")
                        else:
                            line = input_impl("... ")
                    except EOFError:
                        return
                    if len(line.strip()) > 0:
                        if len(expression) > 0:
                            expression += "\n"
                        expression += line.rstrip("\\")

                if HAVE_READLINE:
                    readline.add_history(expression)
                self._idle.clear()
                self._reactor.schedule(lambda: self._send_expression(expression))

        def _send_expression(self, expression):
            self._script.post_message(expression)

        def _process_message(self, message, data):
            handled = False

            if message['type'] == 'send' and 'payload' in message:
                stanza = message['payload']
                if isinstance(stanza, dict) and stanza.get('name') in ('+result', '+error'):
                    handled = True
                    if data is not None:
                        output = hexdump(data).rstrip("\n")
                    else:
                        if 'payload' in stanza:
                            value = stanza['payload']
                            if stanza['name'] == '+result':
                                output = json.dumps(value, sort_keys=True, indent=4, separators=(",", ": "))
                            else:
                                output = value
                        else:
                            output = "undefined"
                    sys.stdout.write(output + "\n")
                    sys.stdout.flush()
                    self._idle.set()

            if not handled:
                print("message:", message, "data:", data)

    def hexdump(src, length=16):
        try:
            xrange
        except NameError:
            xrange = range
        FILTER = "".join([(len(repr(chr(x))) == 3) and chr(x) or "." for x in range(256)])
        lines = []
        for c in xrange(0, len(src), length):
            chars = src[c:c + length]
            hex = " ".join(["%02x" % x for x in iterbytes(chars)])
            printable = ''.join(["%s" % ((x <= 127 and FILTER[x]) or ".") for x in iterbytes(chars)])
            lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
        return "".join(lines)

    if sys.version_info[0] >= 3:
        iterbytes = lambda x: iter(x)
    else:
        def iterbytes(data):
            return (ord(char) for char in data)

    app = REPLApplication()
    app.run()


if __name__ == '__main__':
    main()
