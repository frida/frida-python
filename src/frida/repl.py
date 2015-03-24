def main():
    from frida.application import ConsoleApplication
    from colorama import Fore, Style
    import json
    import platform
    try:
        import readline
        # Stupid hack to workaround oxs's shitty readline impl
        if platform.system() == "Darwin":
            import gnureadline as readline
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
            return "usage: %prog [options] target"

        def _needs_target(self):
            return True

        def _start(self):
            self._prompt_string = self._create_prompt()
            def on_message(message, data):
                self._reactor.schedule(lambda: self._process_message(message, data))
            self._script = self._session.create_script(self._create_repl_script())
            self._script.on('message', on_message)
            self._script.load()
            if self._spawned_argv is not None:
                self._update_status("Spawned `%s`. Call resume() to let the main thread start executing!" % " ".join(self._spawned_argv))
            self._idle.set()

        def _stop(self):
            try:
                self._script.unload()
            except:
                pass
            self._script = None

        def _create_repl_script(self):
            return """\

(function () {
    this.resume = function () {
        send({ name: '+resume' });
    };

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
            eval("result = " + expression + ";");
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
}).call(this);
"""

        def _create_prompt(self):
            # Todo: Make this prompt less shitty and make sure all platforms are covered ;)
            device_type = self._device.type
            type_name = self._target[0]
            target = self._target[1]

            if device_type == "local":
                if self._target[0] == "name":
                    type_name = "ProcName"
                elif self._target[0] == "pid":
                    type_name = "PID"
                prompt_string = "%s::%s::%s" % ("Local", type_name, target)

            elif device_type == "tether" :
                prompt_string = "%s::%s::%s" % ("USB", self._device.name, target)

            else:
                prompt_string = "%s::%s::%s" % (self._device.name, self._device.name, target)

            return prompt_string
        def _process_input(self):
            if sys.version_info[0] >= 3:
                input_impl = input
            else:
                input_impl = raw_input

            self._print_startup_message()

            while True:
                self._idle.wait()
                expression = ""
                line = ""
                while len(expression) == 0 or line.endswith("\\"):
                    try:
                        if len(expression) == 0:
                            line = input_impl("[%s]" % self._prompt_string + "-> ")
                        else:
                            line = input_impl("... ")
                    except EOFError:
                        # An extra newline after EOF to exit the REPL cleanly
                        print "\nThank you for using Frida!"
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
                if isinstance(stanza, dict):
                    name = stanza.get('name')
                    if name in ('+result', '+error'):
                        if data is not None:
                            output = hexdump(data).rstrip("\n")
                        else:
                            if 'payload' in stanza:
                                value = stanza['payload']
                                if stanza['name'] == '+result':
                                    output = json.dumps(value, sort_keys=True, indent=4, separators=(",", ": "))
                                else:
                                    output = Fore.RED + Style.BRIGHT + value + Style.RESET_ALL
                                sys.stdout.write(output + "\n")
                                sys.stdout.flush()
                        self._idle.set()

                        handled = True
                    elif name == '+resume':
                        self._resume()
                        self._idle.set()

                        handled = True

            if not handled:
                print("message:", message, "data:", data)

        def _print_startup_message(self):
            print """    _____
   (_____)
    |   |    Frida v3.0 - A world-class dynamic instrumentation framework
    |   |
    |`-'|    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'

"""

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
