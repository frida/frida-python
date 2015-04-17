def main():
    import frida
    from frida.application import ConsoleApplication
    from colorama import Fore, Style
    import json
    import platform
    try:
        if platform.system() == "Darwin":
            # We really want to avoid libedit
            import gnureadline as readline
        else:
            import readline
        HAVE_READLINE = True
    except:
        HAVE_READLINE = False
    import sys
    import threading
    import os

    if HAVE_READLINE:
       HIST_FILE = os.path.join(os.path.expanduser("~"), ".frida_history")

    class REPLApplication(ConsoleApplication):
        def __init__(self):
            if HAVE_READLINE:
                readline.parse_and_bind("tab: complete")
                # force completor to run on first tab press
                readline.parse_and_bind("set show-all-if-unmodified on")
                readline.parse_and_bind("set show-all-if-ambiguous on")
                # Set our custom completer
                readline.set_completer(self.completer)

                try:
                    readline.read_history_file(HIST_FILE)
                except IOError:
                    pass

            self._idle = threading.Event()
            self._cond = threading.Condition()
            self._response = None
            self._completor_locals = []

            super(REPLApplication, self).__init__(self._process_input)

        def _usage(self):
            return "usage: %prog [options] target"

        def _needs_target(self):
            return True

        def _start(self):
            self._prompt_string = self._create_prompt()
            def on_message(message, data):
                self._reactor.schedule(lambda: self._process_message(message, data))
            self._script = self._session.create_script(name="repl", source=self._create_repl_script())
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
            return """
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
            // If we passed in an object
            // TODO: Fix this gross nonsense
            if (typeof(expression) == "object"){
                if (expression.eval){
                    eval("result = " + expression.eval + ";");
                }
                send({ name: '+silent_result', payload: result });
            // Otherwise expression is a string
            } else {
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
            }
        } catch (e) {
            send({ name: '+error', payload: e.toString() });
        }
        recv(onExpression);
    }
    recv(onExpression);
}).call(this);
"""

        def _synchronous_evaluate(self, text):
            self._reactor.schedule(lambda: self._send_expression({"eval": text}))
            self._cond.acquire()
            while self._response is None:
                self._cond.wait()
            response = self._response
            self._response = None
            self._cond.release()
            # TODO: This is super gross, need to actually fix this and unify conventions
            # once we know what we're doing with messages.
            if "payload" not in response[0]:
                response[0]['payload'] = None
            return response[0]['payload']

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

        def completer(self, prefix, index):
            # If it's the first loop, do the init
            if index == 0:
                # If nothing is in the readline buffer
                if not prefix:
                    # Give every key that doesn't start with a "_"
                    self._completor_locals = [key for key in self._synchronous_evaluate("Object.keys(this)") if not key.startswith('_')]
                else:
                    if prefix.endswith("."):
                        thing_to_check = prefix.split(' ')[0][:-1]
                        self._completor_locals = self._synchronous_evaluate("Object.keys(" + thing_to_check + ")")
                    else:
                        if "." in prefix:
                            # grab the last statement
                            target = prefix.split(' ')[-1]
                            needle = target.split('.')[-1]
                            # Chop off everything
                            target = ".".join(target.split('.')[:-1])
                            self._completor_locals = [target + "." + key for key in self._synchronous_evaluate("Object.keys(" + target + ")") if key.startswith(needle)]
                            # Do stuff
                        # Give every key that starts with the root prefix
                        else:
                            self._completor_locals = [key for key in self._synchronous_evaluate("Object.keys(this)") if key.startswith(prefix)]

            try:
                return self._completor_locals[index]
            except IndexError:
                return None

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
                        print("\nThank you for using Frida!")
                        return
                    if len(line.strip()) > 0:
                        if len(expression) > 0:
                            expression += "\n"
                        expression += line.rstrip("\\")

                if HAVE_READLINE:
                    try:
                        readline.write_history_file(HIST_FILE)
                    except IOError:
                        pass

                if expression.endswith("?"):
                    # Help feature
                    self._print_help(expression)
                elif expression.startswith("%"):
                    # "Magic" commands
                    self._do_magic(expression)
                elif expression in ("quit", "q", "exit"):
                    print("Thank you for using Frida!")
                    return
                elif expression == "help":
                    print("Frida help 1.0!")
                else:
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

                    elif name == '+resume':
                        self._resume()

                    elif name == "+silent_result":
                        # TODO: This is hacky as shit, need to make it cleaner/better
                        self._cond.acquire()
                        self._response = (stanza, data)
                        self._cond.notify()
                        self._cond.release()

                    self._idle.set()
                    handled = True

            if not handled:
                print("message:", message, "data:", data)

        def _print_startup_message(self):
            print("""    _____
   (_____)
    |   |    Frida {version} - A world-class dynamic instrumentation framework
    |   |
    |`-'|    Commands:
    |   |        help      -> Displays the help system
    |   |        object?   -> Display information about 'object'
    |   |        exit/quit -> Exit
    |   |
    |   |    More info at http://www.frida.re/docs/home/
    `._.'

""".format(version=frida.__version__))

        def _print_help(self, expression):
            # TODO: Figure out docstrings and implement here. This is real jankaty right now.
            help_text = ""
            if expression.endswith(".?"):
                expression = expression[:-2] + "?"

            obj_to_identify = [x for x in expression.split(' ') if x.endswith("?")][0][:-1]
            obj_type = self._synchronous_evaluate("typeof(%s)" % obj_to_identify)

            if obj_type == "function":

                signature = self._synchronous_evaluate("%s.toString()" % obj_to_identify)
                clean_signature = signature.split("{")[0][:-1].split('function ')[-1]

                if "[native code]" in signature:
                    help_text += "Type:      Function (native)\n"
                else:
                    help_text += "Type:      Function\n"

                help_text += "Signature: %s\n" % clean_signature
                help_text += "Docstring: #TODO :)"
            elif obj_type == "object":
                help_text += "Type:      Object\n"
                help_text += "Docstring: #TODO :)"

            elif obj_type == "boolean":
                help_text += "Type:      Boolean\n"
                help_text += "Docstring: #TODO :)"

            elif obj_type == "string":
                help_text += "Type:      Boolean\n"
                help_text += "Text:      %s\n" % self._synchronous_evaluate("%s.toString()" % obj_to_identify)
                help_text += "Docstring: #TODO :)"

            print(help_text)


        def _do_magic(self, expression):
            #TODO: add local file read capabilities i.e. %run /tmp/script.txt, and other stuff?
            print("You thought I was sleeping, didn't you. Acting.")

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
