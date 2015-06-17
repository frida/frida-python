from __future__ import unicode_literals
def main():
    import frida
    from frida.application import ConsoleApplication
    from colorama import Fore, Style
    import json
    import platform
    import sys
    import threading
    import os
    from prompt_toolkit.shortcuts import create_default_application, create_default_output, create_eventloop
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.completion import Completion, Completer
    from prompt_toolkit.interface import CommandLineInterface
    from pygments.lexers import JavascriptLexer
    from pygments.token import Token

    class REPLApplication(ConsoleApplication):
        def __init__(self):
            self._script = None
            self._seqno = 0
            self._ready = threading.Event()
            self._response_cond = threading.Condition()
            self._response_data = None
            self._completor_locals = []
            self._history = FileHistory(os.path.join(os.path.expanduser('~'), '.frida_history'))
            self._completer = FridaCompleter(self)
            self._cli = None

            super(REPLApplication, self).__init__(self._process_input, self._on_stop)

        def _add_options(self, parser):
            parser.add_option("-l", "--load", help="load SCRIPT", metavar="SCRIPT",
                type='string', action='store', dest="user_script", default=None)

        def _initialize(self, parser, options, args):
            self._user_script = options.user_script

        def _usage(self):
            return "usage: %prog [options] target"

        def _needs_target(self):
            return True

        def _start(self):
            self._prompt_string = self._create_prompt()
            try:
                self._load_script()
            except Exception as e:
                self._update_status("Failed to load script: {error}".format(error=e))
                self._exit(1)
                return
            if self._spawned_argv is not None:
                self._update_status("Spawned `{command}`. Use %resume to let the main thread start executing!".format(command=" ".join(self._spawned_argv)))
            else:
                sys.stdout.write("\033[A")
            self._ready.set()

        def _on_stop(self):
            def set_return():
                raise EOFError()

            try:
                self._cli.eventloop.call_from_executor(set_return)
            except Exception:
                pass

        def _stop(self):
            self._unload_script()

        def _load_script(self):
            self._seqno += 1
            script = self._session.create_script(name="repl%d" % self._seqno, source=self._create_repl_script())
            self._unload_script()
            self._script = script
            def on_message(message, data):
                self._reactor.schedule(lambda: self._process_message(message, data))
            script.on('message', on_message)
            script.load()

        def _unload_script(self):
            if self._script is None:
                return
            try:
                self._script.unload()
            except:
                pass
            self._script = None

        def _process_input(self, reactor):
            self._print_startup_message()
            while self._ready.wait(0.5) != True:
                if not reactor.is_running():
                    return

            while True:
                expression = ""
                line = ""
                while len(expression) == 0 or line.endswith("\\"):
                    if not reactor.is_running():
                        return
                    try:
                        prompt = "[%s]" % self._prompt_string + "-> " if len(expression) == 0 else "... "

                        # We create the prompt manually instead of using get_input,
                        # so we can use the cli in the _on_stop method
                        eventloop = create_eventloop()

                        self._cli = CommandLineInterface(
                            application=create_default_application(prompt, history=self._history, completer=self._completer, lexer=JavascriptLexer),
                            eventloop=eventloop,
                            output=create_default_output())

                        try:
                            line = None

                            document = self._cli.run()

                            if document:
                                line = document.text
                        finally:
                            eventloop.close()
                    except EOFError:
                        # An extra newline after EOF to exit the REPL cleanly
                        print("\nThank you for using Frida!")
                        return
                    except KeyboardInterrupt:
                        line = ""
                        continue
                    if len(line.strip()) > 0:
                        if len(expression) > 0:
                            expression += "\n"
                        expression += line.rstrip("\\")

                if expression.endswith("?"):
                    try:
                        self._print_help(expression)
                    except Exception as ex:
                        error = ex.message
                        sys.stdout.write(Fore.RED + Style.BRIGHT + error['name'] + Style.RESET_ALL + ": " + error['message'] + "\n")
                        sys.stdout.flush()
                elif expression.startswith("%"):
                    self._do_magic(expression[1:].rstrip())
                elif expression in ("exit", "quit", "q"):
                    print("Thank you for using Frida!")
                    return
                elif expression == "help":
                    print("Help: #TODO :)")
                else:
                    self._eval_and_print(expression)

        def _eval_and_print(self, expression):
            try:
                (t, value) = self._evaluate(expression)
                if t in ('function', 'undefined', 'null'):
                    output = t
                elif t == 'binary':
                    output = hexdump(value).rstrip("\n")
                else:
                    output = json.dumps(value, sort_keys=True, indent=4, separators=(",", ": "))
            except frida.InvalidOperationError:
                return
            except Exception as ex:
                error = ex.message
                output = Fore.RED + Style.BRIGHT + error['name'] + Style.RESET_ALL + ": " + error['message']
            sys.stdout.write(output + "\n")
            sys.stdout.flush()

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
            (obj_type, obj_value) = self._evaluate(obj_to_identify)

            if obj_type == "function":
                signature = self._evaluate("%s.toString()" % obj_to_identify)[1]
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
                help_text += "Text:      %s\n" % self._evaluate("%s.toString()" % obj_to_identify)[1]
                help_text += "Docstring: #TODO :)"

            print(help_text)

        def _do_magic(self, statement):
            tokens = statement.split(" ")
            command = tokens[0]
            args = tokens[1:]

            if command == 'resume' and len(args) == 0:
                self._reactor.schedule(lambda: self._resume())
            elif command == 'load' and len(args) == 1:
                old_user_script = self._user_script
                self._user_script = args[0]
                if not self._reload():
                    self._user_script = old_user_script
            elif command == 'reload' and len(args) == 0:
                self._reload()
            elif command == 'unload' and len(args) == 0:
                self._user_script = None
                self._reload()
            elif command == 'time' and len(args) > 0:
                self._eval_and_print('''
                    (function() {{
                        var _startTime = Date.now();
                        var _result = {expression};
                        var _endTime = Date.now();
                        console.log('Time: ' + (_endTime - _startTime).toLocaleString() + ' ms.');
                        return _result;
                    }})();'''.format(expression=' '.join(args)))
            else:
                print("Unknown command: {command}".format(command=command))

        def _reload(self):
            completed = threading.Event()
            result = [None]
            def do_reload():
                try:
                    self._load_script()
                except Exception as e:
                    result[0] = e
                completed.set()
            self._reactor.schedule(do_reload)
            completed.wait()
            if result[0] is None:
                return True
            else:
                print("Failed to load script: {error}".format(error=result[0]))
                return False

        def _create_prompt(self):
            device_type = self._device.type
            type_name = self._target[0]
            target = self._target[1]

            if device_type in ('local', 'remote'):
                if self._target[0] == 'name':
                    type_name = "ProcName"
                elif self._target[0] == 'pid':
                    type_name = "PID"
                prompt_string = "%s::%s::%s" % (device_type.title(), type_name, target)
            else:
                prompt_string = "%s::%s::%s" % ("USB", self._device.name, target)

            return prompt_string

        def _evaluate(self, text):
            self._reactor.schedule(lambda: self._script.post_message({'name': '.evaluate', 'payload': {'expression': text}}))
            with self._response_cond:
                while self._response_data is None:
                    if not self._reactor.is_running():
                        raise frida.InvalidOperationError("Invalid operation while stopping")
                    self._response_cond.wait(0.5)
                response = self._response_data
                self._response_data = None
            stanza, data = response
            if data is not None:
                return ('binary', data)
            elif stanza['name'] == '+result':
                payload = stanza['payload']
                return (payload['type'], payload.get('value', None))
            else:
                assert stanza['name'] == '+error'
                raise Exception(stanza['payload'])

        def _process_message(self, message, data):
            if message['type'] == 'send':
                stanza = message['payload']
                with self._response_cond:
                    self._response_data = (stanza, data)
                    self._response_cond.notify()
            else:
                print("message:", message, "data:", data)

        def _create_repl_script(self):
            user_script = ""

            if self._user_script is not None:
                with open(self._user_script, 'rb') as f:
                    user_script = f.read().rstrip("\r\n") + "\n\n// Frida REPL script:\n"

            return user_script + """\

(function () {
    "use strict";

    function onEvaluate(expression) {
        try {
            let result = (1, eval)(expression);

            if (isByteArray(result)) {
                send({
                    name: '+result',
                    payload: {
                        type: 'binary'
                    }
                }, result);
            } else {
                const type = (result === null) ? 'null' : typeof result;
                send({
                    name: '+result',
                    payload: {
                        type: type,
                        value: result
                    }
                });
            }
        } catch (e) {
            send({
                name: '+error',
                payload: {
                    name: e.name,
                    message: e.message
                }
            });
        }
    }

    function isByteArray(v) {
        if (!v || typeof v !== 'object' || !('length' in v) || typeof v.length !== 'number' || v.length < 1)
            return false;
        if (v instanceof Array) // Object returned by Memory.readByteArray() isn't an Array
            return false;
        for (var i = 0; i !== v.length; i++) {
            if (typeof v[i] !== 'number')
                return false;
        }
        return true;
    }

    const onStanza = function (stanza) {
        switch (stanza.name) {
            case '.evaluate':
                onEvaluate.call(this, stanza.payload.expression);
                break;
        }

        recv(onStanza);
    }.bind(this);
    recv(onStanza);
}).call(this);
"""

    class FridaCompleter(Completer):
        def __init__(self, repl):
            self._repl = repl
            self._lexer = JavascriptLexer()

        def get_completions(self, document, complete_event):
            prefix = document.text_before_cursor
            tokens = list(self._lexer.get_tokens(prefix))[:-1]

            word_tokens = 0
            before_dot = ''
            after_dot = ''
            encountered_dot = False
            for t in tokens[::-1]:
                if t[0] == Token.Name.Other:
                    before_dot = t[1] + before_dot
                    word_tokens += 1
                elif t[0] == Token.Punctuation and t[1] == '.':
                    before_dot = '.' + before_dot
                    if not encountered_dot:
                        encountered_dot = True
                        after_dot = before_dot[1:]
                        before_dot = ''
                    word_tokens += 1
                else:
                    break

            try:
                if encountered_dot:
                    for key in self._repl._evaluate("Object.keys(" + before_dot +
                               ").concat(Object.getOwnPropertyNames(Object.getPrototypeOf(" + before_dot + ")))")[1]:
                        if key.startswith(after_dot):
                            yield Completion(key, -len(after_dot))
                else:
                    for key in self._repl._evaluate("Object.keys(this)")[1]:
                        if not key.startswith(before_dot) or (key.startswith('_') and before_dot == ''):
                            continue
                        yield Completion(key, -len(before_dot))
            except Exception:
                pass

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
            lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
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
