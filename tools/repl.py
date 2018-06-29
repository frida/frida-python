# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import signal
import threading

def main():
    import codecs
    from colorama import Fore, Style
    import frida
    from frida.application import ConsoleApplication
    import hashlib
    import json
    import os
    import platform
    from prompt_toolkit.shortcuts import create_prompt_application, create_output, create_eventloop
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.completion import Completion, Completer
    from prompt_toolkit.interface import CommandLineInterface
    from pygments.lexers import JavascriptLexer
    from pygments.token import Token
    import re
    import sys
    try:
        from urllib.request import build_opener
    except:
        from urllib2 import build_opener

    class REPLApplication(ConsoleApplication):
        def __init__(self):
            self._script = None
            self._seqno = 0
            self._ready = threading.Event()
            self._stopping = threading.Event()
            self._errors = 0
            config_dir = self._get_or_create_config_dir()
            self._history = FileHistory(os.path.join(config_dir, 'history'))
            self._completer = FridaCompleter(self)
            self._cli = None
            self._last_change_id = 0
            self._script_monitor = None
            self._monitored_file = None

            super(REPLApplication, self).__init__(self._process_input, self._on_stop)

            self._dumb_stdin_reader = None if self._have_terminal else DumbStdinReader(valid_until=self._stopping)

        def _add_options(self, parser):
            parser.add_option("-l", "--load", help="load SCRIPT", metavar="SCRIPT",
                type='string', action='store', dest="user_script", default=None)
            parser.add_option("-c", "--codeshare", help="load CODESHARE_URI", metavar="CODESHARE_URI",
                type='string', action='store', dest="codeshare_uri", default=None)
            parser.add_option("-e", "--eval", help="evaluate CODE", metavar="CODE",
                type='string', action='append', dest="eval_items", default=None)
            parser.add_option("-q", help="quiet mode (no prompt) and quit after -l and -e",
                action='store_true', dest="quiet", default=False)
            parser.add_option("--no-pause", help="automatically start main thread after startup",
                action='store_true', dest="no_pause", default=False)
            parser.add_option("-o", "--output", help="output to log file", dest="logfile", default=None)

        def _initialize(self, parser, options, args):
            self._user_script = options.user_script
            self._codeshare_uri = options.codeshare_uri
            self._codeshare_script = None
            self._pending_eval = options.eval_items
            self._quiet = options.quiet
            self._no_pause = options.no_pause
            if options.logfile is not None:
                try:
                    self._logfile = open(options.logfile, 'w')
                except Exception as e:
                    self._update_status('Failed to open logfile "%s"' % options.logfile)
                    self._exit(1)
            else:
                self._logfile = None

        def _log(self, level, text):
            ConsoleApplication._log(self, level, text)
            if self._logfile is not None:
                self._logfile.write(text + "\n")

        def _usage(self):
            return "usage: %prog [options] target"

        def _needs_target(self):
            return True

        def _start(self):
            self._prompt_string = self._create_prompt()

            if self._codeshare_uri is not None:
                self._codeshare_script = self._load_codeshare_script(self._codeshare_uri)
                if self._codeshare_script is None:
                    self._print("Exiting!")
                    self._exit(1)
                    return

            try:
                self._load_script()
            except Exception as e:
                self._update_status("Failed to load script: {error}".format(error=e))
                self._exit(1)
                return

            if self._spawned_argv is not None:
                if self._no_pause:
                    self._update_status("Spawned `{command}`. Resuming main thread!".format(command=" ".join(self._spawned_argv)))
                    self._do_magic("resume")
                else:
                    self._update_status("Spawned `{command}`. Use %resume to let the main thread start executing!".format(command=" ".join(self._spawned_argv)))
            else:
                self._clear_status()
            self._ready.set()

        def _on_stop(self):
            def set_return():
                raise EOFError()

            self._stopping.set()

            if self._cli is not None:
                try:
                    self._cli.eventloop.call_from_executor(set_return)
                except Exception:
                    pass

        def _stop(self):
            self._unload_script()
            self._unmonitor_script()

            self._print("\nThank you for using Frida!")

        def _load_script(self):
            self._monitor_script()
            self._seqno += 1
            script = self._session.create_script(name="repl%d" % self._seqno, source=self._create_repl_script())
            script.set_log_handler(self._log)
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

        def _monitor_script(self):
            if self._monitored_file == self._user_script:
                return

            self._unmonitor_script()

            if self._user_script is not None:
                monitor = frida.FileMonitor(self._user_script)
                monitor.on('change', self._on_change)
                monitor.enable()
                self._script_monitor = monitor
            self._monitored_file = self._user_script

        def _unmonitor_script(self):
            if self._script_monitor is None:
                return

            self._script_monitor.disable()
            self._script_monitor = None

        def _process_input(self, reactor):
            if not self._quiet:
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

                    prompt = "[%s]" % self._prompt_string + "-> " if len(expression) == 0 else "... "

                    pending_eval = self._pending_eval
                    if pending_eval is not None:
                        if len(pending_eval) > 0:
                            expression = pending_eval.pop(0)
                            if not self._quiet:
                                self._print(prompt + expression)
                        else:
                            self._pending_eval = None
                    else:
                        if self._quiet:
                            self._exit_status = 0 if self._errors == 0 else 1
                            return

                        try:
                            if self._have_terminal:
                                # We create the prompt manually instead of using get_input,
                                # so we can use the cli in the _on_stop method
                                eventloop = create_eventloop()

                                self._cli = CommandLineInterface(
                                    application=create_prompt_application(prompt, history=self._history, completer=self._completer, lexer=JavascriptLexer),
                                    eventloop=eventloop,
                                    output=create_output())

                                try:
                                    line = None

                                    document = self._cli.run()

                                    if document:
                                        line = document.text
                                finally:
                                    eventloop.close()
                            else:
                                line = self._dumb_stdin_reader.read_line(prompt)
                                self._print(line)
                        except EOFError:
                            if not self._have_terminal:
                                while not self._stopping.wait(1):
                                    pass
                            return
                        except KeyboardInterrupt:
                            line = ""
                            if not self._have_terminal:
                                sys.stdout.write("\n" + prompt)
                            continue
                        if len(line.strip()) > 0:
                            if len(expression) > 0:
                                expression += "\n"
                            expression += line.rstrip("\\")

                if expression.endswith("?"):
                    try:
                        self._print_help(expression)
                    except JavaScriptError as e:
                        error = e.error
                        self._print(Fore.RED + Style.BRIGHT + error['name'] + Style.RESET_ALL + ": " + error['message'])
                    except frida.InvalidOperationError:
                        return
                elif expression.startswith("%"):
                    self._do_magic(expression[1:].rstrip())
                elif expression in ("exit", "quit", "q"):
                    return
                elif expression == "help":
                    self._print("Help: #TODO :)")
                else:
                    if not self._eval_and_print(expression):
                        self._errors += 1

        def _eval_and_print(self, expression):
            success = False
            try:
                (t, value) = self._evaluate(expression)
                if t in ('function', 'undefined', 'null'):
                    output = t
                elif t == 'binary':
                    output = hexdump(value).rstrip("\n")
                else:
                    output = json.dumps(value, sort_keys=True, indent=4, separators=(",", ": "))
                success = True
            except JavaScriptError as e:
                error = e.error
                output = Fore.RED + Style.BRIGHT + error['name'] + Style.RESET_ALL + ": " + error['message']
            except frida.InvalidOperationError:
                return success
            self._print(output)
            return success

        def _print_startup_message(self):
            self._print("""\
     ____
    / _  |   Frida {version} - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/""".format(version=frida.__version__))

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

            self._print(help_text)

        # Negative means at least abs(val) - 1
        _magic_command_args = {
            'resume': 0,
            'load': 1,
            'reload': 0,
            'unload': 0,
            'time': -2 # At least 1 arg
        }

        def _do_magic(self, statement):
            tokens = statement.split(" ")
            command = tokens[0]
            args = tokens[1:]

            required_args = self._magic_command_args.get(command)

            if required_args == None:
                self._print("Unknown command: {}".format(command))
                self._print("Valid commands: {}".format(", ".join(self._magic_command_args.keys())))
                return

            atleast_args = False
            if required_args < 0:
                atleast_args = True
                required_args = abs(required_args) - 1

            if (not atleast_args and len(args) != required_args) or \
               (atleast_args and len(args) < required_args):
                self._print("{cmd} command expects {atleast}{n} argument{s}".format(
                    cmd=command, atleast='atleast ' if atleast_args else '', n=required_args, s='' if required_args == 1 else ' '))
                return

            if command == 'resume':
                self._reactor.schedule(lambda: self._resume())
            elif command == 'load':
                old_user_script = self._user_script
                self._user_script = os.path.abspath(args[0])
                if not self._reload():
                    self._user_script = old_user_script
            elif command == 'reload':
                self._reload()
            elif command == 'unload':
                self._user_script = None
                self._reload()
            elif command == 'time':
                self._eval_and_print('''
                    (function () {
                        var _startTime = Date.now();
                        var _result = eval({expression});
                        var _endTime = Date.now();
                        console.log('Time: ' + (_endTime - _startTime).toLocaleString() + ' ms.');
                        return _result;
                    })();'''.format(expression=json.dumps(' '.join(args))))

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
                self._print("Failed to load script: {error}".format(error=result[0]))
                return False

        def _create_prompt(self):
            device_type = self._device.type
            type_name = self._target[0]
            if type_name == 'pid':
                if self._target[1] == 0:
                    target = 'SystemSession'
                else:
                    target = 'PID::%u' % self._target[1]
            elif type_name == 'file':
                target = os.path.basename(self._target[1][0])
            else:
                target = self._target[1]

            if device_type in ('local', 'remote'):
                prompt_string = "%s::%s" % (device_type.title(), target)
            else:
                prompt_string = "%s::%s" % (self._device.name, target)

            return prompt_string

        def _evaluate(self, text):
            result = self._script.exports.evaluate(text)
            if is_byte_array(result):
                return ('binary', result)
            elif isinstance(result, dict):
                return ('binary', bytes())
            elif result[0] == 'error':
                raise JavaScriptError(result[1])
            else:
                return result

        def _process_message(self, message, data):
            message_type = message['type']
            if message_type == 'error':
                text = message.get('stack', message['description'])
                self._log('error', text)
                self._errors += 1
            else:
                self._print("message:", message, "data:", data)

        def _on_change(self, changed_file, other_file, event_type):
            if event_type == 'changes-done-hint':
                return
            self._last_change_id += 1
            change_id = self._last_change_id
            self._reactor.schedule(lambda: self._process_change(change_id), delay=0.05)

        def _process_change(self, change_id):
            if change_id != self._last_change_id:
                return
            try:
                self._load_script()
            except Exception as e:
                self._print("Failed to load script: {error}".format(error=e))

        def _create_repl_script(self):
            user_script = ""

            if self._codeshare_script is not None:
                user_script = self._codeshare_script

            if self._user_script is not None:
                with codecs.open(self._user_script, 'rb', 'utf-8') as f:
                    user_script += f.read().rstrip("\r\n") + "\n\n// Frida REPL script:\n"

            return user_script + """\

rpc.exports.evaluate = function (expression) {
    try {
        var result = (1, eval)(expression);
        if (result instanceof ArrayBuffer) {
            return result;
        } else {
            var type = (result === null) ? 'null' : typeof result;
            return [type, result];
        }
    } catch (e) {
        return ['error', {
            name: e.name,
            message: e.message,
            stack: e.stack
        }];
    }
};
"""

        def _load_codeshare_script(self, uri):
            trust_store = self._get_or_create_truststore()

            project_url = "https://codeshare.frida.re/api/project/{}/".format(uri)
            response_json = None
            try:
                request = build_opener()
                request.addheaders = [('User-Agent', 'Frida v{} | {}'.format(frida.__version__, platform.platform()))]
                response = request.open(project_url)
                response_content = response.read().decode('utf-8')
                response_json = json.loads(response_content)
            except Exception as e:
                self._print("Got an unhandled exception while trying to retrieve {} - {}".format(uri, e))
                return None

            trusted_signature = trust_store.get(uri, "")
            fingerprint = hashlib.sha256(response_json['source'].encode('utf-8')).hexdigest()
            if fingerprint == trusted_signature:
                return response_json['source']

            self._print("""Hello! This is the first time you're running this particular snippet, or the snippet's source code has changed.

Project Name: {project_name}
Author: {author}
Slug: {slug}
Fingerprint: {fingerprint}
URL: {url}
            """.format(
                project_name=response_json['project_name'],
                author="@" + uri.split('/')[0],
                slug=uri,
                fingerprint=fingerprint,
                url="https://codeshare.frida.re/@{}".format(uri)
            ))

            while True:
                prompt_string = "Are you sure you'd like to trust this project? [y/N] "
                response = get_input(prompt_string)

                if response.lower() in ('n', 'no') or response == '':
                    return None

                if response.lower() in ('y', 'yes'):
                    self._print("Adding fingerprint {} to the trust store! You won't be prompted again unless the code changes.".format(fingerprint))
                    script = response_json['source']
                    self._update_truststore({
                        uri: fingerprint
                    })
                    return script

        def _get_or_create_config_dir(self):
            config_dir = os.path.join(os.path.expanduser('~'), '.frida')
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            return config_dir

        def _update_truststore(self, record):
            trust_store = self._get_or_create_truststore()
            trust_store.update(record)

            config_dir = self._get_or_create_config_dir()
            codeshare_trust_store = os.path.join(config_dir, "codeshare-truststore.json")

            with open(codeshare_trust_store, 'w') as f:
                f.write(json.dumps(trust_store))

        def _get_or_create_truststore(self):
            config_dir = self._get_or_create_config_dir()

            codeshare_trust_store = os.path.join(config_dir, "codeshare-truststore.json")

            if os.path.exists(codeshare_trust_store):
                try:
                    with open(codeshare_trust_store) as f:
                        trust_store = json.load(f)
                except Exception as e:
                    self._print("Unable to load the codeshare truststore ({}), defaulting to an empty truststore. You will be prompted every time you want to run a script!".format(e))
                    trust_store = {}
            else:
                with open(codeshare_trust_store, 'w') as f:
                    f.write(json.dumps({}))
                trust_store = {}

            return trust_store

    class FridaCompleter(Completer):
        def __init__(self, repl):
            self._repl = repl
            self._lexer = JavascriptLexer()

        def get_completions(self, document, complete_event):
            prefix = document.text_before_cursor

            magic = len(prefix) > 0 and prefix[0] == '%' and not any(map(lambda c: c.isspace(), prefix))

            tokens = list(self._lexer.get_tokens(prefix))[:-1]

            # 0.toString() is invalid syntax,
            # but pygments doesn't seem to know that
            for i in range(len(tokens) - 1):
                if tokens[i][0] == Token.Literal.Number.Integer \
                    and tokens[i + 1][0] == Token.Punctuation and tokens[i + 1][1] == '.':
                    tokens[i] = (Token.Literal.Number.Float, tokens[i][1] + tokens[i + 1][1])
                    del tokens[i + 1]

            before_dot = ''
            after_dot = ''
            encountered_dot = False
            for t in tokens[::-1]:
                if t[0] in Token.Name.subtypes:
                    before_dot = t[1] + before_dot
                elif t[0] == Token.Punctuation and t[1] == '.':
                    before_dot = '.' + before_dot
                    if not encountered_dot:
                        encountered_dot = True
                        after_dot = before_dot[1:]
                        before_dot = ''
                else:
                    if encountered_dot:
                        # The value/contents of the string, number or array doesn't matter,
                        # so we just use the simplest value with that type
                        if t[0] in Token.Literal.String.subtypes:
                            before_dot = '""' + before_dot
                        elif t[0] in Token.Literal.Number.subtypes:
                            before_dot = '0.0' + before_dot
                        elif t[0] == Token.Punctuation and t[1] == ']':
                            before_dot = '[]' + before_dot

                    break

            try:
                if encountered_dot:
                    for key in self._get_keys("""try {
                                    (function (o) {
                                        "use strict";
                                        var k = Object.getOwnPropertyNames(o);
                                        if (o !== null && o !== undefined) {
                                            var p;
                                            if (typeof o !== 'object')
                                                p = o.__proto__;
                                            else
                                                p = Object.getPrototypeOf(o);
                                            if (p !== null && p !== undefined)
                                                k = k.concat(Object.getOwnPropertyNames(p));
                                        }
                                        return k;
                                    })(""" + before_dot + """);
                                } catch (e) {
                                    [];
                                }"""):
                        if self._pattern_matches(after_dot, key):
                            yield Completion(key, -len(after_dot))
                else:
                    if magic:
                        keys = self._repl._magic_command_args.keys()
                    else:
                        keys = self._get_keys("Object.getOwnPropertyNames(this)")
                    for key in keys:
                        if not self._pattern_matches(before_dot, key) or (key.startswith('_') and before_dot == ''):
                            continue
                        yield Completion(key, -len(before_dot))
            except frida.InvalidOperationError:
                pass
            except Exception as e:
                self._repl._print(e)

        def _get_keys(self, code):
            return sorted(
                    filter(self._is_valid_name,
                     set(self._repl._evaluate(code)[1])))

        def _is_valid_name(self, name):
            tokens = list(self._lexer.get_tokens(name))
            return len(tokens) == 2 and tokens[0][0] in Token.Name.subtypes

        def _pattern_matches(self, pattern, text):
            return re.search(re.escape(pattern), text, re.IGNORECASE) != None

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

    def is_byte_array(value):
        if sys.version_info[0] >= 3:
            return isinstance(value, bytes)
        else:
            return isinstance(value, str)

    if sys.version_info[0] >= 3:
        iterbytes = lambda x: iter(x)
    else:
        def iterbytes(data):
            return (ord(char) for char in data)

    app = REPLApplication()
    app.run()

class JavaScriptError(Exception):
    def __init__(self, error):
        super(JavaScriptError, self).__init__(error['message'])

        self.error = error

class DumbStdinReader(object):
    def __init__(self, valid_until):
        self._valid_until = valid_until

        self._prompt = None
        self._result = None
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

        worker = threading.Thread(target=self._process_requests, name="stdin-reader")
        worker.daemon = True
        worker.start()

        signal.signal(signal.SIGINT, lambda n, f: self._cancel_line())

    def read_line(self, prompt_string):
        with self._lock:
            self._prompt = prompt_string
            self._cond.notify()

        with self._lock:
            while self._result is None:
                if self._valid_until.is_set():
                    raise EOFError()
                self._cond.wait(1)
            line, error = self._result
            self._result = None

        if error is not None:
            raise error

        return line

    def _process_requests(self):
        error = None
        while error is None:
            with self._lock:
                while self._prompt is None:
                    self._cond.wait()
                prompt = self._prompt

            try:
                line = get_input(prompt)
            except Exception as e:
                line = None
                error = e

            with self._lock:
                self._prompt = None
                self._result = (line, error)
                self._cond.notify()

    def _cancel_line(self):
        with self._lock:
            self._prompt = None
            self._result = (None, KeyboardInterrupt())
            self._cond.notify()

try:
    input_impl = raw_input
except NameError:
    input_impl = input

def get_input(prompt_string):
    return input_impl(prompt_string)


if __name__ == '__main__':
    main()
