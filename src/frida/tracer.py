from frida.core import ModuleFunction
import os
import fnmatch
import sys


class TracerProfileBuilder(object):
    def __init__(self):
        self._spec = []

    def include_modules(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(("include", "module", m))
        return self

    def exclude_modules(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(("exclude", "module", m))
        return self

    def include(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(("include", "function", f))
        return self

    def exclude(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(("exclude", "function", f))
        return self

    def build(self):
        return TracerProfile(self._spec)

class TracerProfile(object):
    def __init__(self, spec):
        self._spec = spec

    def resolve(self, process):
        all_modules = process.enumerate_modules()
        working_set = set()
        for (operation, scope, glob) in self._spec:
            if scope == "module":
                if operation == "include":
                    working_set = working_set.union(self._include_module(glob, all_modules))
                elif operation == "exclude":
                    working_set = self._exclude_module(glob, working_set)
            elif scope == "function":
                if operation == "include":
                    working_set = working_set.union(self._include_function(glob, all_modules))
                elif operation == "exclude":
                    working_set = self._exclude_function(glob, working_set)
        return list(working_set)

    def _include_module(self, glob, all_modules):
        r = []
        for module in all_modules:
            if fnmatch.fnmatchcase(module.name, glob):
                for export in module.enumerate_exports():
                    r.append(export)
        return r

    def _exclude_module(self, glob, working_set):
        r = []
        for export in working_set:
            if not fnmatch.fnmatchcase(export.module.name, glob):
                r.append(export)
        return set(r)

    def _include_function(self, glob, all_modules):
        r = []
        for module in all_modules:
            for export in module.enumerate_exports():
                if fnmatch.fnmatchcase(export.name, glob):
                    r.append(export)
        return r

    def _exclude_function(self, glob, working_set):
        r = []
        for export in working_set:
            if not fnmatch.fnmatchcase(export.name, glob):
                r.append(export)
        return set(r)

class Tracer(object):
    def __init__(self, reactor, repository, profile):
        self._reactor = reactor
        self._repository = repository
        self._profile = profile
        self._script = None

    def start_trace(self, process, ui):
        def on_create(*args):
            ui.on_trace_handler_create(*args)
        self._repository.on_create(on_create)

        def on_load(*args):
            ui.on_trace_handler_load(*args)
        self._repository.on_load(on_load)

        def on_message(message, data):
            self._reactor.schedule(lambda: self._process_message(message, data, ui))

        ui.on_trace_progress('resolve')
        working_set = self._profile.resolve(process)
        source = self._create_trace_script()
        ui.on_trace_progress('upload')
        self._script = process.session.create_script(source)
        self._script.on("message", on_message)
        self._script.load()
        for chunk in [working_set[i:i+1000] for i in range(0, len(working_set), 1000)]:
            targets = [{
                    'name': export.name,
                    'absolute_address': hex(export.absolute_address),
                    'handler': self._repository.ensure_handler(export)
                } for export in chunk]
            self._script.post_message({
                'to': "/targets",
                'name': '+add',
                'payload': {
                    'items': targets
                }
            })
        ui.on_trace_progress('ready')

        return working_set

    def stop(self):
        if self._script is not None:
            try:
                self._script.unload()
            except:
                pass
            self._script = None

    def _create_trace_script(self):
        return """
var started = new Date();
var pending = [];
var timer = null;
function log(message) {
    send([new Date().getTime() - started.getTime(), message]);
}
function processNext() {
    timer = null;

    if (pending.length > 0) {
        var work = pending.shift();
        work();
        scheduleNext();
    }
};
function scheduleNext() {
    if (timer === null) {
        timer = setTimeout(processNext, 0);
    }
};
function onStanza(stanza) {
    if (stanza.to === "/targets") {
        if (stanza.name === '+add') {
            var targets = stanza.payload.items;
            targets.forEach(function (target) {
                pending.push(function () {
                    eval("var handler = " + target.handler);
                    var state = {};
                    Interceptor.attach(ptr(target.absolute_address), {
                        onEnter: function onEnter(args) {
                            handler.onEnter(log, args, state);
                        },
                        onLeave: function onLeave(retval) {
                            handler.onLeave(log, retval, state);
                        }
                    });
                });
            });

            scheduleNext();
        }
    }

    recv(onStanza);
};
recv(onStanza);
"""

    def _process_message(self, message, data, ui):
        if message['type'] == 'send':
            ui.on_trace_events([ message['payload'] ])
        else:
            print(message)

class Repository(object):
    def __init__(self):
        self._on_create_callback = None
        self._on_load_callback = None

    def ensure_handler(self, function):
        raise NotImplementedError("not implemented")

    def on_create(self, callback):
        self._on_create_callback = callback

    def on_load(self, callback):
        self._on_load_callback = callback

    def _notify_create(self, function, handler, source):
        if self._on_create_callback is not None:
            self._on_create_callback(function, handler, source)

    def _notify_load(self, function, handler, source):
        if self._on_load_callback is not None:
            self._on_load_callback(function, handler, source)

    def _create_stub_handler(self, function):
        return """\
/*
 * Auto-generated by Frida — please modify to match the signature of %(name)s.
 * This stub is somewhat dumb. Future verions of Frida could auto-generate
 * based on OS API references, manpages, etc. (Pull-requests appreciated!)
 *
 * For full API reference, see: https://github.com/frida/frida-gum/wiki/Reference:-Script
 */

{
    /**
     * Called synchronously when about to call %(name)s.
     *
     * @this {object} - Object allowing you to store state for use in onLeave.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {array} args - Function arguments represented as an array of NativePointer objects.
     * For example use Memory.readUtf8String(args[0]) if the first argument is a pointer to a C string encoded as UTF-8.
     * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
     * @param {object} state - Object allowing you to keep state across function calls.
     * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
     * However, do not use this to store function arguments across onEnter/onLeave, but instead
     * use "this" which is an object for keeping state local to an invocation.
     */
    onEnter: function onEnter(log, args, state) {
        log("%(name)s()");
    },

    /**
     * Called synchronously when about to return from %(name)s.
     *
     * See onEnter for details.
     *
     * @this {object} - Object allowing you to access state stored in onEnter.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {NativePointer} retval - Return value represented as a NativePointer object.
     * @param {object} state - Object allowing you to keep state across function calls.
     */
    onLeave: function onLeave(log, retval, state) {
    }
}
""" % { 'name': function.name }

class MemoryRepository(Repository):
    def __init__(self):
        super(MemoryRepository, self).__init__()
        self._handlers = {}

    def ensure_handler(self, function):
        handler = self._handlers.get(function)
        if handler is None:
            handler = self._create_stub_handler(function)
            self._handlers[function] = handler
            self._notify_create(function, handler, "memory")
        else:
            self._notify_load(function, handler, "memory")
        return handler

class FileRepository(Repository):
    def __init__(self):
        super(FileRepository, self).__init__()
        self._handlers = {}
        self._repo_dir = os.path.join(os.getcwd(), "__frida_handlers__")

    def ensure_handler(self, function):
        handler = self._handlers.get(function)
        if handler is not None:
            return handler

        handler_files_to_try = []

        if isinstance(function, ModuleFunction):
            module_dir = os.path.join(self._repo_dir, function.module.name)
            module_handler_file = os.path.join(module_dir, function.name + ".js")
            handler_files_to_try.append(module_handler_file)

        any_module_handler_file = os.path.join(self._repo_dir, function.name + ".js")
        handler_files_to_try.append(any_module_handler_file)

        for handler_file in handler_files_to_try:
            if os.path.isfile(handler_file):
                with open(handler_file, 'r') as f:
                    handler = f.read()
                self._notify_load(function, handler, handler_file)
                break

        if handler is None:
            handler = self._create_stub_handler(function)
            handler_file = handler_files_to_try[0]
            handler_dir = os.path.dirname(handler_file)
            if not os.path.isdir(handler_dir):
                os.makedirs(handler_dir)
            with open(handler_file, 'w') as f:
                f.write(handler)
            self._notify_create(function, handler, handler_file)

        self._handlers[function] = handler

        return handler

class UI(object):
    def on_trace_progress(self, operation):
        pass

    def on_trace_events(self, events):
        pass

    def on_trace_handler_create(self, function, handler, source):
        pass

    def on_trace_handler_load(self, function, handler, source):
        pass


def main():
    import colorama
    from colorama import Fore, Back, Style
    import frida
    from frida.core import Reactor
    from optparse import OptionParser
    import sys

    colorama.init(autoreset=True)

    tp = TracerProfileBuilder()
    def process_builder_arg(option, opt_str, value, parser, method, **kwargs):
        method(value)

    usage = "usage: %prog [options] process-name-or-id"
    parser = OptionParser(usage=usage)
    parser.add_option("-I", "--include-module=MODULE", help="include MODULE", metavar="MODULE",
            type='string', action='callback', callback=process_builder_arg, callback_args=(tp.include_modules,))
    parser.add_option("-X", "--exclude-module=MODULE", help="exclude MODULE", metavar="MODULE",
            type='string', action='callback', callback=process_builder_arg, callback_args=(tp.exclude_modules,))
    parser.add_option("-i", "--include=FUNCTION", help="include FUNCTION", metavar="FUNCTION",
            type='string', action='callback', callback=process_builder_arg, callback_args=(tp.include,))
    parser.add_option("-x", "--exclude=FUNCTION", help="exclude FUNCTION", metavar="FUNCTION",
            type='string', action='callback', callback=process_builder_arg, callback_args=(tp.exclude,))
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("process name or id must be specified")
    try:
        target = int(args[0])
    except:
        target = args[0]
    profile = tp.build()

    class Application(UI):
        def __init__(self, target, profile):
            self._target = target
            self._process = None
            self._tracer = None
            self._profile = profile
            self._status_updated = False
            self._exit_status = 0
            self._reactor = Reactor(await_enter)
            self._reactor.schedule(self._start)

        def run(self):
            self._reactor.run()
            self._stop()
            return self._exit_status

        def _start(self):
            try:
                self._update_status("Attaching...")
                self._process = frida.attach(self._target)
            except Exception as e:
                self._update_status("Failed to attach: %s" % e)
                self._exit_status = 1
                self._reactor.schedule(self._stop)
                return
            self._tracer = Tracer(self._reactor, FileRepository(), self._profile)
            targets = self._tracer.start_trace(self._process, self)
            if len(targets) == 1:
                plural = ""
            else:
                plural = "s"
            self._update_status("Started tracing %d function%s. Press ENTER to stop." % (len(targets), plural))

        def _stop(self):
            if self._tracer is not None:
                print("Stopping...")
                self._tracer.stop()
                self._tracer = None
            if self._process is not None:
                self._process.detach()
                self._process = None
            self._reactor.stop()

        def on_trace_progress(self, operation):
            if operation == 'resolve':
                self._update_status("Resolving functions...")
            elif operation == 'upload':
                self._update_status("Uploading data...")
            elif operation == 'ready':
                self._update_status("Ready!")

        def on_trace_events(self, events):
            self._status_updated = False
            for timestamp, message in events:
                print("%6d ms\t%s" % (timestamp, message))

        def on_trace_handler_create(self, function, handler, source):
            print("%s: Auto-generated handler at \"%s\"" % (function, source))

        def on_trace_handler_load(self, function, handler, source):
            print("%s: Loaded handler at \"%s\"" % (function, source))

        def _update_status(self, message):
            if self._status_updated:
                cursor_position = "\033[A"
            else:
                cursor_position = ""
            print("%-80s" % (cursor_position + Style.BRIGHT + message,))
            self._status_updated = True

    def await_enter():
        if sys.version_info[0] >= 3:
            input()
        else:
            raw_input()

    app = Application(target, profile)
    status = app.run()
    frida.shutdown()
    sys.exit(status)


if __name__ == '__main__':
    main()
