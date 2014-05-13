# -*- coding: utf-8 -*-

import os
import fnmatch
import time
import re
import binascii

from frida.core import ModuleFunction


class TracerProfileBuilder(object):
    _RE_REL_ADDRESS = re.compile("(?P<module>[^\s!]+)!(?P<offset>(0x)?[0-9a-fA-F]+)")

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

    def include_rel_address(self, *address_rel_offsets):
        for f in address_rel_offsets:
            m = TracerProfileBuilder._RE_REL_ADDRESS.search(f)
            if m is None:
                continue
            self._spec.append(("include", "rel_address", 
                               {'module':m.group('module'), 
                                'offset':int(m.group('offset'), base=16)}))

    def build(self):
        return TracerProfile(self._spec)

class TracerProfile(object):
    def __init__(self, spec):
        self._spec = spec

    def resolve(self, process):
        all_modules = process.enumerate_modules()
        working_set = set()
        for (operation, scope, param) in self._spec:
            if scope == "module":
                if operation == "include":
                    working_set = working_set.union(self._include_module(param, all_modules))
                elif operation == "exclude":
                    working_set = self._exclude_module(param, working_set)
            elif scope == "function":
                if operation == "include":
                    working_set = working_set.union(self._include_function(param, all_modules))
                elif operation == "exclude":
                    working_set = self._exclude_function(param, working_set)
            elif scope == 'rel_address':
                if operation == "include":
                    abs_address = process.find_base_address(param['module']) + param['offset']
                    working_set.add(process.ensure_function(abs_address))
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

        def on_update(function, handler, source):
            self._script.post_message({
                'to': "/targets",
                'name': '+update',
                'payload': {
                    'items': [{
                        'absolute_address': hex(function.absolute_address),
                        'handler': handler
                    }]
                }
            })
        self._repository.on_update(on_update)

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
                    'absolute_address': hex(function.absolute_address),
                    'handler': self._repository.ensure_handler(function)
                } for function in chunk]
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
        return """\
var started = new Date();
var pending = [];
var timer = null;
var handlers = {};
function onStanza(stanza) {
    if (stanza.to === "/targets") {
        if (stanza.name === '+add') {
            add(stanza.payload.items);
        } else if (stanza.name === '+update') {
            update(stanza.payload.items);
        }
    }

    recv(onStanza);
}
function add(targets) {
    targets.forEach(function (target) {
        var targetAddress = target.absolute_address;
        eval("var handler = " + target.handler);
        target = null;

        var h = [handler];
        handlers[targetAddress] = h;
        function log(message) {
            send({
                from: "/events",
                name: '+add',
                payload: {
                    items: [[new Date().getTime() - started.getTime(), targetAddress, message]]
                }
            });
        }
        var state = {};

        pending.push(function attachToTarget() {
            Interceptor.attach(ptr(targetAddress), {
                onEnter: function onEnter(args) {
                    h[0].onEnter(log, args, state);
                },
                onLeave: function onLeave(retval) {
                    h[0].onLeave(log, retval, state);
                }
            });
        });
    });

    scheduleNext();
}
function update(targets) {
    targets.forEach(function (target) {
        eval("var handler = " + target.handler);
        handlers[target.absolute_address][0] = handler;
    });
}
function scheduleNext() {
    if (timer === null) {
        timer = setTimeout(processNext, 0);
    }
}
function processNext() {
    timer = null;

    if (pending.length > 0) {
        var work = pending.shift();
        work();
        scheduleNext();
    }
}
recv(onStanza);
"""

    def _process_message(self, message, data, ui):
        if message['type'] == 'send':
            stanza = message['payload']
            if stanza['from'] == "/events":
                if stanza['name'] == '+add':
                    events = [(timestamp, int(target_address.rstrip("L"), 16), message) for timestamp, target_address, message in stanza['payload']['items']]

                    ui.on_trace_events(events)

                    target_addresses = set([target_address for timestamp, target_address, message in events])
                    for target_address in target_addresses:
                        self._repository.sync_handler(target_address)
                else:
                    print(stanza)
            else:
                print(stanza)
        else:
            print(message)

class Repository(object):
    def __init__(self):
        self._on_create_callback = None
        self._on_load_callback = None
        self._on_update_callback = None

    def ensure_handler(self, function):
        raise NotImplementedError("not implemented")

    def sync_handler(self, function_address):
        pass

    def on_create(self, callback):
        self._on_create_callback = callback

    def on_load(self, callback):
        self._on_load_callback = callback

    def on_update(self, callback):
        self._on_update_callback = callback

    def _notify_create(self, function, handler, source):
        if self._on_create_callback is not None:
            self._on_create_callback(function, handler, source)

    def _notify_load(self, function, handler, source):
        if self._on_load_callback is not None:
            self._on_load_callback(function, handler, source)

    def _notify_update(self, function, handler, source):
        if self._on_update_callback is not None:
            self._on_update_callback(function, handler, source)

    def _create_stub_handler(self, function):
        return """\
/*
 * Auto-generated by Frida. Please modify to match the signature of %(name)s.
 * This stub is somewhat dumb. Future verions of Frida could auto-generate
 * based on OS API references, manpages, etc. (Pull-requests appreciated!)
 *
 * For full API reference, see: http://www.frida.re/docs/javascript-api/
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
        self._repo_dir = os.path.join(os.getcwd(), "__handlers__")

    def ensure_handler(self, function):
        entry = self._handlers.get(function.absolute_address)
        if entry is not None:
            (function, handler, handler_file, handler_mtime, last_sync) = entry
            return handler

        handler = None
        handler_files_to_try = []

        if isinstance(function, ModuleFunction):
            module_dir = os.path.join(self._repo_dir, to_filename(function.module.name))
            module_handler_file = os.path.join(module_dir, to_handler_filename(function.name))
            handler_files_to_try.append(module_handler_file)

        any_module_handler_file = os.path.join(self._repo_dir, to_handler_filename(function.name))
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

        handler_mtime = os.stat(handler_file).st_mtime
        self._handlers[function.absolute_address] = (function, handler, handler_file, handler_mtime, time.time())

        return handler

    def sync_handler(self, function_address):
        (function, handler, handler_file, handler_mtime, last_sync) = self._handlers[function_address]
        delta = time.time() - last_sync
        if delta >= 1.0:
            changed = False

            try:
                new_mtime = os.stat(handler_file).st_mtime
                if new_mtime != handler_mtime:
                    with open(handler_file, 'r') as f:
                        new_handler = f.read()
                    changed = new_handler != handler
                    handler = new_handler
                    handler_mtime = new_mtime
            except:
                pass

            self._handlers[function_address] = (function, handler, handler_file, handler_mtime, time.time())

            if changed:
                self._notify_update(function, handler, handler_file)

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
    from frida.application import ConsoleApplication

    class TracerApplication(ConsoleApplication, UI):
        def _add_options(self, parser):
            pb = TracerProfileBuilder()
            def process_builder_arg(option, opt_str, value, parser, method, **kwargs):
                method(value)
            parser.add_option("-I", "--include-module", help="include MODULE", metavar="MODULE",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_modules,))
            parser.add_option("-X", "--exclude-module", help="exclude MODULE", metavar="MODULE",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.exclude_modules,))
            parser.add_option("-i", "--include", help="include FUNCTION", metavar="FUNCTION",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include,))
            parser.add_option("-x", "--exclude", help="exclude FUNCTION", metavar="FUNCTION",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.exclude,))
            parser.add_option("-a", "--add", help="add MODULE!OFFSET", metavar="MODULE!OFFSET",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_rel_address,))
            self._profile_builder = pb

        def _usage(self):
            return "usage: %prog [options] process-name-or-id"

        def _initialize(self, parser, options, args):
            self._tracer = None
            self._profile = self._profile_builder.build()

        def _target_specifier(self, parser, options, args):
            if len(args) != 1:
                parser.error("process name or id must be specified")
            return args[0]

        def _start(self):
            self._tracer = Tracer(self._reactor, FileRepository(), self._profile)
            targets = self._tracer.start_trace(self._process, self)
            if len(targets) == 1:
                plural = ""
            else:
                plural = "s"
            self._update_status("Started tracing %d function%s. Press ENTER to stop." % (len(targets), plural))

        def _stop(self):
            print("Stopping...")
            self._tracer.stop()
            self._tracer = None

        def on_trace_progress(self, operation):
            if operation == 'resolve':
                self._update_status("Resolving functions...")
            elif operation == 'upload':
                self._update_status("Uploading data...")
            elif operation == 'ready':
                self._update_status("Ready!")

        def on_trace_events(self, events):
            self._status_updated = False
            for timestamp, target_address, message in events:
                print("%6d ms\t%s" % (timestamp, message))

        def on_trace_handler_create(self, function, handler, source):
            print("%s: Auto-generated handler at \"%s\"" % (function, source))

        def on_trace_handler_load(self, function, handler, source):
            print("%s: Loaded handler at \"%s\"" % (function, source))

    app = TracerApplication()
    app.run()

def to_filename(name):
    result = ""
    for c in name:
        if c.isalnum() or c == ".":
            result += c
        else:
            result += "_"
    return result

def to_handler_filename(name):
    full_filename = to_filename(name)
    if len(full_filename) <= 41:
        return full_filename + ".js"
    crc = binascii.crc32(full_filename.encode())
    return full_filename[0:32] + "_%08x.js" % crc

if __name__ == '__main__':
    main()
