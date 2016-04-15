# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import binascii
import codecs
import os
import platform
import re
import subprocess
import threading
import time

from frida import FileMonitor
from frida.core import Function, Module, ModuleFunction, ObjCMethod


class TracerProfileBuilder(object):
    _RE_REL_ADDRESS = re.compile("(?P<module>[^\s!]+)!(?P<offset>(0x)?[0-9a-fA-F]+)")

    def __init__(self):
        self._spec = []

    def include_modules(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('include', 'module', m))
        return self

    def exclude_modules(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('exclude', 'module', m))
        return self

    def include(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('include', 'function', f))
        return self

    def exclude(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('exclude', 'function', f))
        return self

    def include_relative_address(self, *address_rel_offsets):
        for f in address_rel_offsets:
            m = TracerProfileBuilder._RE_REL_ADDRESS.search(f)
            if m is None:
                continue
            self._spec.append(('include', 'relative_function', {
                'module': m.group('module'),
                'offset': int(m.group('offset'), base=16)
            }))
        return self

    def include_imports(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('include', 'imports', m))
        return self

    def include_objc_method(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('include', 'objc_method', f))
        return self

    def build(self):
        return TracerProfile(self._spec)

class TracerProfile(object):
    _BLACKLIST = set([
        "libSystem.B.dylib!dyld_stub_binder"
    ])

    def __init__(self, spec):
        self._spec = spec

    def resolve(self, session, log_handler=None):
        script = session.create_script(name="profile-resolver", source=self._create_resolver_script())
        script.set_log_handler(log_handler)
        def on_message(message, data):
            print(message)
        script.on('message', on_message)
        script.load()
        try:
            data = script.exports.resolve(self._spec)
        finally:
            script.unload()

        modules = {}
        for module_id, m in data['modules'].items():
            module = Module(m['name'], int(m['base'], 16), m['size'], m['path'], session)
            modules[int(module_id)] = module

        working_set = []
        for target in data['targets']:
            objc = target.get('objc')
            if objc is not None:
                method = objc['method']
                of = ObjCMethod(method['type'], objc['className'], method['name'], int(target['address'], 16))
                working_set.append(of)
            else:
                name = target['name']
                absolute_address = int(target['address'], 16)
                module_id = target.get('module')
                if module_id is not None:
                    module = modules[module_id]
                    relative_address = absolute_address - module.base_address
                    exported = not target.get('private', False)
                    mf = ModuleFunction(module, name, relative_address, exported)
                    if not self._is_blacklisted(mf):
                        working_set.append(mf)
                else:
                    f = Function(name, absolute_address)
                    working_set.append(f)
        return working_set

    def _is_blacklisted(self, module_function):
        key = module_function.module.name + "!" + module_function.name
        return key in TracerProfile._BLACKLIST

    def _create_resolver_script(self):
        return r""""use strict";

rpc.exports = {
    resolve: function (spec) {
        var workingSet = spec.reduce(function (workingSet, item) {
            var operation = item[0];
            var scope = item[1];
            var param = item[2];
            switch (scope) {
                case 'module':
                    if (operation === 'include')
                        workingSet = includeModule(param, workingSet);
                    else if (operation === 'exclude')
                        workingSet = excludeModule(param, workingSet);
                    break;
                case 'function':
                    if (operation === 'include')
                        workingSet = includeFunction(param, workingSet);
                    else if (operation === 'exclude')
                        workingSet = excludeFunction(param, workingSet);
                    break;
                case 'relative_function':
                    if (operation === 'include')
                        workingSet = includeRelativeFunction(param, workingSet);
                    break;
                case 'imports':
                    if (operation === 'include')
                        workingSet = includeImports(param, workingSet);
                    break;
                case 'objc_method':
                    if (operation === 'include')
                        workingSet = includeObjCMethod(param, workingSet);
                    break;
            }
            return workingSet;
        }, {});

        var modules = {};
        var targets = [];
        for (var address in workingSet) {
            if (workingSet.hasOwnProperty(address)) {
                var target = workingSet[address];
                var moduleId = target.module;
                if (moduleId !== undefined && !modules.hasOwnProperty(moduleId)) {
                    var m = allModules()[moduleId];
                    delete m._cachedFunctionExports;
                    modules[moduleId] = m;
                }
                targets.push(target);
            }
        }
        return {
            modules: modules,
            targets: targets
        };
    }
};

function includeModule(pattern, workingSet) {
    moduleResolver().enumerateMatchesSync('exports:' + pattern + '!*').forEach(function (m) {
        workingSet[m.address.toString()] = moduleExportFromMatch(m);
    });
    return workingSet;
}

function excludeModule(pattern, workingSet) {
    moduleResolver().enumerateMatchesSync('exports:' + pattern + '!*').forEach(function (m) {
        delete workingSet[m.address.toString()];
    });
    return workingSet;
}

function includeFunction(pattern, workingSet) {
    moduleResolver().enumerateMatchesSync('exports:*!' + pattern).forEach(function (m) {
        workingSet[m.address.toString()] = moduleExportFromMatch(m);
    });
    return workingSet;
}

function excludeFunction(pattern, workingSet) {
    moduleResolver().enumerateMatchesSync('exports:*!' + pattern).forEach(function (m) {
        delete workingSet[m.address.toString()];
    });
    return workingSet;
}

function includeRelativeFunction(func, workingSet) {
    var relativeToModule = func.module;
    var modules = allModules();
    for (var moduleIndex = 0; moduleIndex !== modules.length; moduleIndex++) {
        var module = modules[moduleIndex];
        if (module.path === relativeToModule || module.name === relativeToModule) {
            var relativeAddress = ptr(func.offset);
            var absoluteAddress = module.base.add(relativeAddress);
            workingSet[absoluteAddress] = {
                name: "sub_" + relativeAddress.toString(16),
                address: absoluteAddress,
                module: moduleIndex,
                private: true
            };
        }
    }
    return workingSet;
}

function includeImports(pattern, workingSet) {
    var matches;
    if (pattern === null) {
        var mainModule = allModules()[0].path;
        matches = moduleResolver().enumerateMatchesSync('imports:' + mainModule + '!*');
    } else {
        matches = moduleResolver().enumerateMatchesSync('imports:' + pattern + '!*');
    }

    matches.map(moduleExportFromMatch).forEach(function (e) {
        workingSet[e.address.toString()] = e;
    });

    return workingSet;
}

function includeObjCMethod(pattern, workingSet) {
    objcResolver().enumerateMatchesSync(pattern).forEach(function (m) {
        workingSet[m.address.toString()] = objcMethodFromMatch(m);
    });
    return workingSet;
}

var cachedModuleResolver = null;
function moduleResolver() {
    if (cachedModuleResolver === null)
        cachedModuleResolver = new ApiResolver('module');
    return cachedModuleResolver;
}

var cachedObjcResolver = null;
function objcResolver() {
    if (cachedObjcResolver === null) {
        try {
            cachedObjcResolver = new ApiResolver('objc');
        } catch (e) {
            throw new Error("Objective-C runtime is not available");
        }
    }
    return cachedObjcResolver;
}

var cachedModules = null;
function allModules() {
    if (cachedModules === null) {
        cachedModules = Process.enumerateModulesSync();
        cachedModules._idByPath = cachedModules.reduce(function (mappings, module, index) {
            mappings[module.path] = index;
            return mappings;
        }, {});
    }
    return cachedModules;
}

function moduleExportFromMatch(m) {
    var encodedName = m.name;
    var delimiterIndex = encodedName.indexOf('!');
    var modulePath = encodedName.substring(0, delimiterIndex);
    var functionName = encodedName.substring(delimiterIndex + 1);
    return {
        name: functionName,
        address: m.address,
        module: allModules()._idByPath[modulePath]
    };
}

function objcMethodFromMatch(m) {
    var encodedName = m.name;
    var methodType = encodedName[0];
    var delimiterIndex = encodedName.indexOf(' ', 3);
    var className = encodedName.substring(2, delimiterIndex);
    var methodName = encodedName.substring(delimiterIndex + 1, encodedName.length - 1);
    return {
        objc: {
            className: className,
            method: {
                type: methodType,
                name: methodName
            }
        },
        address: m.address
    };
}
"""

class Tracer(object):
    def __init__(self, reactor, repository, profile, log_handler=None):
        self._reactor = reactor
        self._repository = repository
        self._profile = profile
        self._script = None
        self._log_handler = log_handler

    def start_trace(self, session, ui):
        def on_create(*args):
            ui.on_trace_handler_create(*args)
        self._repository.on_create(on_create)

        def on_load(*args):
            ui.on_trace_handler_load(*args)
        self._repository.on_load(on_load)

        def on_update(function, handler, source):
            self._script.exports.update([{
                'name': function.name,
                'absolute_address': hex(function.absolute_address),
                'handler': handler
            }])
        self._repository.on_update(on_update)

        def on_message(message, data):
            self._reactor.schedule(lambda: self._process_message(message, data, ui))

        ui.on_trace_progress('resolve')
        working_set = self._profile.resolve(session, log_handler=self._log_handler)
        ui.on_trace_progress('instrument')
        self._script = session.create_script(name="tracer", source=self._create_trace_script())
        self._script.set_log_handler(self._log_handler)
        self._script.on('message', on_message)
        self._script.load()
        for chunk in [working_set[i:i+1000] for i in range(0, len(working_set), 1000)]:
            targets = [{
                    'name': function.name,
                    'absolute_address': hex(function.absolute_address),
                    'handler': self._repository.ensure_handler(function)
                } for function in chunk]
            self._script.exports.add(targets)

        self._repository.commit_handlers()

        self._reactor.schedule(lambda: ui.on_trace_progress('ready'))

        return working_set

    def stop(self):
        if self._script is not None:
            try:
                self._script.unload()
            except:
                pass
            self._script = None

    def _create_trace_script(self):
        return """"use strict";

var started = Date.now();
var handlers = {};
var state = {};
var pending = [];
var timer = null;

installFlushBeforeExitHandlers();

rpc.exports = {
    add: function (targets) {
        targets.forEach(function (target) {
            var h = [parseHandler(target)];
            var name = target.name;
            var targetAddress = target.absolute_address;
            target = null;

            handlers[targetAddress] = h;

            function invokeCallback(callback, context, param) {
                if (callback === undefined)
                    return;

                var timestamp = Date.now() - started;
                var threadId = context.threadId;
                var depth = context.depth;

                function log(message) {
                    emit([timestamp, threadId, depth, targetAddress, message]);
                }

                callback.call(context, log, param, state);
            }

            try {
                Interceptor.attach(ptr(targetAddress), {
                    onEnter: function (args) {
                        invokeCallback(h[0].onEnter, this, args);
                    },
                    onLeave: function (retval) {
                        invokeCallback(h[0].onLeave, this, retval);
                    }
                });
            } catch (e) {
                send({
                    from: "/targets",
                    name: '+error',
                    payload: {
                        message: "Skipping '" + name + "': " + e.message
                    }
                });
            }
        });
    },
    update: function (targets) {
        targets.forEach(function (target) {
            handlers[target.absolute_address][0] = parseHandler(target);
        });
    }
};

function emit(event) {
    pending.push(event);

    if (timer === null)
        timer = setTimeout(flush, 50);
}

function flush() {
    if (timer !== null) {
        clearTimeout(timer);
        timer = null;
    }

    if (pending.length === 0)
        return;

    var items = pending;
    pending = [];

    send({
        from: "/events",
        name: '+add',
        payload: {
            items: items
        }
    });
}

function parseHandler(target) {
    try {
        return (1, eval)("(" + target.handler + ")");
    } catch (e) {
        send({
            from: "/targets",
            name: '+error',
            payload: {
                message: "Invalid handler for '" + target.name + "': " + e.message
            }
        });
        return {};
    }
}

function installFlushBeforeExitHandlers() {
    if (Process.platform === 'windows') {
        attachFlushBeforeExitHandler("kernel32.dll", "ExitProcess");
    } else {
        attachFlushBeforeExitHandler(null, "abort");
        attachFlushBeforeExitHandler(null, "exit");
    }
}

function attachFlushBeforeExitHandler(module, name) {
    Interceptor.attach(Module.findExportByName(module, name), performFlushBeforeExit);
}

function performFlushBeforeExit() {
    flush();

    send({
        from: "/events",
        name: '+flush',
        payload: {}
    });
    recv('+flush-ack', function () {}).wait();
}
"""

    def _process_message(self, message, data, ui):
        handled = False
        if message['type'] == 'send':
            stanza = message['payload']
            if stanza['from'] == "/events":
                if stanza['name'] == '+add':
                    events = [(timestamp, thread_id, depth, int(target_address.rstrip("L"), 16), message) for timestamp, thread_id, depth, target_address, message in stanza['payload']['items']]
                    ui.on_trace_events(events)
                    handled = True
                elif stanza['name'] == '+flush':
                    try:
                        self._script.post_message({ 'type': '+flush-ack' })
                    except Exception as e:
                        pass
                    handled = True
            elif stanza['from'] == "/targets" and stanza['name'] == '+error':
                ui.on_trace_error(stanza['payload'])
                handled = True
        if not handled:
            print(message)

class Repository(object):
    def __init__(self):
        self._on_create_callback = None
        self._on_load_callback = None
        self._on_update_callback = None

    def ensure_handler(self, function):
        raise NotImplementedError("not implemented")

    def commit_handlers(self):
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
        if isinstance(function, ObjCMethod):
            display_name = function.display_name()
            _nonlocal_i = {'val': 2}
            def objc_arg(m):
                r = ':" + args[%d] + " ' % _nonlocal_i['val']
                _nonlocal_i['val'] += 1
                return r

            log_str = '"' + re.sub(r':', objc_arg, display_name) + '"'
        else:
            display_name = function.name

            args = ""
            argc = 0
            varargs = False
            try:
                with open(os.devnull, 'w') as devnull:
                    man_argv = ["man"]
                    if platform.system() != "Darwin":
                        man_argv.extend(["-E", "UTF-8"])
                    man_argv.extend(["-P", "col -b", "2", function.name])
                    output = subprocess.check_output(man_argv, stderr=devnull)
                match = re.search(r"^SYNOPSIS(?:.|\n)*?((?:^.+$\n)* {5}\w+ \**?" + function.name + r"\((?:.+\,\s*?$\n)*?(?:.+\;$\n))(?:.|\n)*^DESCRIPTION", output.decode('UTF-8', errors='replace'), re.MULTILINE)
                if match:
                    decl = match.group(1)
                    for argm in re.finditer(r"([^* ]*)\s*(,|\))", decl):
                        arg = argm.group(1)
                        if arg == 'void':
                            continue
                        if arg == '...':
                            args += '+ ", ..."'
                            varargs = True
                            continue

                        args += '%(pre)s%(arg)s=" + args[%(argc)s]' % {"arg": arg, "argc": argc, "pre": '"' if argc == 0 else '+ ", '}
                        argc += 1
            except Exception as e:
                pass
            if args == "":
                args = '""'

            log_str = '"%(name)s(" + %(args)s + ")"' % { "name": function.name, "args": args }

        return """\
/*
 * Auto-generated by Frida. Please modify to match the signature of %(display_name)s.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: http://www.frida.re/docs/javascript-api/
 */

{
    /**
     * Called synchronously when about to call %(display_name)s.
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
    onEnter: function (log, args, state) {
        log(%(log_str)s);
    },

    /**
     * Called synchronously when about to return from %(display_name)s.
     *
     * See onEnter for details.
     *
     * @this {object} - Object allowing you to access state stored in onEnter.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {NativePointer} retval - Return value represented as a NativePointer object.
     * @param {object} state - Object allowing you to keep state across function calls.
     */
    onLeave: function (log, retval, state) {
    }
}
""" % {"display_name": display_name, "log_str": log_str}

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
    def __init__(self, reactor):
        super(FileRepository, self).__init__()
        self._reactor = reactor
        self._handler_by_address = {}
        self._handler_by_file = {}
        self._changed_files = set()
        self._last_change_id = 0
        self._repo_dir = os.path.join(os.getcwd(), "__handlers__")
        self._repo_monitors = {}

    def ensure_handler(self, function):
        entry = self._handler_by_address.get(function.absolute_address)
        if entry is not None:
            (function, handler, handler_file) = entry
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
                with codecs.open(handler_file, 'r', 'utf-8') as f:
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

        entry = (function, handler, handler_file)
        self._handler_by_address[function.absolute_address] = entry
        self._handler_by_file[handler_file] = entry

        self._ensure_monitor(handler_file)

        return handler

    def _ensure_monitor(self, handler_file):
        handler_dir = os.path.dirname(handler_file)
        monitor = self._repo_monitors.get(handler_dir)
        if monitor is None:
            monitor = FileMonitor(handler_dir)
            monitor.on('change', self._on_change)
            self._repo_monitors[handler_dir] = monitor

    def commit_handlers(self):
        for monitor in self._repo_monitors.values():
            monitor.enable()

    def _on_change(self, changed_file, other_file, event_type):
        if changed_file not in self._handler_by_file or event_type == 'changes-done-hint':
            return
        self._changed_files.add(changed_file)
        self._last_change_id += 1
        change_id = self._last_change_id
        self._reactor.schedule(lambda: self._sync_handlers(change_id), delay=0.05)

    def _sync_handlers(self, change_id):
        if change_id != self._last_change_id:
            return
        changes = self._changed_files.copy()
        self._changed_files.clear()
        for changed_handler_file in changes:
            (function, old_handler, handler_file) = self._handler_by_file[changed_handler_file]
            with codecs.open(handler_file, 'r', 'utf-8') as f:
                new_handler = f.read()
            changed = new_handler != old_handler
            if changed:
                entry = (function, new_handler, handler_file)
                self._handler_by_address[function.absolute_address] = entry
                self._handler_by_file[handler_file] = entry
                self._notify_update(function, new_handler, handler_file)

class UI(object):
    def on_trace_progress(self, operation):
        pass

    def on_trace_error(self, error):
        pass

    def on_trace_events(self, events):
        pass

    def on_trace_handler_create(self, function, handler, source):
        pass

    def on_trace_handler_load(self, function, handler, source):
        pass


def main():
    from colorama import Fore, Style
    from frida.application import ConsoleApplication, input_with_timeout

    class TracerApplication(ConsoleApplication, UI):
        def __init__(self):
            super(TracerApplication, self).__init__(self._await_ctrl_c)
            self._palette = [Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.GREEN, Fore.RED, Fore.BLUE]
            self._next_color = 0
            self._attributes_by_thread_id = {}
            self._last_event_tid = -1

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
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_relative_address,))
            parser.add_option("-T", "--include-imports", help="include program's imports",
                    action='callback', callback=process_builder_arg, callback_args=(pb.include_imports,))
            parser.add_option("-t", "--include-module-imports", help="include MODULE imports", metavar="MODULE",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_imports,))
            parser.add_option("-m", "--include-objc-method", help="include OBJC_METHOD", metavar="OBJC_METHOD",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_objc_method,))
            self._profile_builder = pb

        def _usage(self):
            return "usage: %prog [options] target"

        def _initialize(self, parser, options, args):
            self._tracer = None
            self._targets = None
            self._profile = self._profile_builder.build()

        def _needs_target(self):
            return True

        def _start(self):
            self._tracer = Tracer(self._reactor, FileRepository(self._reactor), self._profile, log_handler=self._log)
            try:
                self._targets = self._tracer.start_trace(self._session, self)
            except Exception as e:
                self._update_status("Failed to start tracing: {error}".format(error=e))
                self._exit(1)

        def _stop(self):
            self._print("Stopping...")
            self._tracer.stop()
            self._tracer = None

        def _await_ctrl_c(self, reactor):
            while reactor.is_running():
                try:
                    input_with_timeout(0.5)
                except KeyboardInterrupt:
                    break

        def on_trace_progress(self, operation):
            if operation == 'resolve':
                self._update_status("Resolving functions...")
            elif operation == 'instrument':
                self._update_status("Instrumenting functions...")
            elif operation == 'ready':
                if len(self._targets) == 1:
                    plural = ""
                else:
                    plural = "s"
                self._update_status("Started tracing %d function%s. Press Ctrl+C to stop." % (len(self._targets), plural))
                self._resume()

        def on_trace_error(self, error):
            self._print(Fore.RED + Style.BRIGHT + "Error" + Style.RESET_ALL + ": " + error['message'])

        def on_trace_events(self, events):
            no_attributes = Style.RESET_ALL
            for timestamp, thread_id, depth, target_address, message in events:
                indent = depth * "   | "
                attributes = self._get_attributes(thread_id)
                if thread_id != self._last_event_tid:
                    self._print("%s           /* TID 0x%x */%s" % (attributes, thread_id, Style.RESET_ALL))
                    self._last_event_tid = thread_id
                self._print("%6d ms  %s%s%s%s" % (timestamp, attributes, indent, message, no_attributes))

        def on_trace_handler_create(self, function, handler, source):
            self._print("%s: Auto-generated handler at \"%s\"" % (function, source.replace("\\", "\\\\")))

        def on_trace_handler_load(self, function, handler, source):
            self._print("%s: Loaded handler at \"%s\"" % (function, source.replace("\\", "\\\\")))

        def _get_attributes(self, thread_id):
            attributes = self._attributes_by_thread_id.get(thread_id, None)
            if attributes is None:
                color = self._next_color
                self._next_color += 1
                attributes = self._palette[color % len(self._palette)]
                if (1 + int(color / len(self._palette))) % 2 == 0:
                    attributes += Style.BRIGHT
                self._attributes_by_thread_id[thread_id] = attributes
            return attributes

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
