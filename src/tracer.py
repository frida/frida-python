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
    def __init__(self, profile):
        self._profile = profile
        self._script = None

    def start_trace(self, process, sink):
        def on_message(message, data):
            sink.on_update([ message['payload'] ])

        working_set = self._profile.resolve(process)
        source = self._create_trace_script()
        self._script = process._session.create_script(source)
        self._script.on("message", on_message)
        self._script.load()
        for module, export in working_set:
            self._script.post_message([{ 'address': hex(export.address), 'name': export.name }])

    def _create_trace_script(self):
        return """
var pending = [];
var timer = null;
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
function onStanza(targets) {
    for (var i = 0; i !== targets.length; i++) {
        var target = targets[i];
        pending.push(function () {
            Interceptor.attach(ptr(target.address), {
                onEnter: function onEnter(args) {
                    send(target.name);
                }
            });
        });
    }

    scheduleNext();

    recv(onStanza);
};
recv(onStanza);
"""

    def end_trace(self):
        pass

class IOSink(object):
    def __init__(self, stream):
        self._stream = stream

    def on_update(self, invocation_events):
        for ev in invocation_events:
            self._stream.write(repr(ev) + "\n")

STDOUT_SINK = IOSink(sys.stdout)
STDERR_SINK = IOSink(sys.stderr)
