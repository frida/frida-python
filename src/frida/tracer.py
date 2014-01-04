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
        self._script = process.session.create_script(source)
        self._script.on("message", on_message)
        self._script.load()
        for chunk in [working_set[i:i+1000] for i in range(0, len(working_set), 1000)]:
            targets = [{ 'absolute_address': hex(export.absolute_address), 'name': export.name } for export in chunk]
            self._script.post_message(targets)

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
    targets.forEach(function (target) {
        pending.push(function () {
            Interceptor.attach(ptr(target.absolute_address), {
                onEnter: function onEnter(args) {
                    send([new Date().getTime() - started.getTime(), target.name]);
                }
            });
        });
    });

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
        for timestamp, function_name in invocation_events:
            self._stream.write("%6d ms\t%s\n" % (timestamp, function_name))

STDOUT_SINK = IOSink(sys.stdout)
STDERR_SINK = IOSink(sys.stderr)


def main():
    import frida
    from optparse import OptionParser

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

    t = Tracer(tp.build())
    try:
        target = int(args[0])
    except:
        target = args[0]
    try:
        p = frida.attach(target)
    except Exception as e:
        print >> sys.stderr, "Failed to attach: %s" % e
        sys.exit(1)
    targets = t.start_trace(p, STDOUT_SINK)
    print("Started tracing %d functions" % len(targets))
    print("Press ENTER to stop")
    raw_input()
    print("Stopping...")
    t.stop()
    p.detach()
    frida.shutdown()
    sys.exit(0)


if __name__ == '__main__':
    main()
