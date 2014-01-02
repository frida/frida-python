class Discoverer(object):
    def __init__(self):
        self._script = None

    def start(self, process):
        def on_message(message, data):
            print message, data
        source = self._create_discover_script()
        self._script = process._session.create_script(source)
        self._script.on("message", on_message)
        self._script.load()

    def stop(self):
        if self._script is not None:
            try:
                self._script.unload()
            except:
                pass
            self._script = None

    def _create_discover_script(self):
        return """
var pending = [];
var active = [];
Process.enumerateThreads({
    onMatch: function (thread) {
        pending.push(thread);
    },
    onComplete: function () {
        var currentThreadId = Process.getCurrentThreadId();
        pending = pending.filter(function (thread) {
            return thread.id !== currentThreadId;
        });
        var processNext = function processNext() {
            if (pending.length === 0) {
                return;
            }
            active.forEach(function (thread) {
                send("unfollow(" + thread.id + ")");
                Stalker.unfollow(thread.id);
            });
            active = pending.splice(0, 4);
            active.forEach(function (thread) {
                send("follow(" + thread.id + ")");
                Stalker.follow(thread.id, {
                    events: { call: true },
                    onCallSummary: function (summary) {
                        send("summary from " + thread.id);
                    }
                });
            });
            setTimeout(processNext, 2000);
        };
        setTimeout(processNext, 0);
    }
});
"""


def main():
    import frida
    from optparse import OptionParser
    import sys

    usage = "usage: %prog [options] process-name-or-id"
    parser = OptionParser(usage=usage)
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("process name or id must be specified")

    try:
        target = int(args[0])
    except:
        target = args[0]
    try:
        process = frida.attach(target)
    except Exception, e:
        print >> sys.stderr, "Failed to attach: %s" % e
        sys.exit(1)

    d = Discoverer()
    d.start(process)
    print "Discovery started"
    print "Press ENTER to stop"
    raw_input()
    print "Stopping..."
    d.stop()
    process.detach()
    frida.shutdown()

    sys.exit(0)


if __name__ == '__main__':
    main()
