# -*- coding: utf-8 -*-

from frida.core import ModuleFunction


class Discoverer(object):
    def __init__(self, reactor):
        self._reactor = reactor
        self._script = None

    def start(self, process, ui):
        def on_message(message, data):
            self._reactor.schedule(lambda: self._process_message(message, data, process, ui))
        source = self._create_discover_script()
        self._script = process.session.create_script(source)
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
var Sampler = function Sampler() {
    var total = 0;
    var pending = [];
    var active = [];
    var samples = {};
    Process.enumerateThreads({
        onMatch: function (thread) {
            pending.push(thread);
        },
        onComplete: function () {
            var currentThreadId = Process.getCurrentThreadId();
            pending = pending.filter(function (thread) {
                return thread.id !== currentThreadId;
            });
            total = pending.length;
            var processNext = function processNext() {
                active.forEach(function (thread) {
                    Stalker.unfollow(thread.id);
                });
                active = pending.splice(0, 4);
                if (active.length > 0) {
                    var begin = total - pending.length - active.length;
                    send({
                        from: "/sampler",
                        name: '+progress',
                        payload: {
                            begin: begin,
                            end: begin + active.length - 1,
                            total: total
                        }
                    });
                } else {
                    for (var address in samples) {
                        if (samples.hasOwnProperty(address)) {
                            var counts = samples[address].counts;
                            var sum = 0;
                            for (var i = 0; i !== counts.length; i++) {
                                sum += counts[i];
                            }
                            var callsPerSecond = Math.round(sum / (counts.length * 0.25));
                            samples[address] = callsPerSecond;
                        }
                    }
                    send({
                        from: "/sampler",
                        name: '+result',
                        payload: {
                            samples: samples
                        }
                    });
                    samples = null;
                }
                active.forEach(function (thread) {
                    Stalker.follow(thread.id, {
                        events: { call: true },
                        onCallSummary: function (summary) {
                            if (samples === null) {
                                return;
                            }

                            for (var address in summary) {
                                if (summary.hasOwnProperty(address)) {
                                    var sample = samples[address];
                                    if (sample === undefined) {
                                        sample = { counts: [] };
                                        samples[address] = sample;
                                    }
                                    sample.counts.push(summary[address]);
                                }
                            }
                        }
                    });
                });
                if (active.length > 0) {
                    setTimeout(processNext, 2000);
                    setTimeout(Stalker.garbageCollect, 2100);
                }
            };
            setTimeout(processNext, 0);
        }
    });
};
sampler = new Sampler();
"""

    def _process_message(self, message, data, process, ui):
        if message['type'] == 'send':
            stanza = message['payload']
            name = stanza['name']
            payload = stanza['payload']
            if stanza['from'] == "/sampler":
                if name == '+progress':
                    ui.on_sample_progress(payload['begin'], payload['end'], payload['total'])
                elif name == '+result':
                    module_functions = {}
                    dynamic_functions = []
                    for address, rate in payload['samples'].items():
                        address = int(address, 16)
                        function = process.ensure_function(address)
                        if isinstance(function, ModuleFunction):
                            functions = module_functions.get(function.module, [])
                            if len(functions) == 0:
                                module_functions[function.module] = functions
                            functions.append((function, rate))
                        else:
                            dynamic_functions.append((function, rate))
                    ui.on_sample_result(module_functions, dynamic_functions)
                else:
                    print(message, data)
            else:
                print(message, data)
        else:
            print(message, data)

class UI(object):
    def on_sample_progress(self, begin, end, total):
        pass

    def on_sample_result(self, module_functions, dynamic_functions):
        pass


def main():
    from frida.application import ConsoleApplication

    class DiscovererApplication(ConsoleApplication, UI):
        def _usage(self):
            return "usage: %prog [options] process-name-or-id"

        def _initialize(self, parser, options, args):
            self._discoverer = None

        def _target_specifier(self, parser, options, args):
            if len(args) != 1:
                parser.error("process name or id must be specified")
            return args[0]

        def _start(self):
            self._update_status("Injecting script...")
            self._discoverer = Discoverer(self._reactor)
            self._discoverer.start(self._process, self)

        def _stop(self):
            print("Stopping...")
            self._discoverer.stop()
            self._discoverer = None

        def on_sample_progress(self, begin, end, total):
            self._update_status("Sampling %d threads: %d through %d..." % (total, begin, end))

        def on_sample_result(self, module_functions, dynamic_functions):
            for module, functions in module_functions.items():
                print(module.name)
                print("\t%-10s\t%s" % ("Rate", "Function"))
                for function, rate in sorted(functions, key=lambda item: item[1], reverse=True):
                    print("\t%-10d\t%s" % (rate, function))
                print("")

            if len(dynamic_functions) > 0:
                print("Dynamic functions:")
                print("\t%-10s\t%s" % ("Rate", "Function"))
                for function, rate in sorted(dynamic_functions, key=lambda item: item[1], reverse=True):
                    print("\t%-10d\t%s" % (rate, function))

            self._exit(0)

    app = DiscovererApplication()
    app.run()


if __name__ == '__main__':
    main()
