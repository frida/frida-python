# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

from frida_tools.model import Module, Function, ModuleFunction


def main():
    import threading

    from frida_tools.application import await_enter, ConsoleApplication

    class DiscovererApplication(ConsoleApplication, UI):
        def __init__(self):
            self._results_received = threading.Event()
            ConsoleApplication.__init__(self, self._await_keys)

        def _await_keys(self, reactor):
            await_enter(reactor)
            reactor.schedule(lambda: self._discoverer.stop())
            while reactor.is_running() and not self._results_received.is_set():
                self._results_received.wait(0.5)

        def _usage(self):
            return "usage: %prog [options] target"

        def _initialize(self, parser, options, args):
            self._discoverer = None

        def _needs_target(self):
            return True

        def _start(self):
            self._update_status("Injecting script...")
            self._discoverer = Discoverer(self._reactor)
            self._discoverer.start(self._session, self)

        def _stop(self):
            self._print("Stopping...")
            self._discoverer.dispose()
            self._discoverer = None

        def on_sample_start(self, total):
            self._update_status("Tracing %d threads. Press ENTER to stop." % total)
            self._resume()

        def on_sample_result(self, module_functions, dynamic_functions):
            for module, functions in module_functions.items():
                self._print(module.name)
                self._print("\t%-10s\t%s" % ("Calls", "Function"))
                for function, count in sorted(functions, key=lambda item: item[1], reverse=True):
                    self._print("\t%-10d\t%s" % (count, function))
                self._print("")

            if len(dynamic_functions) > 0:
                self._print("Dynamic functions:")
                self._print("\t%-10s\t%s" % ("Calls", "Function"))
                for function, count in sorted(dynamic_functions, key=lambda item: item[1], reverse=True):
                    self._print("\t%-10d\t%s" % (count, function))

            self._results_received.set()

    app = DiscovererApplication()
    app.run()


class Discoverer(object):
    def __init__(self, reactor):
        self._reactor = reactor
        self._ui = None
        self._script = None

    def dispose(self):
        if self._script is not None:
            try:
                self._script.unload()
            except:
                pass
            self._script = None

    def start(self, session, ui):
        def on_message(message, data):
            print(message, data)
        session.enable_jit()
        self._script = session.create_script(name="discoverer", source=self._create_discover_script())
        self._script.on('message', on_message)
        self._script.load()

        params = self._script.exports.start()
        ui.on_sample_start(params['total'])

        self._ui = ui

    def stop(self):
        result = self._script.exports.stop()

        modules = dict((int(module_id), Module(m['name'], int(m['base'], 16), m['size'], m['path']))
            for module_id, m in result['modules'].items())

        module_functions = {}
        dynamic_functions = []
        for module_id, name, visibility, raw_address, count in result['targets']:
            address = int(raw_address, 16)

            if module_id != 0:
                module = modules[module_id]
                exported = visibility == 'e'
                function = ModuleFunction(module, name, address - module.base_address, exported)

                functions = module_functions.get(module, [])
                if len(functions) == 0:
                    module_functions[module] = functions
                functions.append((function, count))
            else:
                function = Function(name, address)

                dynamic_functions.append((function, count))

        self._ui.on_sample_result(module_functions, dynamic_functions)

    def _create_discover_script(self):
        return """'use strict';

var threadIds = [];
var result = {};

rpc.exports = {
    start: function () {
        threadIds = Process.enumerateThreadsSync().map(function (thread) { return thread.id; });
        threadIds.forEach(function (threadId) {
            Stalker.follow(threadId, {
                events: { call: true },
                onCallSummary: function (summary) {
                    for (var address in summary) {
                        if (summary.hasOwnProperty(address)) {
                            var count = result[address] || 0;
                            result[address] = count + summary[address];
                        }
                    }
                }
            });
        });

        return {
            total: threadIds.length
        };
    },
    stop: function () {
        threadIds.forEach(function (threadId) {
            Stalker.unfollow(threadId);
        });
        threadIds = [];

        var res = result;
        result = {};

        var map = new ModuleMap();

        var allModules = map.values()
            .reduce(function (result, module) {
                result[module.path] = module;
                return result;
            }, {});
        var seenModules = {};

        var moduleDetails = {};
        var nextModuleId = 1;

        var targets = Object.keys(res)
            .map(function (address) {
                var moduleId = 0;
                var name;
                var visibility = 'i';
                var addressPtr = ptr(address);
                var count = res[address];

                var path = map.findPath(addressPtr);
                if (path !== null) {
                    var module = allModules[path];

                    var details = moduleDetails[path];
                    if (details !== undefined) {
                        moduleId = details.id;
                    } else {
                        moduleId = nextModuleId++;

                        details = {
                            id: moduleId,
                            exports: Module.enumerateExportsSync(path)
                                .reduce(function (result, e) {
                                    result[e.address.toString()] = e.name;
                                    return result;
                                }, {})
                        };
                        moduleDetails[path] = details;

                        seenModules[moduleId] = module;
                    }

                    var exportName = details.exports[address];
                    if (exportName !== undefined) {
                        name = exportName;
                        visibility = 'e';
                    } else {
                        name = 'sub_' + addressPtr.sub(module.base).toString(16);
                    }
                } else {
                    name = 'dsub_' + addressPtr.toString(16);
                }

                return [moduleId, name, visibility, address, count];
            });

        return {
            targets: targets,
            modules: seenModules
        };
    }
};
"""


class UI(object):
    def on_sample_start(self, total):
        pass

    def on_sample_result(self, module_functions, dynamic_functions):
        pass


if __name__ == '__main__':
    main()
