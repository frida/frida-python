# -*- coding: utf-8 -*-

import bisect
import fnmatch
import numbers
import sys
import threading


class DeviceManager(object):
    def __init__(self, manager):
        self._manager = manager

    def __repr__(self):
        return repr(self._manager)

    def enumerate_devices(self):
        return [Device(device) for device in self._manager.enumerate_devices()]

    def get_device(self, device_id):
        devices = self._manager.enumerate_devices()
        if device_id is None:
            return Device(devices[0])
        for device in devices:
            if device.id == device_id:
                return Device(device)
        raise ValueError("device not found")

    def on(self, signal, callback):
        self._manager.on(signal, callback)

    def off(self, signal, callback):
        self._manager.off(signal, callback)

class Device(object):
    def __init__(self, device):
        self.id = device.id
        self.name = device.name
        self.icon = device.icon
        self.type = device.type
        self._device = device

    def __repr__(self):
        return repr(self._device)

    def enumerate_processes(self):
        return self._device.enumerate_processes()

    def get_process(self, process_name):
        process_name_lc = process_name.lower()
        matching = [process for process in self._device.enumerate_processes() if fnmatch.fnmatchcase(process.name.lower(), process_name_lc)]
        if len(matching) == 1:
            return matching[0]
        elif len(matching) > 1:
            raise ValueError("ambiguous name; it matches: %s" % ", ".join(["%s (pid: %d)" % (process.name, process.pid) for process in matching]))
        else:
            raise ValueError("process not found")

    def spawn(self, command_line):
        return self._device.spawn(command_line)

    def resume(self, target):
        return self._device.resume(self._pid_of(target))

    def attach(self, target):
        return Process(self._device.attach(self._pid_of(target)))

    def on(self, signal, callback):
        self._device.on(signal, callback)

    def off(self, signal, callback):
        self._device.off(signal, callback)

    def _pid_of(self, target):
        if isinstance(target, numbers.Number):
            return target
        else:
            return self.get_process(target).pid

class FunctionContainer(object):
    def __init__(self):
        self._functions = {}

    """
    @param address is relative to container
    """
    def ensure_function(self, address):
        f = self._functions.get(address)
        if f is not None:
            return f
        return self._do_ensure_function(address)

    def _do_ensure_function(self, address):
        raise NotImplementedError("not implemented")

class Process(FunctionContainer):
    def __init__(self, session):
        super(Process, self).__init__()
        self.session = session
        self._modules = None
        self._module_map = None

    def detach(self):
        self.session.detach()

    def enumerate_modules(self):
        if self._modules is None:
            script = self.session.create_script(
    """
    var modules = [];
    Process.enumerateModules({
        onMatch: function (module) {
            modules.push(module);
        },
        onComplete: function () {
            send(modules);
        }
    });
    """)
            self._modules = [Module(data['name'], int(data['base'], 16), data['size'], data['path'], self.session) for data in _execute_script(script)]
        return self._modules

    """
      @param protection example '--x'
    """
    def enumerate_ranges(self, protection):
        script = self.session.create_script(
"""
var ranges = [];
Process.enumerateRanges(\"%s\", {
    onMatch: function (range) {
        ranges.push(range);
    },
    onComplete: function () {
        send(ranges);
    }
});
""" % protection)
        return [Range(int(data['base'], 16), data['size'], data['protection']) for data in _execute_script(script)]

    def _exec_script(self, script_source, post_hook = None):
        script = self.session.create_script(script_source)
        return _execute_script(script, post_hook)

    def find_base_address(self, module_name):
        return int(self._exec_script("var p = Module.findBaseAddress(\"%s\"); send(p !== null ? p.toString() : \"0\");" % module_name), 16)

    def read_bytes(self, address, length):
        return self._exec_script("send(null, Memory.readByteArray(ptr(\"%u\"), %u));" % (address, length))

    def read_utf8(self, address, length = -1):
        return self._exec_script("send(Memory.readUtf8String(ptr(\"%u\"), %u));" % (address, length))

    def write_bytes(self, address, data):
        script = \
"""
recv(function (data) {
    var base = ptr("%u");
    for (var i = 0; i !== data.length; i++)
        Memory.writeU8(base.add(i), data[i]);
    send(true);
});
""" % address

        def send_data(script):
            script.post_message([x for x in iterbytes(data)])

        self._exec_script(script, send_data)

    def write_utf8(self, address, string):
        script = \
"""
recv(function (string) {
    Memory.writeUtf8String(ptr("%u"), string);
    send(true);
});
""" % address

        def send_data(script):
            script.post_message(string)

        self._exec_script(script, send_data)

    def on(self, signal, callback):
        self.session.on(signal, callback)

    def off(self, signal, callback):
        self.session.off(signal, callback)

    def _do_ensure_function(self, absolute_address):
        if self._module_map is None:
            self._module_map = ModuleMap(self.enumerate_modules())
        m = self._module_map.lookup(absolute_address)
        if m is not None:
            f = m.ensure_function(absolute_address - m.base_address)
        else:
            f = Function("dsub_%x" % absolute_address, absolute_address)
            self._functions[absolute_address] = f
        return f

class Module(FunctionContainer):
    def __init__(self, name, base_address, size, path, session):
        super(Module, self).__init__()
        self.name = name
        self.base_address = base_address
        self.size = size
        self.path = path
        self._exports = None
        self._session = session

    def __repr__(self):
        return "Module(name=\"%s\", base_address=0x%x, size=%d, path=\"%s\")" % (self.name, self.base_address, self.size, self.path)

    def __hash__(self):
        return self.base_address.__hash__()

    def __cmp__(self, other):
        return self.base_address.__cmp__(other.base_address)

    def __eq__(self, other):
        return self.base_address == other.base_address

    def __ne__(self, other):
        return self.base_address != other.base_address

    def enumerate_exports(self):
        if self._exports is None:
            script = self._session.create_script(
"""
var exports = [];
Module.enumerateExports(\"%s\", {
    onMatch: function (exp) {
        if (exp.type === 'function') {
            exports.push(exp);
        }
    },
    onComplete: function () {
        send(exports);
    }
});
""" % self.name)
            self._exports = []
            for export in _execute_script(script):
                relative_address = int(export["address"], 16) - self.base_address
                mf = ModuleFunction(self, export["name"], relative_address, True)
                self._exports.append(mf)
        return self._exports

    """
      @param protection example '--x'
    """
    def enumerate_ranges(self, protection):
        script = self._session.create_script(
"""
var ranges = [];
Module.enumerateRanges(\"%s\", \"%s\", {
    onMatch: function (range) {
        ranges.push(range);
    },
    onComplete: function () {
        send(ranges);
    }
});
""" % (self.name, protection))
        return [Range(int(data['base'], 16), data['size'], data['protection']) for data in _execute_script(script)]

    def _do_ensure_function(self, relative_address):
        if self._exports is None:
            for mf in self.enumerate_exports():
                self._functions[mf.relative_address] = mf
        mf = self._functions.get(relative_address)
        if mf is None:
            mf = ModuleFunction(self, "sub_%x" % relative_address, relative_address, False)
            self._functions[relative_address] = mf
        return mf

class Function(object):
    def __init__(self, name, absolute_address):
        self.name = name
        self.absolute_address = absolute_address

    def __str__(self):
        return self.name

    def __repr__(self):
        return "Function(name=\"%s\", absolute_address=0x%x)" % (self.name, self.absolute_address)

    def __hash__(self):
        return self.absolute_address.__hash__()

    def __cmp__(self, other):
        return self.absolute_address.__cmp__(other.absolute_address)

    def __eq__(self, other):
        return self.absolute_address == other.absolute_address

    def __ne__(self, other):
        return self.absolute_address != other.absolute_address

class ModuleFunction(Function):
    def __init__(self, module, name, relative_address, exported):
        super(ModuleFunction, self).__init__(name, module.base_address + relative_address)
        self.module = module
        self.relative_address = relative_address
        self.exported = exported

    def __repr__(self):
        return "ModuleFunction(module=\"%s\", name=\"%s\", relative_address=0x%x)" % (self.module.name, self.name, self.relative_address)

class Range(object):
    def __init__(self, base_address, size, protection):
        self.base_address = base_address
        self.size = size
        self.protection = protection

    def __repr__(self):
        return "Range(base_address=0x%x, size=%s, protection='%s')" % (self.base_address, self.size, self.protection)

class Error(Exception):
    pass

class AddressMap(object):
    def __init__(self, items, get_address, get_size):
        self._items = sorted(items, key=get_address)
        self._indices = [ get_address(item) for item in self._items ]
        self._get_address = get_address
        self._get_size = get_size

    def lookup(self, address):
        index = bisect.bisect(self._indices, address)
        if index == 0:
            return None
        item = self._items[index - 1]
        if address >= self._get_address(item) + self._get_size(item):
            return None
        return item

class ModuleMap(AddressMap):
    def __init__(self, modules):
        super(ModuleMap, self).__init__(modules, lambda m: m.base_address, lambda m: m.size)

class FunctionMap(AddressMap):
    def __init__(self, functions, get_address = lambda f: f.absolute_address):
        super(FunctionMap, self).__init__(functions, get_address, lambda f: 1)

def _execute_script(script, post_hook = None):
    def on_message(message, data):
        if message['type'] == 'send':
            if data is not None:
                result['data'] = data
            else:
                result['data'] = message['payload']
        elif message['type'] == 'error':
            result['error'] = message['description']
        event.set()

    result = {}
    event = threading.Event()

    script.on('message', on_message)
    script.load()
    if post_hook:
        post_hook(script)
    event.wait()
    script.unload()
    script.off('message', on_message)

    if 'error' in result:
        raise Error(result['error'])

    return result['data']

if sys.version_info[0] >= 3:
    iterbytes = lambda x: iter(x)
else:
    def iterbytes(data):
        return (ord(char) for char in data)
