# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import _frida
import bisect
import fnmatch
import numbers
import sys
import threading
import traceback


class DeviceManager(object):
    def __init__(self, impl):
        self._impl = impl

    def __repr__(self):
        return repr(self._impl)

    def enumerate_devices(self):
        return [Device(device) for device in self._impl.enumerate_devices()]

    def add_remote_device(self, host):
        return Device(self._impl.add_remote_device(host))

    def remove_remote_device(self, host):
        self._impl.remove_remote_device(host)

    def get_device(self, device_id):
        devices = self._impl.enumerate_devices()
        if device_id is None:
            return Device(devices[0])
        for device in devices:
            if device.id == device_id:
                return Device(device)
        raise _frida.InvalidArgumentError("unable to find device with id %s" % device_id)

    def on(self, signal, callback):
        self._impl.on(signal, callback)

    def off(self, signal, callback):
        self._impl.off(signal, callback)

class Device(object):
    def __init__(self, device):
        self.id = device.id
        self.name = device.name
        self.icon = device.icon
        self.type = device.type
        self._impl = device

    def __repr__(self):
        return repr(self._impl)

    def get_frontmost_application(self):
        return self._impl.get_frontmost_application()

    def enumerate_applications(self):
        return self._impl.enumerate_applications()

    def enumerate_processes(self):
        return self._impl.enumerate_processes()

    def get_process(self, process_name):
        process_name_lc = process_name.lower()
        matching = [process for process in self._impl.enumerate_processes() if fnmatch.fnmatchcase(process.name.lower(), process_name_lc)]
        if len(matching) == 1:
            return matching[0]
        elif len(matching) > 1:
            raise _frida.ProcessNotFoundError("ambiguous name; it matches: %s" % ", ".join(["%s (pid: %d)" % (process.name, process.pid) for process in matching]))
        else:
            raise _frida.ProcessNotFoundError("unable to find process with name '%s'" % process_name)

    def enable_spawn_gating(self):
        return self._impl.enable_spawn_gating()

    def disable_spawn_gating(self):
        return self._impl.disable_spawn_gating()

    def enumerate_pending_spawns(self):
        return self._impl.enumerate_pending_spawns()

    def spawn(self, argv):
        return self._impl.spawn(argv)

    def input(self, target, data):
        self._impl.input(self._pid_of(target), data)

    def resume(self, target):
        self._impl.resume(self._pid_of(target))

    def kill(self, target):
        self._impl.kill(self._pid_of(target))

    def attach(self, target):
        return Session(self._impl.attach(self._pid_of(target)))

    def on(self, signal, callback):
        self._impl.on(signal, callback)

    def off(self, signal, callback):
        self._impl.off(signal, callback)

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

class Session(FunctionContainer):
    def __init__(self, impl):
        super(Session, self).__init__()
        self._impl = impl
        self._modules = None
        self._module_map = None

        self._script = None

    def detach(self):
        self._impl.detach()

    def enumerate_modules(self):
        if self._modules is None:
            raw_modules = self._get_api().enumerate_modules()
            self._modules = [Module(data['name'], int(data['base'], 16), data['size'], data['path'], self) for data in raw_modules]
        return self._modules

    def prefetch_modules(self):
        modules = self.enumerate_modules()
        pending = [m for m in modules if m._exports is None]
        batches = self._get_api().enumerate_exports([m.path for m in pending])
        for i, raw_exports in enumerate(batches):
            pending[i]._update_exports(raw_exports)

    """
      @param protection example '--x'
    """
    def enumerate_ranges(self, protection):
        raw_ranges = self._get_api().enumerate_ranges(protection)
        return [Range(int(data['base'], 16), data['size'], data['protection']) for data in raw_ranges]

    def find_base_address(self, module_name):
        raw_base_address = self._get_api().find_base_address(module_name)
        return int(raw_base_address, 16)

    def read_bytes(self, address, size):
        return self._get_api().read_byte_array("0x%x" % address, size)

    def write_bytes(self, address, data):
        self._get_api().write_byte_array("0x%x" % address, [x for x in iterbytes(data)])

    def read_utf8(self, address, length=-1):
        return self._get_api().read_utf8("0x%x" % address, length)

    def write_utf8(self, address, string):
        self._get_api().write_utf8("0x%x" % address, string)

    def create_script(self, *args, **kwargs):
        return Script(self._impl.create_script(*args, **kwargs))

    def enable_debugger(self, *args, **kwargs):
        return self._impl.enable_debugger(*args, **kwargs)

    def disable_debugger(self):
        return self._impl.disable_debugger()

    def disable_jit(self):
        return self._impl.disable_jit()

    def on(self, signal, callback):
        self._impl.on(signal, callback)

    def off(self, signal, callback):
        self._impl.off(signal, callback)

    def _get_api(self):
        return self._get_script().exports

    def _get_script(self):
        if self._script is None:
            self._script = self.create_script(name="session", source=self._create_session_script())
            self._script.on('message', self._on_message)
            self._script.load()
        return self._script

    def _on_message(self, message, data):
        print("[session]", message, data)

    def _create_session_script(self):
        return """\
"use strict";

rpc.exports = {
  enumerateModules: function () {
    return Process.enumerateModulesSync();
  },
  enumerateExports: function (modulePaths) {
    return modulePaths.map(function (modulePath) {
      return Module.enumerateExportsSync(modulePath);
    });
  },
  enumerateRanges: function (protection) {
    return Process.enumerateRangesSync(protection);
  },
  findBaseAddress: function (moduleName) {
    var address = Module.findBaseAddress(moduleName);
    return (address !== null) ? address.toString() : "0";
  },
  readByteArray: function (address, size) {
    return Memory.readByteArray(ptr(address), size);
  },
  writeByteArray: function (address, data) {
    var base = ptr(address);
    for (var i = 0; i !== data.length; i++) {
      Memory.writeU8(base.add(i), data[i]);
    }
  },
  readUtf8: function (address, length) {
    return Memory.readUtf8String(ptr(address), length);
  },
  writeUtf8: function (address, string) {
    Memory.writeUtf8String(ptr(address), string);
  },
  enumerateModuleExports: function (modulePath) {
    return Module.enumerateExportsSync(modulePath).filter(function (e) {
      return e.type === 'function';
    });
  },
  enumerateModuleRanges: function (modulePath, protection) {
    return Module.enumerateRangesSync(modulePath, protection);
  }
};
"""

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

    def __getattr__(self, attr):
        if attr == 'session':
            raise KeyError("Please update your code from `.session.create_script()` to `.create_script()`")
        else:
            return getattr(super(Session, self), attr)

class Script(object):
    def __init__(self, impl):
        self.exports = ScriptExports(self)

        self._impl = impl
        self._on_message_callbacks = []
        self._log_handler = self._on_log

        self._pending = {}
        self._next_request_id = 1
        self._cond = threading.Condition()

        impl.on('message', self._on_message)

    def __repr__(self):
        return repr(self._impl)

    def load(self):
        self._impl.load()

    def unload(self):
        self._impl.unload()

    def post_message(self, message):
        self._impl.post_message(message)

    def on(self, signal, callback):
        if signal == 'message':
            self._on_message_callbacks.append(callback)
        else:
            self._impl.on(signal, callback)

    def off(self, signal, callback):
        if signal == 'message':
            self._on_message_callbacks.remove(callback)
        else:
            self._impl.off(signal, callback)

    def set_log_handler(self, handler):
        if handler is not None:
            self._log_handler = handler
        else:
            self._log_handler = self._on_log

    def _rpc_request(self, *args):
        result = [False, None, None]
        def on_complete(value, error):
            with self._cond:
                result[0] = True
                result[1] = value
                result[2] = error
                self._cond.notifyAll()

        with self._cond:
            request_id = self._next_request_id
            self._next_request_id += 1
            self._pending[request_id] = on_complete
            message = ['frida:rpc', request_id]
            message.extend(args)
            self.post_message(message)
            while not result[0]:
                self._cond.wait()

        if result[2] is not None:
            raise result[2]

        return result[1]

    def _on_rpc_message(self, request_id, operation, params, data):
        if operation in ('ok', 'error'):
            callback = self._pending.pop(request_id)

            value = None
            error = None
            if operation == 'ok':
                value = params[0] if data is None else data
            else:
                error = Exception(params[0])

            callback(value, error)

    def _on_message(self, message, data):
        mtype = message['type']
        payload = message.get('payload', None)
        if mtype == 'log':
            level = message['level']
            text = payload
            self._log_handler(level, text)
        elif mtype == 'send' and isinstance(payload, list) and payload[0] == 'frida:rpc':
            request_id = payload[1]
            operation = payload[2]
            params = payload[3:]
            self._on_rpc_message(request_id, operation, params, data)
        else:
            for callback in self._on_message_callbacks[:]:
                try:
                    callback(message, data)
                except:
                    traceback.print_exc()

    def _on_log(self, level, text):
        if level == 'info':
            print(text, file=sys.stdout)
        else:
            print(text, file=sys.stderr)

class ScriptExports(object):
    def __init__(self, script):
        self._script = script

    def __getattr__(self, name):
        script = self._script
        js_name = _to_camel_case(name)
        def method(*args):
            return script._rpc_request('call', js_name, args)
        return method

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
            raw_exports = self._session._get_api().enumerate_module_exports(self.path)
            self._update_exports(raw_exports)
        return self._exports

    """
      @param protection example '--x'
    """
    def enumerate_ranges(self, protection):
        raw_ranges = self._session._get_script().exports.enumerate_module_ranges(self.path, protection)
        return [Range(int(data['base'], 16), data['size'], data['protection']) for data in raw_ranges]

    def _update_exports(self, exports):
        self._exports = []
        for export in exports:
            relative_address = int(export["address"], 16) - self.base_address
            mf = ModuleFunction(self, export["name"], relative_address, True)
            self._exports.append(mf)
            self._functions[relative_address] = mf

    def _do_ensure_function(self, relative_address):
        self.enumerate_exports()
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

class ObjCMethod(Function):
    def __init__(self, mtype, cls, method, address):
        self.mtype = mtype
        self.cls = cls
        self.method = method
        self.address = address
        super(ObjCMethod, self).__init__(self.display_name(), address)

    def display_name(self):
        return '{mtype}[{cls} {method}]'.format(mtype=self.mtype, cls=self.cls, method=self.method)

    def __repr__(self):
        return "ObjCMethod(mtype=\"%s\", cls=\"%s\", method=\"%s\", address=0x%x)" % (self.mtype, self.cls, self.method, self.address)

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
    def __init__(self, functions, get_address=lambda f: f.absolute_address):
        super(FunctionMap, self).__init__(functions, get_address, lambda f: 1)

def _to_camel_case(name):
    result = ""
    uppercase_next = False
    for c in name:
        if c == '_':
            uppercase_next = True
        elif uppercase_next:
            result += c.upper()
            uppercase_next = False
        else:
            result += c.lower()
    return result

if sys.version_info[0] >= 3:
    iterbytes = lambda x: iter(x)
else:
    def iterbytes(data):
        return (ord(char) for char in data)
