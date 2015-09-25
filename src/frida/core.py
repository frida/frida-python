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
        self._pending = {}
        self._next_request_id = 1
        self._cond = threading.Condition()

    def detach(self):
        self._impl.detach()

    def enumerate_modules(self):
        if self._modules is None:
            response = self._request('process:enumerate-modules')
            self._modules = [Module(data['name'], int(data['base'], 16), data['size'], data['path'], self) for data in response['modules']]
        return self._modules

    def prefetch_modules(self):
        modules = self.enumerate_modules()
        pending = [m for m in modules if m._exports is None]
        response = self._request('process:enumerate-module-exports', {
            'module_paths': [m.path for m in pending]
        })
        for i, exports in enumerate(response['exports']):
            pending[i]._update_exports(exports)

    """
      @param protection example '--x'
    """
    def enumerate_ranges(self, protection):
        response = self._request('process:enumerate-ranges', {
            'protection': protection
        })
        return [Range(int(data['base'], 16), data['size'], data['protection']) for data in response['ranges']]

    def find_base_address(self, module_name):
        response = self._request('module:find-base-address', {
            'module_name': module_name
        })
        return int(response['base_address'], 16)

    def read_bytes(self, address, size):
        return self._request('memory:read-byte-array', {
            'address': "0x%x" % address,
            'size': size
        })

    def write_bytes(self, address, data):
        self._request('memory:write-byte-array', {
            'address': "0x%x" % address,
            'data': [x for x in iterbytes(data)]
        })

    def read_utf8(self, address, length=-1):
        response = self._request('memory:read-utf8', {
            'address': "0x%x" % address,
            'length': length
        })
        return response['string']

    def write_utf8(self, address, string):
        self._request('memory:write-utf8', {
            'address': "0x%x" % address,
            'string': string
        })

    def create_script(self, *args, **kwargs):
        return Script(self._impl.create_script(*args, **kwargs))

    def enable_debugger(self, *args, **kwargs):
        return self._impl.enable_debugger(*args, **kwargs)

    def disable_debugger(self):
        return self._impl.disable_debugger()

    def on(self, signal, callback):
        self._impl.on(signal, callback)

    def off(self, signal, callback):
        self._impl.off(signal, callback)

    def _exec_script(self, source, post_hook=None):
        script = self.create_script(name="exec", source=source)
        return _execute_script(script, post_hook)

    def _request(self, name, payload = {}):
        result = [False, None, None]
        def on_complete(data, error):
            with self._cond:
                result[0] = True
                result[1] = data
                result[2] = error
                self._cond.notifyAll()

        with self._cond:
            request_id = self._next_request_id
            self._next_request_id += 1
            self._pending[request_id] = on_complete
            script = self._get_script()
            script.post_message({
                'id': request_id,
                'name': name,
                'payload': payload
            })
            while not result[0]:
                self._cond.wait()

        if result[2] is not None:
            raise result[2]

        return result[1]

    def _get_script(self):
        if self._script is None:
            self._script = self.create_script(name="session", source=self._create_session_script())
            self._script.on('message', self._on_message)
            self._script.load()
        return self._script

    def _on_message(self, message, data):
        if message['type'] == 'send':
            stanza = message['payload']
            callback = self._pending.pop(stanza['id'])
            name = stanza['name']
            payload = stanza['payload']
            if name == 'request:result':
                if data is None:
                    callback(payload, None)
                else:
                    callback(data, None)
            elif name == 'request:error':
                callback(None, Exception(payload))
            else:
                raise NotImplementedError("unhandled stanza")
        else:
            print("[session]", message, data)

    def _create_session_script(self):
        return """\
"use strict";

const handlers = {};

handlers['process:enumerate-modules'] = function () {
  return new Promise(function (resolve, reject) {
    const modules = [];
    Process.enumerateModules({
      onMatch: function (m) {
        modules.push(m);
      },
      onComplete: function () {
        resolve({ modules: modules });
      }
    });
  });
};

handlers['process:enumerate-module-exports'] = function (payload) {
  return new Promise(function (resolve, reject) {
    const result = payload.module_paths.map(function (modulePath) {
      const exports = [];
      Module.enumerateExports(modulePath, {
        onMatch: function (e) {
          exports.push(e);
        },
        onComplete: function () {
        }
      });
      return exports;
    });
    resolve({ exports: result });
  });
};

handlers['process:enumerate-ranges'] = function (payload) {
  return new Promise(function (resolve, reject) {
    const ranges = [];
    Process.enumerateRanges(payload.protection, {
      onMatch: function (r) {
        ranges.push(r);
      },
      onComplete: function () {
        resolve({ ranges: ranges });
      }
    });
  });
};

handlers['module:find-base-address'] = function (payload) {
  return new Promise(function (resolve, reject) {
    const address = Module.findBaseAddress(payload.module_name);
    resolve({ base_address: (address !== null) ? address : "0" });
  });
};

handlers['memory:read-byte-array'] = function (payload) {
  return new Promise(function (resolve, reject) {
    const data = Memory.readByteArray(ptr(payload.address), payload.size);
    resolve([{}, data]);
  });
};

handlers['memory:write-byte-array'] = function (payload) {
  return new Promise(function (resolve, reject) {
    const base = ptr(payload.address);
    const data = payload.data;
    for (let i = 0; i !== data.length; i++) {
      Memory.writeU8(base.add(i), data[i]);
    }
    resolve({});
  });
};

handlers['memory:read-utf8'] = function (payload) {
  return new Promise(function (resolve, reject) {
    resolve({
      string: Memory.readUtf8String(ptr(payload.address), payload.length)
    });
  });
};

handlers['memory:write-utf8'] = function (payload) {
  return new Promise(function (resolve, reject) {
    Memory.writeUtf8String(ptr(payload.address), payload.string);
    resolve({});
  });
};

handlers['module:enumerate-exports'] = function (payload) {
  return new Promise(function (resolve, reject) {
    const exports = [];
    Module.enumerateExports(payload.module_path, {
      onMatch: function (e) {
        if (e.type === 'function')
          exports.push(e);
      },
      onComplete: function () {
        resolve({ exports: exports });
      }
    });
  });
};

handlers['module:enumerate-ranges'] = function (payload) {
  return new Promise(function (resolve, reject) {
    const ranges = [];
    Module.enumerateRanges(payload.module_path, payload.protection, {
      onMatch: function (r) {
        ranges.push(r);
      },
      onComplete: function () {
        resolve({ ranges: ranges });
      }
    });
  });
};

function onStanza(stanza) {
  const handler = handlers[stanza.name];
  handler(stanza.payload)
  .then(function (result) {
    const payload = result.length === 2 ? result[0] : result;
    const data = result.length === 2 ? result[1] : null;
    send({
      id: stanza.id,
      name: 'request:result',
      payload: payload
    }, data);
  })
  .catch(function (error) {
    send({
      id: stanza.id,
      name: 'request:error',
      payload: error.stack
    });
  });

  recv(onStanza);
}
recv(onStanza);
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

    def _on_rpc_message(self, request_id, operation, params):
        if operation in ('ok', 'error'):
            callback = self._pending.pop(request_id)

            value = None
            error = None
            if operation == 'ok':
                value = params[0]
            else:
                error = Exception(params[0])

            callback(value, error)

    def _on_message(self, message, data):
        mtype = message['type']
        payload = message.get('payload', None)
        if mtype == 'log':
            level = message.get('level', 'info')
            text = payload
            self._log_handler(level, text)
        elif mtype == 'send' and isinstance(payload, list) and payload[0] == 'frida:rpc':
            request_id = payload[1]
            operation = payload[2]
            params = payload[3:]
            self._on_rpc_message(request_id, operation, params)
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
        def method(*args):
            return script._rpc_request('call', name, args)
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
            response = self._session._request('module:enumerate-exports', {
                'module_path': self.path
            })
            self._update_exports(response['exports'])
        return self._exports

    """
      @param protection example '--x'
    """
    def enumerate_ranges(self, protection):
        response = self._session._request('module:enumerate-ranges', {
            'module_path': self.path,
            'protection': protection
        })
        return [Range(int(data['base'], 16), data['size'], data['protection']) for data in response['ranges']]

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

def _execute_script(script, post_hook=None):
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
