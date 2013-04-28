import _frida
import fnmatch
import threading


def spawn(command_line, device_id = None):
    return get_device_manager().get_device(device_id).spawn(command_line)

def resume(target, device_id = None):
    return get_device_manager().get_device(device_id).resume(target)

def attach(target, device_id = None):
    return get_device_manager().get_device(device_id).attach(target)


global _device_manager
_device_manager = None
def get_device_manager():
    global _device_manager
    if _device_manager is None:
        _device_manager = DeviceManager(_frida.DeviceManager())
        _device_manager.enumerate_devices() # warm up
    return _device_manager


class DeviceManager:
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
        raise ValueError, "device not found"

    def on(self, signal, callback):
        self._manager.on(signal, callback)

    def off(self, signal, callback):
        self._manager.off(signal, callback)

class Device:
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
        matching = [process for process in self._device.enumerate_processes() if fnmatch.fnmatchcase(process.name, process_name)]
        if len(matching) == 1:
            return matching[0]
        elif len(matching) > 1:
            raise ValueError, "ambiguous name; it matches: %s" % ", ".join(["%s (pid: %d)" % (process.name, process.pid) for process in matching])
        else:
            raise ValueError, "process not found"

    def spawn(self, command_line):
        return self._device.spawn(command_line)

    def resume(self, target):
        return self._device.resume(self._pid_of(target))

    def attach(self, target):
        return Session(self._device.attach(self._pid_of(target)))

    def on(self, signal, callback):
        self._device.on(signal, callback)

    def off(self, signal, callback):
        self._device.off(signal, callback)

    def _pid_of(self, target):
        if isinstance(target, basestring):
            return self.get_process(target).pid
        else:
            return target

class Session:
    def __init__(self, session):
        self._session = session

    def detach(self):
        self._session.detach()

    def enumerate_modules(self):
        script = self._session.create_script(
"""
var modules = [];
Process.enumerateModules({
    onMatch: function(name, address, path) {
        modules.push({name: name, address: address.toString(), path: path});
    },
    onComplete: function() {
        send(modules);
    }
});
""")
        return [Module(data['name'], int(data['address']), data['path'], self._session) for data in _execute_script(script)]

    """
      @param protection example '--x'
    """
    def enumerate_ranges(self, protection):
        script = self._session.create_script(
"""
var ranges = [];
Process.enumerateRanges(\"%s\", {
    onMatch: function(address, size, protection) {
        ranges.push({address: address.toString(), size: size, protection: protection});
    },
    onComplete: function() {
        send(ranges);
    }
});
""" % protection)
        return [Range(int(data['address']), data['size'], data['protection']) for data in _execute_script(script)]

    def _exec_script(self, script_source, post_hook = None):
        script = self._session.create_script(script_source)
        return _execute_script(script, post_hook)

    def find_base_address(self, module_name):
        return int(self._exec_script("send(Module.findBaseAddress(\"%s\").toString());" % module_name))

    def read_bytes(self, address, length):
        return self._exec_script("send(null, Memory.readByteArray(ptr(\"%u\"), %u));" % (address, length))

    def read_utf8(self, address, length = -1):
        return self._exec_script("send(Memory.readUtf8String(ptr(\"%u\"), %u));" % (address, length))

    def write_bytes(self, address, bytes):
        script = \
"""
recv(function(bytes) {
    var base = ptr("%u");
    for (var i = 0; i < bytes.length; i++)
        Memory.writeU8(base.add(i), bytes[i]);
    send(true);
});
""" % address

        def send_data(script):
            script.post_message([ord(x) for x in bytes])

        return self._exec_script(script, send_data)

    def write_utf8(self, address, string):
        script = \
"""
recv(function(string) {
    Memory.writeUtf8String(ptr("%u"), string);
    send(true);
});
""" % address

        def send_data(script):
            script.post_message(string)

        return self._exec_script(script, send_data)

    def on(self, signal, callback):
        self._session.on(signal, callback)

    def off(self, signal, callback):
        self._session.off(signal, callback)

class Module:
    def __init__(self, name, address, path, _session):
        self.name = name
        self.address = address
        self.path = path
        self._session = _session

    def __repr__(self):
        return "Module(name=\"%s\", address=%s, path=\"%s\")" % (self.name, self.address, self.path)

    def enumerate_exports(self):
        script = self._session.create_script(
"""
var exports = [];
Module.enumerateExports(\"%s\", {
    onMatch: function(name, address) {
        exports.push({name: name, address: address.toString()});
    },
    onComplete: function() {
        send(exports);
    }
});
""" % self.name)
        return [Export(export["name"], int(export["address"])) for export in _execute_script(script)]

    """
      @param protection example '--x'
    """
    def enumerate_ranges(self, protection):
        script = self._session.create_script(
"""
var ranges = [];
Module.enumerateRanges(\"%s\", \"%s\", {
    onMatch: function(address, size, protection) {
        ranges.push({address: address.toString(), size: size, protection: protection});
    },
    onComplete: function() {
        send(ranges);
    }
});
""" % (self.name, protection))
        return [Range(int(data['address']), data['size'], data['protection']) for data in _execute_script(script)]

class Export:
    def __init__(self, name, address):
        self.name = name
        self.address = address

    def __repr__(self):
        return "Export(name=\"%s\", address=%s)" % (self.name, self.address)

class Range:
    def __init__(self, address, size, protection):
        self.address = address
        self.size = size
        self.protection = protection

    def __repr__(self):
        return "Range(address=%s, size=%s, protection='%s')" % (self.address, self.size, self.protection)

class Error(Exception):
    pass

def _execute_script(script, post_hook = None):
    def msg(message, data):
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

    script.on('message', msg)
    script.load()
    if post_hook:
        post_hook(script)
    event.wait()
    script.unload()

    if 'error' in result:
        raise Error, result['error']

    return result['data']
