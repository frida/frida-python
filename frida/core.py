# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import fnmatch
import json
import numbers
import sys
import threading
import traceback

import _frida


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

    def enumerate_pending_spawn(self):
        return self._impl.enumerate_pending_spawn()

    def enumerate_pending_children(self):
        return self._impl.enumerate_pending_children()

    def spawn(self, program, argv=None, envp=None, env=None, cwd=None, stdio=None, **kwargs):
        if not isinstance(program, string_types):
            argv = program
            program = argv[0]
            if len(argv) == 1:
                argv = None

        aux_options = kwargs

        return self._impl.spawn(program, argv, envp, env, cwd, stdio, aux_options)

    def input(self, target, data):
        self._impl.input(self._pid_of(target), data)

    def resume(self, target):
        self._impl.resume(self._pid_of(target))

    def kill(self, target):
        self._impl.kill(self._pid_of(target))

    def attach(self, target):
        return Session(self._impl.attach(self._pid_of(target)))

    def inject_library_file(self, target, path, entrypoint, data):
        return self._impl.inject_library_file(self._pid_of(target), path, entrypoint, data)

    def inject_library_blob(self, target, blob, entrypoint, data):
        return self._impl.inject_library_blob(self._pid_of(target), blob, entrypoint, data)

    def on(self, signal, callback):
        self._impl.on(signal, callback)

    def off(self, signal, callback):
        self._impl.off(signal, callback)

    def _pid_of(self, target):
        if isinstance(target, numbers.Number):
            return target
        else:
            return self.get_process(target).pid


class Session(object):
    def __init__(self, impl):
        self._impl = impl

    def __repr__(self):
        return repr(self._impl)

    def detach(self):
        self._impl.detach()

    def enable_child_gating(self):
        self._impl.enable_child_gating()

    def disable_child_gating(self):
        self._impl.disable_child_gating()

    def create_script(self, *args, **kwargs):
        return Script(self._impl.create_script(*args, **kwargs))

    def create_script_from_bytes(self, *args, **kwargs):
        return Script(self._impl.create_script_from_bytes(*args, **kwargs))

    def compile_script(self, *args, **kwargs):
        return self._impl.compile_script(*args, **kwargs)

    def enable_debugger(self, *args, **kwargs):
        self._impl.enable_debugger(*args, **kwargs)

    def disable_debugger(self):
        self._impl.disable_debugger()

    def enable_jit(self):
        self._impl.enable_jit()

    def on(self, signal, callback):
        self._impl.on(signal, callback)

    def off(self, signal, callback):
        self._impl.off(signal, callback)


class Script(object):
    def __init__(self, impl):
        self.exports = ScriptExports(self)

        self._impl = impl

        self._on_message_callbacks = []
        self._log_handler = self._on_log

        self._pending = {}
        self._next_request_id = 1
        self._cond = threading.Condition()

        impl.on('destroyed', self._on_destroyed)
        impl.on('message', self._on_message)

    def __repr__(self):
        return repr(self._impl)

    def load(self):
        self._impl.load()

    def unload(self):
        self._impl.unload()

    def eternalize(self):
        self._impl.eternalize()

    def post(self, message, **kwargs):
        raw_message = json.dumps(message)
        self._impl.post(raw_message, **kwargs)

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
                self._cond.notify_all()

        with self._cond:
            request_id = self._next_request_id
            self._next_request_id += 1
            self._pending[request_id] = on_complete

        message = ['frida:rpc', request_id]
        message.extend(args)
        try:
            self.post(message)
        except Exception as e:
            del self._pending[request_id]
            raise

        with self._cond:
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
                error = RPCException(*params[0:3])

            callback(value, error)

    def _on_destroyed(self):
        while True:
            next_pending = None

            with self._cond:
                pending_ids = list(self._pending.keys())
                if len(pending_ids) > 0:
                    next_pending = self._pending.pop(pending_ids[0])

            if next_pending is None:
                break

            next_pending(None, _frida.InvalidOperationError('script is destroyed'))

    def _on_message(self, raw_message, data):
        message = json.loads(raw_message)

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


class RPCException(Exception):
    def __str__(self):
        return self.args[2] if len(self.args) >= 3 else self.args[0]


class ScriptExports(object):
    def __init__(self, script):
        self._script = script

    def __getattr__(self, name):
        script = self._script
        js_name = _to_camel_case(name)
        def method(*args):
            return script._rpc_request('call', js_name, args)
        return method


class Error(Exception):
    pass


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
    string_types = str,
else:
    string_types = basestring,
