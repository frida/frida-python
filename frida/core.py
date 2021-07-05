# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import fnmatch
from functools import wraps
import json
import numbers
import sys
import threading
import traceback

import _frida


_Cancellable = _frida.Cancellable


def cancellable(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        cancellable = kwargs.pop('cancellable', None)
        if cancellable is not None:
            with cancellable:
                return f(*args, **kwargs)

        return f(*args, **kwargs)

    return wrapper


class DeviceManager(object):
    def __init__(self, impl):
        self._impl = impl

    def __repr__(self):
        return repr(self._impl)

    def get_local_device(self, **kwargs):
        return self.get_device_matching(lambda d: d.type == 'local', timeout=0, **kwargs)

    def get_remote_device(self, **kwargs):
        return self.get_device_matching(lambda d: d.type == 'remote', timeout=0, **kwargs)

    def get_usb_device(self, timeout=0, **kwargs):
        return self.get_device_matching(lambda d: d.type == 'usb', timeout, **kwargs)

    def get_device(self, id, timeout=0, **kwargs):
        return self.get_device_matching(lambda d: d.id == id, timeout, **kwargs)

    @cancellable
    def get_device_matching(self, predicate, timeout=0):
        if timeout < 0:
            raw_timeout = -1
        elif timeout == 0:
            raw_timeout = 0
        else:
            raw_timeout = int(timeout * 1000.0)
        return Device(self._impl.get_device_matching(lambda d: predicate(Device(d)), raw_timeout))

    @cancellable
    def enumerate_devices(self):
        return [Device(device) for device in self._impl.enumerate_devices()]

    @cancellable
    def add_remote_device(self, *args, **kwargs):
        return Device(self._impl.add_remote_device(*args, **kwargs))

    @cancellable
    def remove_remote_device(self, *args, **kwargs):
        self._impl.remove_remote_device(*args, **kwargs)

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
        self.bus = Bus(device.bus)

        self._impl = device

    def __repr__(self):
        return repr(self._impl)

    @property
    def is_lost(self):
        return self._impl.is_lost()

    @cancellable
    def query_system_parameters(self):
        return self._impl.query_system_parameters()

    @cancellable
    def get_frontmost_application(self, *args, **kwargs):
        return self._impl.get_frontmost_application(*args, **kwargs)

    @cancellable
    def enumerate_applications(self, *args, **kwargs):
        return self._impl.enumerate_applications(*args, **kwargs)

    @cancellable
    def enumerate_processes(self, *args, **kwargs):
        return self._impl.enumerate_processes(*args, **kwargs)

    @cancellable
    def get_process(self, process_name):
        process_name_lc = process_name.lower()
        matching = [process for process in self._impl.enumerate_processes() if fnmatch.fnmatchcase(process.name.lower(), process_name_lc)]
        if len(matching) == 1:
            return matching[0]
        elif len(matching) > 1:
            raise _frida.ProcessNotFoundError("ambiguous name; it matches: %s" % ", ".join(["%s (pid: %d)" % (process.name, process.pid) for process in matching]))
        else:
            raise _frida.ProcessNotFoundError("unable to find process with name '%s'" % process_name)

    @cancellable
    def enable_spawn_gating(self):
        return self._impl.enable_spawn_gating()

    @cancellable
    def disable_spawn_gating(self):
        return self._impl.disable_spawn_gating()

    @cancellable
    def enumerate_pending_spawn(self):
        return self._impl.enumerate_pending_spawn()

    @cancellable
    def enumerate_pending_children(self):
        return self._impl.enumerate_pending_children()

    @cancellable
    def spawn(self, program, argv=None, envp=None, env=None, cwd=None, stdio=None, **kwargs):
        if not isinstance(program, string_types):
            argv = program
            program = argv[0]
            if len(argv) == 1:
                argv = None

        aux_options = kwargs

        return self._impl.spawn(program, argv, envp, env, cwd, stdio, aux_options)

    @cancellable
    def input(self, target, data):
        self._impl.input(self._pid_of(target), data)

    @cancellable
    def resume(self, target):
        self._impl.resume(self._pid_of(target))

    @cancellable
    def kill(self, target):
        self._impl.kill(self._pid_of(target))

    @cancellable
    def attach(self, target, *args, **kwargs):
        return Session(self._impl.attach(self._pid_of(target), *args, **kwargs))

    @cancellable
    def inject_library_file(self, target, path, entrypoint, data):
        return self._impl.inject_library_file(self._pid_of(target), path, entrypoint, data)

    @cancellable
    def inject_library_blob(self, target, blob, entrypoint, data):
        return self._impl.inject_library_blob(self._pid_of(target), blob, entrypoint, data)

    @cancellable
    def open_channel(self, address):
        return IOStream(self._impl.open_channel(address))

    @cancellable
    def get_bus(self):
        return Bus(self._impl.get_bus())

    def on(self, signal, callback):
        self._impl.on(signal, callback)

    def off(self, signal, callback):
        self._impl.off(signal, callback)

    def _pid_of(self, target):
        if isinstance(target, numbers.Number):
            return target
        else:
            return self.get_process(target).pid


class Bus(object):
    def __init__(self, impl):
        self._impl = impl
        self._on_message_callbacks = []

        impl.on('message', self._on_message)

    @cancellable
    def attach(self):
        self._impl.attach()

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

    def _on_message(self, raw_message, data):
        message = json.loads(raw_message)

        for callback in self._on_message_callbacks[:]:
            try:
                callback(message, data)
            except:
                traceback.print_exc()


class Session(object):
    def __init__(self, impl):
        self._impl = impl

    def __repr__(self):
        return repr(self._impl)

    @property
    def is_detached(self):
        return self._impl.is_detached()

    @cancellable
    def detach(self):
        self._impl.detach()

    @cancellable
    def resume(self):
        self._impl.resume()

    @cancellable
    def enable_child_gating(self):
        self._impl.enable_child_gating()

    @cancellable
    def disable_child_gating(self):
        self._impl.disable_child_gating()

    @cancellable
    def create_script(self, *args, **kwargs):
        return Script(self._impl.create_script(*args, **kwargs))

    @cancellable
    def create_script_from_bytes(self, *args, **kwargs):
        return Script(self._impl.create_script_from_bytes(*args, **kwargs))

    @cancellable
    def compile_script(self, *args, **kwargs):
        return self._impl.compile_script(*args, **kwargs)

    @cancellable
    def enable_debugger(self, *args, **kwargs):
        self._impl.enable_debugger(*args, **kwargs)

    @cancellable
    def disable_debugger(self):
        self._impl.disable_debugger()

    @cancellable
    def setup_peer_connection(self, *args, **kwargs):
        self._impl.setup_peer_connection(*args, **kwargs)

    @cancellable
    def join_portal(self, *args, **kwargs):
        return PortalMembership(self._impl.join_portal(*args, **kwargs))

    def on(self, signal, callback):
        self._impl.on(signal, callback)

    def off(self, signal, callback):
        self._impl.off(signal, callback)


class Script(object):
    def __init__(self, impl):
        self.exports = ScriptExports(self)

        self._impl = impl

        self._on_message_callbacks = []
        self._log_handler = self.default_log_handler

        self._pending = {}
        self._next_request_id = 1
        self._cond = threading.Condition()

        impl.on('destroyed', self._on_destroyed)
        impl.on('message', self._on_message)

    def __repr__(self):
        return repr(self._impl)

    @property
    def is_destroyed(self):
        return self._impl.is_destroyed()

    @cancellable
    def load(self):
        self._impl.load()

    @cancellable
    def unload(self):
        self._impl.unload()

    @cancellable
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

    def get_log_handler(self):
        return self._log_handler

    def set_log_handler(self, handler):
        self._log_handler = handler

    def default_log_handler(self, level, text):
        if level == 'info':
            print(text, file=sys.stdout)
        else:
            print(text, file=sys.stderr)

    def list_exports(self):
        return self._rpc_request('list')

    @cancellable
    def _rpc_request(self, *args):
        result = [False, None, None]

        def on_complete(value, error):
            with self._cond:
                result[0] = True
                result[1] = value
                result[2] = error
                self._cond.notify_all()

        def on_cancelled():
            self._pending.pop(request_id, None)
            on_complete(None, None)

        with self._cond:
            request_id = self._next_request_id
            self._next_request_id += 1
            self._pending[request_id] = on_complete

        if not self.is_destroyed:
            message = ['frida:rpc', request_id]
            message.extend(args)
            self.post(message)

            cancellable = Cancellable.get_current()
            cancel_handler = cancellable.connect(on_cancelled)
            try:
                with self._cond:
                    while not result[0]:
                        self._cond.wait()
            finally:
                cancellable.disconnect(cancel_handler)

            cancellable.raise_if_cancelled()
        else:
            self._on_destroyed()

        if result[2] is not None:
            raise result[2]

        return result[1]

    def _on_rpc_message(self, request_id, operation, params, data):
        if operation in ('ok', 'error'):
            callback = self._pending.pop(request_id, None)
            if callback is None:
                return

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

            next_pending(None, _frida.InvalidOperationError('script has been destroyed'))

    def _on_message(self, raw_message, data):
        message = json.loads(raw_message)

        mtype = message['type']
        payload = message.get('payload', None)
        if mtype == 'log':
            level = message['level']
            text = payload
            self._log_handler(level, text)
        elif mtype == 'send' and isinstance(payload, list) and len(payload) > 0 and payload[0] == 'frida:rpc':
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


class RPCException(Exception):
    def __str__(self):
        return self.args[2] if len(self.args) >= 3 else self.args[0]


class ScriptExports(object):
    def __init__(self, script):
        self._script = script

    def __getattr__(self, name):
        script = self._script
        js_name = _to_camel_case(name)
        def method(*args, **kwargs):
            return script._rpc_request('call', js_name, args, **kwargs)
        return method

    def __dir__(self):
        return self._script.list_exports()


class PortalMembership(object):
    def __init__(self, impl):
        self._impl = impl

    @cancellable
    def terminate(self):
        self._impl.terminate()


class EndpointParameters(object):
    def __init__(self, address=None, port=None, certificate=None, origin=None, authentication=None, asset_root=None):
        kw = {}

        if address is not None:
            kw['address'] = address

        if port is not None:
            kw['port'] = port

        if certificate is not None:
            kw['certificate'] = certificate

        if origin is not None:
            kw['origin'] = origin

        if authentication is not None:
            (auth_scheme, auth_data) = authentication
            if auth_scheme == 'token':
                kw['auth_token'] = auth_data
            elif auth_scheme == 'callback':
                kw['auth_callback'] = make_auth_callback(auth_data)
            else:
                raise ValueError("invalid authentication scheme")

        if asset_root is not None:
            kw['asset_root'] = str(asset_root)

        self._impl = _frida.EndpointParameters(**kw)


class PortalService(object):
    def __init__(self, cluster_params=EndpointParameters(), control_params=None):
        args = [cluster_params._impl]
        if control_params is not None:
            args.append(control_params._impl)
        impl = _frida.PortalService(*args)

        self.device = impl.device
        self._impl = impl
        self._on_authenticated_callbacks = []
        self._on_message_callbacks = []

        impl.on('authenticated', self._on_authenticated)
        impl.on('message', self._on_message)

    @cancellable
    def start(self):
        self._impl.start()

    @cancellable
    def stop(self):
        self._impl.stop()

    def post(self, connection_id, message, **kwargs):
        raw_message = json.dumps(message)
        self._impl.post(connection_id, raw_message, **kwargs)

    def narrowcast(self, tag, message, **kwargs):
        raw_message = json.dumps(message)
        self._impl.narrowcast(tag, raw_message, **kwargs)

    def broadcast(self, message, **kwargs):
        raw_message = json.dumps(message)
        self._impl.broadcast(raw_message, **kwargs)

    def enumerate_tags(self, connection_id):
        return self._impl.enumerate_tags(connection_id)

    def tag(self, connection_id, tag):
        self._impl.tag(connection_id, tag)

    def untag(self, connection_id, tag):
        self._impl.untag(connection_id, tag)

    def on(self, signal, callback):
        if signal == 'authenticated':
            self._on_authenticated_callbacks.append(callback)
        elif signal == 'message':
            self._on_message_callbacks.append(callback)
        else:
            self._impl.on(signal, callback)

    def off(self, signal, callback):
        if signal == 'authenticated':
            self._on_authenticated_callbacks.remove(callback)
        elif signal == 'message':
            self._on_message_callbacks.remove(callback)
        else:
            self._impl.off(signal, callback)

    def _on_authenticated(self, connection_id, raw_session_info):
        session_info = json.loads(raw_session_info)

        for callback in self._on_authenticated_callbacks[:]:
            try:
                callback(connection_id, session_info)
            except:
                traceback.print_exc()

    def _on_message(self, connection_id, raw_message, data):
        message = json.loads(raw_message)

        for callback in self._on_message_callbacks[:]:
            try:
                callback(connection_id, message, data)
            except:
                traceback.print_exc()


class IOStream(object):
    def __init__(self, impl):
        self._impl = impl

    def __repr__(self):
        return repr(self._impl)

    @property
    def is_closed(self):
        return self._impl.is_closed()

    @cancellable
    def close(self):
        self._impl.close()

    @cancellable
    def read(self, count):
        return self._impl.read(count)

    @cancellable
    def read_all(self, count):
        return self._impl.read_all(count)

    @cancellable
    def write(self, data):
        return self._impl.write(data)

    @cancellable
    def write_all(self, data):
        self._impl.write_all(data)


class Cancellable(object):
    def __init__(self):
        self._impl = _Cancellable()

    def __repr__(self):
        return repr(self._impl)

    @property
    def is_cancelled(self):
        return self._impl.is_cancelled()

    def raise_if_cancelled(self):
        self._impl.raise_if_cancelled()

    def get_pollfd(self):
        return CancellablePollFD(self._impl)

    @classmethod
    def get_current(cls):
        return _Cancellable.get_current()

    def __enter__(self):
        self._impl.push_current()

    def __exit__(self, *args):
        self._impl.pop_current()

    def connect(self, callback):
        return self._impl.connect(callback)

    def disconnect(self, handler_id):
        self._impl.disconnect(handler_id)

    def cancel(self):
        self._impl.cancel()


class CancellablePollFD(object):
    def __init__(self, cancellable):
        self.handle = cancellable.get_fd()
        self._cancellable = cancellable

    def __del__(self):
        self.release()

    def release(self):
        if self._cancellable is not None:
            if self.handle != -1:
                self._cancellable.release_fd()
                self.handle = -1
            self._cancellable = None

    def __repr__(self):
        return repr(self.handle)

    def __enter__(self):
        return self.handle

    def __exit__(self, *args):
        self.release()


def make_auth_callback(callback):
    def authenticate(token):
        session_info = callback(token)
        return json.dumps(session_info)
    return authenticate


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
