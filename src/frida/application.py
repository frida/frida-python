# -*- coding: utf-8 -*-

import collections
from optparse import OptionParser
import os
import platform
import sys
import threading
import time

import colorama
from colorama import Style

import frida

def await_enter():
    if sys.version_info[0] >= 3:
        input()
    else:
        raw_input()

class ConsoleApplication(object):
    def __init__(self, run_until_return=await_enter):
        colorama.init()

        parser = OptionParser(usage=self._usage(), version=frida.__version__)
        parser.add_option("-U", "--usb", help="connect to USB device",
                action='store_const', const='tether', dest="device_type", default='local')
        parser.add_option("-R", "--remote", help="connect to remote device",
                action='store_const', const='remote', dest="device_type", default='local')
        if self._needs_target():
            def store_target(option, opt_str, target_value, parser, target_type, *args, **kwargs):
                if target_type == 'file':
                    target_value = [target_value]
                setattr(parser.values, 'target', (target_type, target_value))
            parser.add_option("-f", "--file", help="spawn FILE", metavar="FILE",
                type='string', action='callback', callback=store_target, callback_args=('file',))
            parser.add_option("-n", "--attach-name", help="attach to NAME", metavar="NAME",
                type='string', action='callback', callback=store_target, callback_args=('name',))
            parser.add_option("-p", "--attach-pid", help="attach to PID", metavar="PID",
                type='int', action='callback', callback=store_target, callback_args=('pid',))
            parser.add_option("--debug", help="enable the Node.js compatible script debugger",
                action='store_true', dest="enable_debugger", default=False)
        self._add_options(parser)

        (options, args) = parser.parse_args()

        self._device_type = options.device_type
        self._device = None
        self._schedule_on_device_lost = lambda: self._reactor.schedule(self._on_device_lost)
        self._spawned_pid = None
        self._spawned_argv = None
        self._session = None
        if self._needs_target():
            self._enable_debugger = options.enable_debugger
        else:
            self._enable_debugger = False
        self._schedule_on_session_detached = lambda: self._reactor.schedule(self._on_session_detached)
        self._started = False
        self._resumed = False
        self._reactor = Reactor(run_until_return)
        self._exit_status = None
        self._status_updated = False

        if self._needs_target():
            target = getattr(options, 'target', None)
            if target is None:
                if len(args) < 1:
                    parser.error("target file, process name or pid must be specified")
                target = infer_target(args[0])
                args.pop(0)
            target = expand_target(target)
            if target[0] == 'file':
                argv = target[1]
                if not os.path.isfile(argv[0]):
                    parser.error("%s: file not found" % argv[0])
                argv.extend(args)
            args = []
            self._target = target
        else:
            self._target = None

        self._initialize(parser, options, args)

    def run(self):
        mgr = frida.get_device_manager()
        on_devices_changed = lambda: self._reactor.schedule(self._try_start)
        mgr.on('changed', on_devices_changed)
        self._reactor.schedule(self._try_start)
        self._reactor.schedule(self._show_message_if_no_device, delay=0.1)
        self._reactor.run()
        if self._started:
            self._stop()
        if self._session is not None:
            self._session.off('detached', self._schedule_on_session_detached)
            self._session.detach()
            self._session = None
        if self._spawned_pid is not None:
            self._device.kill(self._spawned_pid)
        if self._device is not None:
            self._device.off('lost', self._schedule_on_device_lost)
        mgr.off('changed', on_devices_changed)
        print('before frida.shutdown')
        frida.shutdown()
        print('after frida.shutdown')
        sys.exit(self._exit_status)

    def _add_options(self, parser):
        pass

    def _initialize(self, parser, options, args):
        pass

    def _needs_target(self):
        return False

    def _start(self):
        pass

    def _stop(self):
        pass

    def _resume(self):
        if self._resumed:
            return
        if self._spawned_pid is not None:
            self._device.resume(self._spawned_pid)
        self._resumed = True

    def _exit(self, exit_status):
        self._exit_status = exit_status
        self._reactor.stop()

    def _try_start(self):
        if self._device is not None:
            return
        self._device = find_device(self._device_type)
        if self._device is None:
            return
        self._device.on('lost', self._schedule_on_device_lost)
        if self._target is not None:
            spawning = True
            try:
                target_type, target_value = self._target
                if target_type == 'file':
                    argv = target_value
                    self._update_status("Spawning `%s`..." % " ".join(argv))
                    self._spawned_pid = self._device.spawn(argv)
                    self._spawned_argv = argv
                    attach_target = self._spawned_pid
                else:
                    attach_target = target_value
                    self._update_status("Attaching...")
                spawning = False
                self._session = self._device.attach(attach_target)
                if self._enable_debugger:
                    self._session.enable_debugger()
                    self._update_status("")
                    print("Debugger listening on port 5858\n")
                    self._update_status("Attaching...")
                self._session.on('detached', self._schedule_on_session_detached)
            except Exception as e:
                if spawning:
                    self._update_status("Failed to spawn: %s" % e)
                else:
                    self._update_status("Failed to attach: %s" % e)
                self._exit(1)
                return
        self._start()
        self._started = True

    def _show_message_if_no_device(self):
        if self._device is None:
            print("Waiting for USB device to appear...")

    def _on_device_lost(self):
        if self._exit_status is not None:
            return
        print("Device disconnected.")
        self._exit(1)

    def _on_session_detached(self):
        print("Target process terminated.")
        self._exit(1)

    def _update_status(self, message):
        if self._status_updated:
            cursor_position = "\033[A"
        else:
            cursor_position = ""
        print("%-80s" % (cursor_position + Style.BRIGHT + message + Style.RESET_ALL,))
        self._status_updated = True

def find_device(type):
    for device in frida.get_device_manager().enumerate_devices():
        if device.type == type:
            return device
    return None

def infer_target(target_value):
    if target_value.startswith('.') or target_value.startswith(os.path.sep) \
            or (platform.system() == 'Windows' \
                and target_value[0].isalpha() \
                and target_value[1] == ":" \
                and target_value[2] == "\\"):
        target_type = 'file'
        target_value = [target_value]
    else:
        try:
            target_value = int(target_value)
            target_type = 'pid'
        except:
            target_type = 'name'
    return (target_type, target_value)

def expand_target(target):
    target_type, target_value = target
    if target_type == 'file':
        target_value = [os.path.abspath(target_value[0])]
    return (target_type, target_value)


class Reactor(object):
    def __init__(self, run_until_return):
        self._running = False
        self._run_until_return = run_until_return
        self._pending = collections.deque([])
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

    def run(self):
        with self._lock:
            self._running = True

        def termination_watcher():
            self._run_until_return()
            self.stop()
        watcher_thread = threading.Thread(target=termination_watcher)
        watcher_thread.daemon = True
        watcher_thread.start()

        running = True
        should_stop = False
        while running:
            now = time.time()
            work = None
            # We can't use None as then KeyboardInterrupt will not be raised from Condition.wait
            # See https://bugs.python.org/issue8844
            timeout = 1e10
            with self._lock:
                for item in self._pending:
                    (f, when) = item
                    if now >= when:
                        work = f
                        self._pending.remove(item)
                        break
                if len(self._pending) > 0:
                    timeout = max([min(map(lambda item: item[1], self._pending)) - now, 0])
            if work is not None:
                work()
            with self._lock:
                if self._running:
                    try:
                        self._cond.wait(timeout)
                    except KeyboardInterrupt:
                        should_stop = True
                running = self._running

            if should_stop:
                self.stop()
                return

    def stop(self):
        with self._lock:
            self._running = False
            self._cond.notify()

    def schedule(self, f, delay=None):
        now = time.time()
        if delay is not None:
            when = now + delay
        else:
            when = now
        with self._lock:
            self._pending.append((f, when))
            self._cond.notify()
