# -*- coding: utf-8 -*-

import collections
from optparse import OptionParser
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
        colorama.init(autoreset=True)

        parser = OptionParser(usage=self._usage())
        parser.add_option("-U", "--usb", help="connect to USB device",
                action='store_const', const='tether', dest="device_type", default='local')
        parser.add_option("-R", "--remote", help="connect to remote device",
                action='store_const', const='remote', dest="device_type", default='local')
        self._add_options(parser)

        (options, args) = parser.parse_args()

        self._device_type = options.device_type
        self._device = None
        self._schedule_on_device_lost = lambda: self._reactor.schedule(self._on_device_lost)
        self._target = None
        self._process = None
        self._schedule_on_process_detached = lambda: self._reactor.schedule(self._on_process_detached)
        self._started = False
        self._reactor = Reactor(run_until_return)
        self._exit_status = None
        self._status_updated = False

        self._initialize(parser, options, args)

        target_specifier = self._target_specifier(parser, options, args)
        if target_specifier is not None:
            try:
                self._target = int(target_specifier)
            except:
                self._target = target_specifier
        else:
            self._target = None

    def run(self):
        mgr = frida.get_device_manager()
        on_devices_changed = lambda: self._reactor.schedule(self._try_start)
        mgr.on('changed', on_devices_changed)
        self._reactor.schedule(self._try_start)
        self._reactor.schedule(self._show_message_if_no_device, delay=0.1)
        self._reactor.run()
        if self._started:
            self._stop()
        if self._process is not None:
            self._process.off('detached', self._schedule_on_process_detached)
            self._process.detach()
            self._process = None
        if self._device is not None:
            self._device.off('lost', self._schedule_on_device_lost)
        mgr.off('changed', on_devices_changed)
        frida.shutdown()
        sys.exit(self._exit_status)

    def _add_options(self, parser):
        pass

    def _initialize(self, parser, options, args):
        pass

    def _target_specifier(self, parser, options, args):
        return None

    def _start(self):
        pass

    def _stop(self):
        pass

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
            try:
                self._update_status("Attaching...")
                self._process = self._device.attach(self._target)
                self._process.on('detached', self._schedule_on_process_detached)
            except Exception as e:
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

    def _on_process_detached(self):
        print("Target process terminated.")
        self._exit(1)

    def _update_status(self, message):
        if self._status_updated:
            cursor_position = "\033[A"
        else:
            cursor_position = ""
        print("%-80s" % (cursor_position + Style.BRIGHT + message,))
        self._status_updated = True

def find_device(type):
    for device in frida.get_device_manager().enumerate_devices():
        if device.type == type:
            return device
    return None


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
        while running:
            now = time.time()
            work = None
            timeout = None
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
                    self._cond.wait(timeout)
                running = self._running

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
