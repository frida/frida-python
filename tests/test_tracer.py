# -*- coding: utf-8 -*-

import frida
from frida.core import Reactor
from frida.tracer import Tracer, TracerProfileBuilder, MemoryRepository, UI
import platform
import subprocess
import threading
try:
    import unittest2 as unittest
except:
    import unittest


class TestTracer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        system = platform.system()
        if system == 'Windows':
            cls.target = subprocess.Popen([r"C:\Windows\notepad.exe"])
        else:
            cls.target = subprocess.Popen(["/bin/cat"])
        cls.process = frida.attach(cls.target.pid)

    @classmethod
    def tearDownClass(cls):
        cls.process.detach()
        cls.target.terminate()

    def test_basics(self):
        never = threading.Event()
        reactor = Reactor(never.wait)
        def start():
            tp = TracerProfileBuilder().include("open*")
            t = Tracer(reactor, MemoryRepository(), tp.build())
            targets = t.start_trace(self.process, UI())
            t.stop()
            reactor.stop()
        reactor.schedule(start)
        reactor.run()


if __name__ == '__main__':
    unittest.main()
