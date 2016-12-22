# -*- coding: utf-8 -*-

from .data import target_program
import platform
import subprocess
import threading
try:
    import unittest2 as unittest
except:
    import unittest

import frida
from frida.application import Reactor
from frida.tracer import Tracer, TracerProfileBuilder, MemoryRepository, UI


class TestTracer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        system = platform.system()
        cls.target = subprocess.Popen([target_program], stdin=subprocess.PIPE)
        cls.session = frida.attach(cls.target.pid)

    @classmethod
    def tearDownClass(cls):
        cls.session.detach()
        cls.target.terminate()

    def test_basics(self):
        done = threading.Event()
        reactor = Reactor(lambda reactor: done.wait())
        def start():
            tp = TracerProfileBuilder().include("open*")
            t = Tracer(reactor, MemoryRepository(), tp.build())
            targets = t.start_trace(self.session, UI())
            t.stop()
            reactor.stop()
            done.set()
        reactor.schedule(start)
        reactor.run()


if __name__ == '__main__':
    unittest.main()
