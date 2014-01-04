import frida
from frida.tracer import Tracer, TracerProfileBuilder, STDOUT_SINK
import platform
import subprocess
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
        tp = TracerProfileBuilder().include("open*")
        t = Tracer(tp.build())
        targets = t.start_trace(self.process, STDOUT_SINK)
        t.stop()


if __name__ == '__main__':
    unittest.main()
