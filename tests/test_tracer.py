import frida
from frida.tracer import Tracer, TracerProfileBuilder, STDOUT_SINK
import platform
import subprocess
try:
    import unittest2 as unittest
except:
    import unittest


class TestTracer(unittest.TestCase):
    def setUp(self):
        system = platform.system()
        if system == 'Windows':
            self.target = subprocess.Popen([r"C:\Windows\notepad.exe"])
        else:
            self.target = subprocess.Popen(["/bin/cat"])
        self.process = frida.attach(self.target.pid)

    def tearDown(self):
        self.process.detach()
        self.target.terminate()

    def test_basics(self):
        tp = TracerProfileBuilder().include("open*")
        t = Tracer(tp.build())
        targets = t.start_trace(self.process, STDOUT_SINK)
        t.stop()


if __name__ == '__main__':
    unittest.main()
