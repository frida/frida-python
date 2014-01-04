import frida
from frida.core import Reactor
from frida.discoverer import Discoverer, UI
import platform
import subprocess
import threading
try:
    import unittest2 as unittest
except:
    import unittest


class TestDiscoverer(unittest.TestCase):
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
        test_ui = TestUI()
        reactor = Reactor(test_ui.on_result.wait)
        d = Discoverer(reactor)
        def start():
            d.start(self.process, test_ui)
        reactor.schedule(start)
        reactor.run()
        self.assertIsInstance(test_ui.module_functions, dict)
        self.assertIsInstance(test_ui.dynamic_functions, list)

class TestUI(UI):
    def __init__(self):
        super(UI, self).__init__()
        self.module_functions = None
        self.dynamic_functions = None
        self.on_result = threading.Event()

    def on_sample_result(self, module_functions, dynamic_functions):
        self.module_functions = module_functions
        self.dynamic_functions = dynamic_functions
        self.on_result.set()


if __name__ == '__main__':
    unittest.main()
