# -*- coding: utf-8 -*-

try:
    import unittest2 as unittest
except:
    import unittest

import frida


class TestCore(unittest.TestCase):
    def test_enumerate_devices(self):
        devices = frida.get_device_manager().enumerate_devices()
        self.assertTrue(len(devices) > 0)


if __name__ == '__main__':
    unittest.main()
