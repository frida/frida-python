# -*- coding: utf-8 -*-

import platform
import subprocess
import sys
import threading
import time
try:
    import unittest2 as unittest
except:
    import unittest

import frida

from .data import target_program


class TestRpc(unittest.TestCase):
    @classmethod
    def setUp(cls):
        system = platform.system()
        cls.target = subprocess.Popen([target_program], stdin=subprocess.PIPE)
        cls.session = frida.attach(cls.target.pid)

    @classmethod
    def tearDown(cls):
        cls.session.detach()
        cls.target.terminate()
        cls.target.stdin.close()
        cls.target.wait()

    def test_basics(self):
        script = self.session.create_script(name="test-rpc", source="""\
"use strict";

rpc.exports = {
    add: function (a, b) {
        var result = a + b;
        if (result < 0)
          throw new Error("No");
        return result;
    },
    sub: function (a, b) {
        return a - b;
    },
    speak: function () {
        var buf = Memory.allocUtf8String("Yo");
        return Memory.readByteArray(buf, 2);
    }
};
""")
        script.load()
        self.assertEqual(script.exports.add(2, 3), 5)
        self.assertEqual(script.exports.sub(5, 3), 2)
        self.assertRaises(Exception, lambda: script.exports.add(1, -2))
        self.assertListEqual([x for x in iterbytes(script.exports.speak())],
            [0x59, 0x6f])

    def test_post_failure(self):
        script = self.session.create_script(name="test-rpc", source="""\
"use strict";

rpc.exports = {
    init: function () {
    },
};
""")
        script.load()
        agent = script.exports

        self.session.detach()
        self.assertRaisesScriptDestroyed(lambda: agent.init())
        self.assertEqual(script._pending, {})

    def test_unload_mid_request(self):
        script = self.session.create_script(name="test-rpc", source="""\
"use strict";

rpc.exports = {
    waitForever: function () {
        return new Promise(function () {});
    },
};
""")
        script.load()
        agent = script.exports

        def unload_script_after_100ms():
            time.sleep(0.1)
            script.unload()

        threading.Thread(target=unload_script_after_100ms).start()
        self.assertRaisesScriptDestroyed(lambda: agent.wait_forever())
        self.assertEqual(script._pending, {})

    def test_detach_mid_request(self):
        script = self.session.create_script(name="test-rpc", source="""\
"use strict";

rpc.exports = {
    waitForever: function () {
        return new Promise(function () {});
    },
};
""")
        script.load()
        agent = script.exports

        def terminate_target_after_100ms():
            time.sleep(0.1)
            self.target.terminate()

        threading.Thread(target=terminate_target_after_100ms).start()
        self.assertRaisesScriptDestroyed(lambda: agent.wait_forever())
        self.assertEqual(script._pending, {})

    def assertRaisesScriptDestroyed(self, operation):
        m = self.assertRaisesRegex if sys.version_info[0] >= 3 else self.assertRaisesRegexp
        m(frida.InvalidOperationError, "script is destroyed", operation)


if sys.version_info[0] >= 3:
    iterbytes = lambda x: iter(x)
else:
    def iterbytes(data):
        return (ord(char) for char in data)


if __name__ == '__main__':
    unittest.main()
