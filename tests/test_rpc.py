import subprocess
import threading
import time
import unittest

import frida

from .data import target_program


class TestRpc(unittest.TestCase):
    target: subprocess.Popen
    session: frida.core.Session

    @classmethod
    def setUp(cls):
        cls.target = subprocess.Popen([target_program], stdin=subprocess.PIPE)
        # TODO: improve injectors to handle injection into a process that hasn't yet finished initializing
        time.sleep(0.05)
        cls.session = frida.attach(cls.target.pid)

    @classmethod
    def tearDown(cls):
        cls.session.detach()
        cls.target.terminate()
        cls.target.stdin.close()
        cls.target.wait()

    def test_basics(self):
        script = self.session.create_script(
            name="test-rpc",
            source="""\
rpc.exports = {
    add(a, b) {
        const result = a + b;
        if (result < 0)
            throw new Error("No");
        return result;
    },
    sub(a, b) {
        return a - b;
    },
    speak() {
        const buf = Memory.allocUtf8String("Yo");
        return Memory.readByteArray(buf, 2);
    },
    speakWithMetadata() {
        const buf = Memory.allocUtf8String("Yo");
        return ['soft', Memory.readByteArray(buf, 2)];
    },
    processData(val, data) {
        return { val, dump: hexdump(data, { header: false }) };
    },
};
""",
        )
        script.load()
        agent = script.exports_sync
        self.assertEqual(agent.add(2, 3), 5)
        self.assertEqual(agent.sub(5, 3), 2)
        self.assertRaises(Exception, lambda: agent.add(1, -2))
        self.assertEqual(agent.speak(), b"\x59\x6f")
        meta, data = agent.speak_with_metadata()
        self.assertEqual(meta, "soft")
        self.assertEqual(data, b"\x59\x6f")
        result = agent.process_data(1337, b"\x13\x37")
        self.assertEqual(result["val"], 1337)
        self.assertEqual(result["dump"], "00000000  13 37                                            .7")

    def test_post_failure(self):
        script = self.session.create_script(
            name="test-rpc",
            source="""\
rpc.exports = {
    init: function () {
    },
};
""",
        )
        script.load()
        agent = script.exports_sync

        self.session.detach()
        self.assertRaisesScriptDestroyed(lambda: agent.init())
        self.assertEqual(script._pending, {})

    def test_unload_mid_request(self):
        script = self.session.create_script(
            name="test-rpc",
            source="""\
rpc.exports = {
    waitForever: function () {
        return new Promise(function () {});
    },
};
""",
        )
        script.load()
        agent = script.exports_sync

        def unload_script_after_100ms():
            time.sleep(0.1)
            script.unload()

        threading.Thread(target=unload_script_after_100ms).start()
        self.assertRaisesScriptDestroyed(lambda: agent.wait_forever())
        self.assertEqual(script._pending, {})

    def test_detach_mid_request(self):
        script = self.session.create_script(
            name="test-rpc",
            source="""\
rpc.exports = {
    waitForever: function () {
        return new Promise(function () {});
    },
};
""",
        )
        script.load()
        agent = script.exports_sync

        def terminate_target_after_100ms():
            time.sleep(0.1)
            self.target.terminate()

        threading.Thread(target=terminate_target_after_100ms).start()
        self.assertRaisesScriptDestroyed(lambda: agent.wait_forever())
        self.assertEqual(script._pending, {})

    def test_cancellation_mid_request(self):
        script = self.session.create_script(
            name="test-rpc",
            source="""\
rpc.exports = {
    waitForever: function () {
        return new Promise(function () {});
    },
};
""",
        )
        script.load()
        agent = script.exports_sync

        def cancel_after_100ms():
            time.sleep(0.1)
            cancellable.cancel()

        cancellable = frida.Cancellable()
        threading.Thread(target=cancel_after_100ms).start()
        self.assertRaisesOperationCancelled(lambda: agent.wait_forever(cancellable=cancellable))
        self.assertEqual(script._pending, {})

        def call_wait_forever_with_cancellable():
            with cancellable:
                agent.wait_forever()

        cancellable = frida.Cancellable()
        threading.Thread(target=cancel_after_100ms).start()
        self.assertRaisesOperationCancelled(call_wait_forever_with_cancellable)
        self.assertEqual(script._pending, {})

    def assertRaisesScriptDestroyed(self, operation):
        self.assertRaisesRegex(frida.InvalidOperationError, "script has been destroyed", operation)

    def assertRaisesOperationCancelled(self, operation):
        self.assertRaisesRegex(frida.OperationCancelledError, "operation was cancelled", operation)


if __name__ == "__main__":
    unittest.main()
