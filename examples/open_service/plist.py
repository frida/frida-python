import frida

device = frida.get_usb_device()

diag = device.open_service("plist:com.apple.mobile.diagnostics_relay")
diag.request({"type": "query", "payload": {"Request": "RSDCheckin", "ProtocolVersion": "2", "Label": "Frida"}})
diag.request({"type": "read"})
diag.request({"type": "query", "payload": {"Request": "Sleep", "WaitForDisconnect": True}})
diag.request({"type": "query", "payload": {"Request": "Goodbye"}})
