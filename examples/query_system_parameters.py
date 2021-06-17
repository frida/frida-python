# -*- coding: utf-8 -*-
from __future__ import print_function
import frida


print("Local parameters:", frida.query_system_parameters())
print("USB device parameters:", frida.get_usb_device().query_system_parameters())
