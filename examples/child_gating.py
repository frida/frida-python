# -*- coding: utf-8 -*-
from __future__ import print_function
import frida
import sys

def on_delivered(child):
    print("on_delivered:", child)

device = frida.get_local_device()
device.on('delivered', on_delivered)

pid = device.spawn(["/bin/sh", "-c", "ls /"])
session = device.attach(pid)
session.enable_child_gating()
device.resume(pid)

sys.stdin.read()
