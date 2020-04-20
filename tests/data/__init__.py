# -*- coding: utf-8 -*-

import os
import platform
import sys


system = platform.system()
if system == 'Windows':
    target_program = r"C:\Windows\notepad.exe"
elif system == 'Darwin':
    target_program = os.path.join(os.path.dirname(__file__), "unixvictim-macos")
else:
    arch = "x86_64" if sys.maxsize > 2**32 else "x86"
    target_program = os.path.join(os.path.dirname(__file__), "unixvictim-linux-" + arch)


__all__ = ['target_program']
