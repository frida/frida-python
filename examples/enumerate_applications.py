# -*- coding: utf-8 -*-
from __future__ import print_function
import frida
from pprint import pformat
from pygments import highlight
from pygments.formatters import Terminal256Formatter
from pygments.lexers import PythonLexer


device = frida.get_usb_device()

def trim_icon(icon):
    result = dict(icon)
    result['image'] = result['image'][0:16] + b"..."
    return result

apps = device.enumerate_applications(scope='full')
for app in apps:
    params = dict(app.parameters)
    if 'icons' in params:
        params['icons'] = [trim_icon(icon) for icon in params['icons']]
    print("Application(identifier=\"{}\", name=\"{}\", pid={}, parameters={})".format(
        app.identifier,
        app.name,
        app.pid,
        highlight(pformat(params), PythonLexer(), Terminal256Formatter()).rstrip()))
