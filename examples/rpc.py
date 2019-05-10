# -*- coding: utf-8 -*-
from __future__ import print_function

import frida


session = frida.attach("Twitter")
script = session.create_script("""\
rpc.exports = {
  hello: function () {
    return 'Hello';
  },
  failPlease: function () {
    oops;
  }
};
""")
script.load()
api = script.exports
print("api.hello() =>", api.hello())
api.fail_please()
