# -*- coding: utf-8 -*-
from __future__ import print_function


def main():
    import frida
    from frida.application import ConsoleApplication, infer_target, expand_target

    class KillApplication(ConsoleApplication):
        def _usage(self):
            return "usage: %prog [options] process"

        def _start(self):
            try:
                self._device.kill(self._process)
            except frida.ProcessNotFoundError:
                self._update_status('unable to find process: %s' % self._process)
                self._exit(1)
            self._exit(0)

        def _initialize(self, parser, options, args):
            if len(args) < 1:
                parser.error('process name or pid must be specified')
            process = expand_target(infer_target(args[0]))
            if process[0] == 'file':
                parser.error('process name or pid must be specified')

            self._process = process[1]

    app = KillApplication()
    app.run()


if __name__ == '__main__':
    main()
