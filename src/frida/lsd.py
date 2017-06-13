# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

def main():
    import frida
    from frida.application import ConsoleApplication

    class LSDApplication(ConsoleApplication):
        def _usage(self):
            return "usage: %prog [options]"

        def _needs_device(self):
            return False

        def _start(self):
            try:
                devices = frida.enumerate_devices()
            except Exception as e:
                self._update_status("Failed to enumerate devices: %s" % e)
                self._exit(1)
                return
            id_column_width = max(map(lambda device: len(device.id), devices))
            type_column_width = max(map(lambda device: len(device.type), devices))
            name_column_width = max(map(lambda device: len(device.name), devices))
            header_format = "%-" + str(id_column_width) + "s  " + \
                "%-" + str(type_column_width) + "s  " + \
                "%-" + str(name_column_width) + "s"
            self._print(header_format % ("Id", "Type", "Name"))
            self._print("%s  %s  %s" % (id_column_width * "-", type_column_width * "-", name_column_width * "-"))
            line_format = "%-" + str(id_column_width) + "s  " + \
                "%-" + str(type_column_width) + "s  " + \
                "%-" + str(name_column_width) + "s"
            for device in sorted(devices, key=cmp_to_key(compare_devices)):
                self._print(line_format % (device.id, device.type, device.name))
            self._exit(0)

    def compare_devices(a, b):
        a_score = score(a)
        b_score = score(b)
        if a_score == b_score:
            if a.name > b.name:
                return 1
            elif a.name < b.name:
                return -1
            else:
                return 0
        else:
            if a_score > b_score:
                return -1
            elif a_score < b_score:
                return 1
            else:
                return 0

    def score(device):
        type = device.type
        if type == 'local':
            return 3
        elif type == 'tether':
            return 2
        else:
            return 1

    def cmp_to_key(mycmp):
        "Convert a cmp= function into a key= function"
        class K:
            def __init__(self, obj, *args):
                self.obj = obj
            def __lt__(self, other):
                return mycmp(self.obj, other.obj) < 0
            def __gt__(self, other):
                return mycmp(self.obj, other.obj) > 0
            def __eq__(self, other):
                return mycmp(self.obj, other.obj) == 0
            def __le__(self, other):
                return mycmp(self.obj, other.obj) <= 0
            def __ge__(self, other):
                return mycmp(self.obj, other.obj) >= 0
            def __ne__(self, other):
                return mycmp(self.obj, other.obj) != 0
        return K

    device = LSDApplication()
    device.run()


if __name__ == '__main__':
    main()
