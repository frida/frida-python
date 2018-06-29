# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

def main():
    from frida.application import ConsoleApplication

    class PSApplication(ConsoleApplication):
        def _add_options(self, parser):
            parser.add_option("-a", "--applications", help="list only applications",
                action='store_true', dest="list_only_applications", default=False)
            parser.add_option("-i", "--installed", help="include all installed applications",
                action='store_true', dest="include_all_applications", default=False)

        def _initialize(self, parser, options, args):
            if options.include_all_applications and not options.list_only_applications:
                parser.error("-i cannot be used without -a")
            self._list_only_applications = options.list_only_applications
            self._include_all_applications = options.include_all_applications

        def _usage(self):
            return "usage: %prog [options]"

        def _start(self):
            if self._list_only_applications:
                try:
                    applications = self._device.enumerate_applications()
                except Exception as e:
                    self._update_status("Failed to enumerate applications: %s" % e)
                    self._exit(1)
                    return
                if not self._include_all_applications:
                    applications = list(filter(lambda app: app.pid != 0, applications))
                if len(applications) > 0:
                    pid_column_width = max(map(lambda app: len("%d" % app.pid), applications))
                    name_column_width = max(map(lambda app: len(app.name), applications))
                    identifier_column_width = max(map(lambda app: len(app.identifier), applications))
                else:
                    pid_column_width = 0
                    name_column_width = 0
                    identifier_column_width = 0
                header_format = "%" + str(pid_column_width) + "s  " + \
                    "%-" + str(name_column_width) + "s  " + \
                    "%-" + str(identifier_column_width) + "s"
                self._print(header_format % ("PID", "Name", "Identifier"))
                self._print("%s  %s  %s" % (pid_column_width * "-", name_column_width * "-", identifier_column_width * "-"))
                line_format = "%" + str(pid_column_width) + "s  " + \
                    "%-" + str(name_column_width) + "s  " + \
                    "%-" + str(identifier_column_width) + "s"
                for app in sorted(applications, key=cmp_to_key(compare_applications)):
                    if app.pid == 0:
                        self._print(line_format % ("-", app.name, app.identifier))
                    else:
                        self._print(line_format % (app.pid, app.name, app.identifier))
            else:
                try:
                    processes = self._device.enumerate_processes()
                except Exception as e:
                    self._update_status("Failed to enumerate processes: %s" % e)
                    self._exit(1)
                    return
                pid_column_width = max(map(lambda p: len("%d" % p.pid), processes))
                name_column_width = max(map(lambda p: len(p.name), processes))
                header_format = "%" + str(pid_column_width) + "s  %s"
                self._print(header_format % ("PID", "Name"))
                self._print("%s  %s" % (pid_column_width * "-", name_column_width * "-"))
                line_format = "%" + str(pid_column_width) + "d  %s"
                for process in sorted(processes, key=cmp_to_key(compare_processes)):
                    self._print(line_format % (process.pid, process.name))
            self._exit(0)

    def compare_applications(a, b):
        a_is_running = a.pid != 0
        b_is_running = b.pid != 0
        if a_is_running == b_is_running:
            if a.name > b.name:
                return 1
            elif a.name < b.name:
                return -1
            else:
                return 0
        elif a_is_running:
            return -1
        else:
            return 1

    def compare_processes(a, b):
        a_has_icon = a.get_small_icon() is not None
        b_has_icon = b.get_small_icon() is not None
        if a_has_icon == b_has_icon:
            if a.name > b.name:
                return 1
            elif a.name < b.name:
                return -1
            else:
                return 0
        elif a_has_icon:
            return -1
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

    app = PSApplication()
    app.run()


if __name__ == '__main__':
    main()
