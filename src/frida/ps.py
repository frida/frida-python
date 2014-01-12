def main():
    from frida.application import ConsoleApplication

    class PSApplication(ConsoleApplication):
        def _usage(self):
            return "usage: %prog [options]"

        def _start(self):
            try:
                processes = self._device.enumerate_processes()
            except Exception as e:
                self._update_status("Failed to enumerate processes: %s" % e)
                self._exit(1)
                return
            pid_column_width = max(map(lambda p: len("%d" % p.pid), processes))
            header_format = "%" + str(pid_column_width) + "s %s"
            print(header_format % ("PID", "NAME"))
            line_format = "%" + str(pid_column_width) + "d %s"
            for process in sorted(processes, key=cmp_to_key(compare_devices)):
                print(line_format % (process.pid, process.name))
            self._exit(0)

    def compare_devices(a, b):
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
