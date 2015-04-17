bin_SCRIPTS = \
	frida \
	frida-discover \
	frida-ps \
	frida-trace
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = \
	frida.in \
	frida-discover.in \
	frida-ps.in \
	frida-trace.in

do_substitution = sed \
	-e 's,[@]PYTHON[@],$(PYTHON),g' \
	-e 's,[@]pythondir[@],$(pythondir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g'

frida: frida.in Makefile
	$(do_substitution) < $(srcdir)/frida.in > $@
	chmod +x $@

frida-discover: frida-discover.in Makefile
	$(do_substitution) < $(srcdir)/frida-discover.in > $@
	chmod +x $@

frida-ps: frida-ps.in Makefile
	$(do_substitution) < $(srcdir)/frida-ps.in > $@
	chmod +x $@

frida-trace: frida-trace.in Makefile
	$(do_substitution) < $(srcdir)/frida-trace.in > $@
	chmod +x $@
