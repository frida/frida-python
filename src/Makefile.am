SUBDIRS = frida

bin_SCRIPTS = \
	frida-ps \
	frida-discover \
	frida-trace \
	frida-repl
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = \
	frida-ps.in \
	frida-discover.in \
	frida-trace.in \
	frida-repl.in

do_substitution = sed -e 's,[@]pythondir[@],$(pythondir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g'

frida-ps: frida-ps.in Makefile
	$(do_substitution) < $(srcdir)/frida-ps.in > $@
	chmod +x $@

frida-discover: frida-discover.in Makefile
	$(do_substitution) < $(srcdir)/frida-discover.in > $@
	chmod +x $@

frida-trace: frida-trace.in Makefile
	$(do_substitution) < $(srcdir)/frida-trace.in > $@
	chmod +x $@

frida-repl: frida-repl.in Makefile
	$(do_substitution) < $(srcdir)/frida-repl.in > $@
	chmod +x $@

pyexec_LTLIBRARIES = _frida.la

_frida_la_SOURCES = \
	_frida.c
_frida_la_LDFLAGS = \
	-export-symbols-regex "^(PyInit__frida|init_frida)$$" \
	-module -avoid-version -shared \
	$(PYFRIDA_LDFLAGS) \
	$(PYTHON_LDFLAGS)
_frida_la_LIBADD = \
	$(PYFRIDA_LIBS) \
	$(PYTHON_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	$(PYFRIDA_CFLAGS) \
	$(PYTHON_CFLAGS)
