SUBDIRS = \
	frida \
	scripts

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
