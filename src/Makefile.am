pyexec_LTLIBRARIES = _frida.la

_frida_la_SOURCES = \
        pyfrida.c
_frida_la_LDFLAGS = \
	-export-symbols-regex "^init_frida$$" \
	-module -avoid-version -shared \
	$(PYTHON_LDFLAGS) \
	$(PYFRIDA_LDFLAGS)
_frida_la_LIBADD = \
	$(PYTHON_LIBS) \
	$(PYFRIDA_LIBS)

AM_CPPFLAGS = \
	-include config.h \
	$(PYTHON_CFLAGS) \
	$(PYFRIDA_CFLAGS)
