py_sources = [
  '__init__.pyi',
  'py.typed',
]
python.install_sources(py_sources, subdir: 'frida' / '_frida', pure: false)

extra_link_args = []
if host_os_family == 'darwin'
  extra_link_args += '-Wl,-exported_symbol,_PyInit__frida'
elif host_os_family != 'windows'
  extra_link_args += '-Wl,--version-script,' + meson.current_source_dir() / 'extension.version'
endif

extension = python.extension_module('_frida', 'extension.c',
  limited_api: '3.7',
  c_args: frida_component_cflags,
  link_args: extra_link_args,
  dependencies: [python_dep, frida_core_dep, os_deps],
  install: true,
  subdir: 'frida',
)
