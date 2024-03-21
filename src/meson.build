extra_link_args = []
if host_os_family == 'darwin'
  extra_link_args += '-Wl,-exported_symbol,_PyInit__frida'
elif host_os_family != 'windows'
  extra_link_args += '-Wl,--version-script,' + meson.current_source_dir() / '_frida.version'
endif

extension = python.extension_module('_frida', '_frida.c',
  limited_api: '3.7',
  c_args: frida_component_cflags,
  link_args: extra_link_args,
  dependencies: [python_dep, frida_core_dep, os_deps],
  install: true,
)
