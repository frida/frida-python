extra_link_args = []
if host_os_family == 'darwin'
  extra_link_args += ['-Wl,-exported_symbol,_PyInit__frida']
elif host_os_family != 'windows'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), '_frida.version')]
endif

extension = shared_module('_frida', '_frida.c',
  name_prefix: '',
  name_suffix: 'so',
  c_args: frida_component_cflags,
  include_directories: include_directories(python_incdir),
  link_args: extra_link_args,
  dependencies: [frida_core_dep] + os_deps,
  install: true,
  install_dir: python_site_packages,
)
