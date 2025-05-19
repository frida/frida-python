if frida_core_dep.type_name() == 'internal'
  frida_core_subprj = subproject('frida-core')
  frida_gir = frida_core_subprj.get_variable('core_public_gir')
  glib_gir = frida_core_subprj.get_variable('glib_gir')
  gobject_gir = frida_core_subprj.get_variable('gobject_gir')
  gio_gir = frida_core_subprj.get_variable('gio_gir')
else
  girdir = frida_core_dep.get_variable('frida_girdir')
  frida_gir = girdir / 'Frida-1.0.gir'
  glib_gir = girdir / 'GLib-2.0.gir'
  gobject_gir = girdir / 'GObject-2.0.gir'
  gio_gir = girdir / 'Gio-2.0.gir'
endif

env = environment()
env.set('PYTHONPATH', meson.current_source_dir())

code = custom_target('binding-code',
  output: [
    '__init__.py',
    '__init__.pyi',
    'extension.c',
  ],
  input: [
    frida_gir,
    glib_gir,
    gobject_gir,
    gio_gir,
    files(
      'frida_bindgen' / '__init__.py',
      'frida_bindgen' / '__main__.py',
      'frida_bindgen' / 'cli.py',
      'frida_bindgen' / 'codegen.py',
      'frida_bindgen' / 'customization.py',
      'frida_bindgen' / 'loader.py',
      'frida_bindgen' / 'model.py',
      'frida_bindgen' / 'assets' / 'codegen_gobject_globals.c',
      'frida_bindgen' / 'assets' / 'codegen_gobject_methods.c',
      'frida_bindgen' / 'assets' / 'codegen_gobject_prototypes.h',
      'frida_bindgen' / 'assets' / 'codegen_helpers.c',
      'frida_bindgen' / 'assets' / 'codegen_helpers.ts',
      'frida_bindgen' / 'assets' / 'codegen_macros.h',
      'frida_bindgen' / 'assets' / 'codegen_prototypes.h',
      'frida_bindgen' / 'assets' / 'codegen_structs.h',
      'frida_bindgen' / 'assets' / 'codegen_typedefs.h',
      'frida_bindgen' / 'assets' / 'customization_facade.exports',
      'frida_bindgen' / 'assets' / 'customization_facade.ts',
      'frida_bindgen' / 'assets' / 'customization_helpers.imports',
      'frida_bindgen' / 'assets' / 'customization_helpers.ts',
    )
  ],
  command: [
    python, '-m', 'frida_bindgen',
    '--frida-gir=@INPUT0@',
    '--glib-gir=@INPUT1@',
    '--gobject-gir=@INPUT2@',
    '--gio-gir=@INPUT3@',
    '--output-py=@OUTPUT0@',
    '--output-pyi=@OUTPUT1@',
    '--output-c=@OUTPUT2@',
  ],
  env: env,
  install: true,
  install_dir: [
    python.get_install_dir() / 'frida',
    python.get_install_dir() / 'frida' / '_frida',
    false,
  ]
)

py_sources = [
  'py.typed',
]
python.install_sources(py_sources, subdir: 'frida', pure: false)

extension_py_sources = [
  'py.typed',
]
python.install_sources(extension_py_sources, subdir: 'frida' / '_frida', pure: false)

extra_link_args = []
if host_os_family == 'darwin'
  extra_link_args += '-Wl,-exported_symbol,_PyInit__frida'
elif host_os_family != 'windows'
  extra_link_args += '-Wl,--version-script,' + meson.current_source_dir() / 'extension.version'
endif

extension = python.extension_module('_frida', code[2],
  limited_api: '3.7',
  c_args: frida_component_cflags,
  link_args: extra_link_args,
  dependencies: [python_dep, frida_core_dep, os_deps],
  install: true,
  subdir: 'frida',
)
