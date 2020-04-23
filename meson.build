project('frida-python', 'c', version: '1.0.0')

host_os_family = host_machine.system()
host_os = host_os_family

cc = meson.get_compiler('c')

frida_component_cflags = []
ndebug = get_option('b_ndebug')
if ndebug == 'true' or (ndebug == 'if-release' and not get_option('debug'))
  frida_component_cflags += [
    '-DG_DISABLE_ASSERT',
    '-DG_DISABLE_CHECKS',
    '-DG_DISABLE_CAST_CHECKS',
  ]
endif

target_conditionals_prefix = '#include <TargetConditionals.h>'

is_macos_src = target_conditionals_prefix + '''
#if !TARGET_OS_OSX
# error Not macOS
#endif
'''
if cc.compiles(is_macos_src, name: 'compiling for macOS')
  host_os = 'macos'
endif

is_ios_src = target_conditionals_prefix + '''
#if !TARGET_OS_IOS
# error Not iOS
#endif
'''
if cc.compiles(is_ios_src, name: 'compiling for iOS')
  host_os = 'ios'
endif

if cc.has_header('android/api-level.h')
  host_os = 'android'
endif

python_incdir = get_option('python_incdir')
if python_incdir == ''
  python = get_option('python')
  if python == ''
    python = find_program('python3', required: false)
    if not python.found()
      python = find_program('python')
    endif
  endif

  result = run_command(python, '-c',
    'import sys; sys.stdout.write("%d.%d" % (sys.version_info[0], sys.version_info[1]))')
  if result.returncode() != 0
    error('Unable to detect Python version: ' + result.stdout() + result.stderr())
  endif
  python_version = result.stdout()
  python_name = 'python' + python_version

  result = run_command(python, '-c',
    'from distutils import sysconfig; import sys; sys.stdout.write(sysconfig.get_python_inc())')
  if result.returncode() != 0
    error('Unable to detect Python include directory: ' + result.stdout() + result.stderr())
  endif
  python_incdir = result.stdout()
else
  py_major_v = cc.get_define('PY_MAJOR_VERSION',
    prefix: '#include <patchlevel.h>',
    args: ['-I' + python_incdir])

  py_minor_v = cc.get_define('PY_MINOR_VERSION',
    prefix: '#include <patchlevel.h>',
    args: ['-I' + python_incdir])

  python_version = py_major_v + '.' + py_minor_v
  python_name = 'python' + python_version
endif

python_site_packages = join_paths(get_option('libdir'), python_name, 'site-packages')

if python_version.version_compare('>3')
  python_plugin_export_name = 'PyInit__frida'
else
  python_plugin_export_name = 'init_frida'
endif

cdata = configuration_data()

cdata.set('HAVE_' + host_os_family.to_upper(), 1)
if host_os != host_os_family
  cdata.set('HAVE_' + host_os.to_upper(), 1)
endif

frida_core_dep = dependency('frida-core-1.0')

configure_file(input: 'config.h.in',
  output: 'config.h',
  configuration: cdata)

subdir('src')
subdir('frida')
