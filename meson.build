project('frida-python', 'c', version: '1.0.0')

host_os = host_machine.system()
if host_os == 'android'
  host_os_family = 'linux'
else
  host_os_family = host_os
endif

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

python = import('python').find_installation()

python_incdir = get_option('python_incdir')
if python_incdir == ''
  result = run_command(python, '-c',
    'import sys; sys.stdout.write(f"{sys.version_info[0]}.{sys.version_info[1]}")',
    check: true)
  python_version = result.stdout()
  python_name = 'python' + python_version

  result = run_command(python, '-c',
    'from distutils import sysconfig; import sys; sys.stdout.write(sysconfig.get_python_inc())',
    check: true)
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

cdata = configuration_data()

cdata.set('HAVE_' + host_os_family.to_upper(), 1)
if host_os != host_os_family
  cdata.set('HAVE_' + host_os.to_upper(), 1)
endif

frida_core_dep = dependency('frida-core-1.0')
os_deps = []
if host_os_family != 'windows'
  os_deps += dependency('gio-unix-2.0')
endif

configure_file(input: 'config.h.in',
  output: 'config.h',
  configuration: cdata)

subdir('src')
subdir('frida')

test('frida-python', python,
  args: ['-m', 'unittest', 'discover'],
  workdir: meson.current_source_dir(),
  env: {'PYTHONPATH': meson.current_build_dir() / 'src'},
  timeout: 30,
)
