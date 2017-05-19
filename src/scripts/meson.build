scripts = [
  'frida',
  'frida-discover',
  'frida-kill',
  'frida-ls-devices',
  'frida-ps',
  'frida-trace',
]

cdata = configuration_data()
cdata.set('PYTHON', python)
cdata.set('pythondir', python_site_packages)

foreach s : scripts
  generated_script = configure_file(
    input: s + '.in',
    output: s,
    configuration: cdata,
  )
  install_data(generated_script,
    install_dir: get_option('bindir'),
    install_mode: 'rwxr-xr-x',
  )
endforeach
