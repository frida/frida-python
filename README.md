# frida-python

Python bindings for [Frida](http://www.frida.re).

# Some tips during development

To build and test your own egg, do something along the following lines:

```
set FRIDA_VERSION=12.0.0.10.gd7c36fc # from C:\src\frida\build\tmp-windows\frida-version.h
set FRIDA_EXTENSION=C:\src\frida\build\frida-windows\Win32-Debug\lib\python2.7\site-packages\_frida.pyd
cd C:\src\frida\frida-python\
python setup.py bdist_egg
pip uninstall frida
easy_install dist\frida-12.0.0.10.gd7c36fc-py2.7-win32.egg
```
