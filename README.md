# frida-python

Python bindings for [Frida](http://www.frida.re).

# Some tips during development

To build and test your own egg, do something along the following lines:

```
set FRIDA_VERSION=10.3.1.10.gd7c36fc # from c:\temp\frida\build\tmp-windows\frida-version.h
set FRIDA_EXTENSION=c:\temp\frida\build\frida-windows\Win32-Debug\lib\python2.7\site-packages\_frida.pyd
cd C:\Temp\frida\frida-python\src\
python setup.py bdist_egg
pip uninstall frida
easy_install dist\frida-10.3.1.10.gd7c36fc-py2.7-win32.egg
```
