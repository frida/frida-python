# -*- coding: utf-8 -*-

from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.extension import Extension
import os
import re
import shutil

root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
version = os.environ['FRIDA_VERSION']
long_description = open(os.path.join(root_dir, "README.md")).read()
frida_extension = os.environ['FRIDA_EXTENSION']

class FridaPrebuiltExt(build_ext):
    def build_extension(self, ext):
        target = self.get_ext_fullpath(ext.name)
        try:
            os.makedirs(os.path.dirname(target))
        except:
            pass
        shutil.copyfile(frida_extension, target)

setup(
    name='frida',
    version=version,
    description="Inject JavaScript to explore native apps on Windows, Mac, Linux, iOS and Android",
    long_description=long_description,
    author="Frida Developers",
    author_email="ole.andre.ravnas@tillitech.com",
    url="http://www.frida.re",
    install_requires=[
        "colorama >= 0.2.7",
        "prompt-toolkit >= 0.38",
        "pygments >= 2.0.2"
    ],
    license="wxWindows Library Licence, Version 3.1",
    zip_safe=True,
    keywords="frida debugger inject javascript windows mac linux ios iphone ipad android",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Environment :: MacOS X",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: JavaScript",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    packages=['frida'],
    entry_points={
        'console_scripts': [
            "frida = frida.repl:main",
            "frida-discover = frida.discoverer:main",
            "frida-ps = frida.ps:main",
            "frida-trace = frida.tracer:main"
        ]
    },
    ext_modules=[Extension('_frida', [])],
    cmdclass={
        'build_ext': FridaPrebuiltExt
    }
)
