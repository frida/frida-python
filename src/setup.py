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
        except Exception, e:
            pass
        shutil.copyfile(frida_extension, target)

setup(
    name='frida',
    version=version,
    packages=['frida'],
    license="GNU GPLv3",
    description="Frida is an open-source toolkit for interactive and scriptable reverse-engineering",
    long_description=long_description,
    url="http://frida.github.io",
    author="Frida Developers",
    author_email="ole.andre.ravnas@tillitech.com",
    entry_points={
        'console_scripts': [
            'frida-trace = frida.tracer:main'
        ]
    },
    ext_modules=[Extension('_frida', [])],
    cmdclass={
        'build_ext': FridaPrebuiltExt
    }
)
