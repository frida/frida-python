# -*- coding: utf-8 -*-

from __future__ import print_function
try:
    from io import BytesIO
except:
    try:
        from cStringIO import StringIO as BytesIO
    except:
        from StringIO import StringIO as BytesIO
from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.extension import Extension
import os
import platform
import shutil
import struct
import sys
try:
    from urllib.request import urlopen
except:
    from urllib2 import urlopen
import zipfile
try:
    import xmlrpclib
except ImportError:
    import xmlrpc.client as xmlrpclib

package_dir = os.path.dirname(os.path.realpath(__file__))
pkg_info = os.path.join(package_dir, "PKG-INFO")
in_source_package = os.path.isfile(pkg_info)
if in_source_package:
    with open(pkg_info, "r") as f:
        version_line = [line.rstrip("\r") for line in f.read().split("\n") if line.startswith("Version: ")][0]
        frida_version = version_line[9:]
    long_description = None
else:
    root_dir = os.path.dirname(package_dir)
    frida_version = os.environ['FRIDA_VERSION']
    long_description = open(os.path.join(root_dir, "README.md")).read()
    frida_extension = os.environ['FRIDA_EXTENSION']

class FridaPrebuiltExt(build_ext):
    def build_extension(self, ext):
        target = self.get_ext_fullpath(ext.name)
        target_extension = os.path.splitext(target)[1]
        target_dir = os.path.dirname(target)
        try:
            os.makedirs(target_dir)
        except:
            pass
        if in_source_package:
            python_version = sys.version_info[0:2]
            python_major_version = python_version[0]
            system = platform.system()
            arch = struct.calcsize('P') * 8
            if system == 'Windows':
                os_version = "win-amd64" if arch == 64 else "win32"
            elif system == 'Darwin':
                os_version = "macosx-10.6-intel" if python_major_version == 3 else "macosx-10.11-intel"
            elif system == 'Linux':
                os_version = "linux-x86_64" if arch == 64 else "linux-i686"

            network_error = None

            try:
                print("querying pypi for available prebuilds")
                client = xmlrpclib.ServerProxy("https://pypi.python.org/pypi")
                urls = client.release_urls("frida", frida_version)

                urls = [url for url in urls if url['python_version'] != 'source']

                def parse_version(version):
                    return tuple(map(int, version.split(".")))

                if python_major_version >= 3:
                    urls = [url for url in urls if parse_version(url['python_version'])[0] == python_major_version]
                else:
                    urls = [url for url in urls if parse_version(url['python_version']) == python_version]

                os_suffix = "-{}.egg".format(os_version)
                urls = [url for url in urls if url['filename'].endswith(os_suffix)]

                if len(urls) == 0:
                    raise Exception("Could not find prebuilt Frida extension. "
                                    "Prebuilds only provided for python 2.6-2.7 and 3.x.")

                url = urls[0]
                egg_filename = url['filename']
                egg_url = url['url']

                print("downloading prebuilt extension from", egg_url)
                egg_data = urlopen(egg_url).read()
            except Exception as e:
                network_error = e

            if network_error is not None:
                print("network query failed")

                egg_path = os.path.expanduser("~/frida-{}-py{}.{}-{}.egg".format(frida_version, python_version[0], python_version[1], os_version))
                print("looking for prebuilt extension in home directory, i.e.", egg_path)
                try:
                    with open(egg_path, "rb") as f:
                        egg_data = f.read()
                except:
                    print("no prebuilt extension found in home directory")
                    egg_data = None

                if egg_data is None:
                    raise network_error

            egg_file = BytesIO(egg_data)

            print("extracting prebuilt extension")
            egg_zip = zipfile.ZipFile(egg_file)
            extension_member = [info for info in egg_zip.infolist() if info.filename.endswith(target_extension)][0]
            extension_data = egg_zip.read(extension_member)
            with open(target, 'wb') as f:
                f.write(extension_data)
        else:
            shutil.copyfile(frida_extension, target)

setup(
    name='frida',
    version=frida_version,
    description="Inject JavaScript to explore native apps on Windows, macOS, Linux, iOS, Android, and QNX",
    long_description=long_description,
    author="Frida Developers",
    author_email="oleavr@nowsecure.com",
    url="http://www.frida.re",
    install_requires=[
        "colorama >= 0.2.7",
        "prompt-toolkit >= 0.57",
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
            "frida-ls-devices = frida.lsd:main",
            "frida-ps = frida.ps:main",
            "frida-trace = frida.tracer:main"
        ]
    },
    ext_modules=[Extension('_frida', [])],
    cmdclass={
        'build_ext': FridaPrebuiltExt
    }
)
