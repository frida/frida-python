# -*- coding: utf-8 -*-
from __future__ import print_function

import codecs
try:
    from io import BytesIO
except:
    try:
        from cStringIO import StringIO as BytesIO
    except:
        from StringIO import StringIO as BytesIO
import os
import platform
from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.extension import Extension
import shutil
import struct
import sys
try:
    from urllib.request import urlopen, Request
except:
    from urllib2 import urlopen, Request
try:
    import xmlrpclib
except ImportError:
    import xmlrpc.client as xmlrpclib
import zipfile


package_dir = os.path.dirname(os.path.realpath(__file__))
pkg_info = os.path.join(package_dir, "PKG-INFO")
in_source_package = os.path.isfile(pkg_info)
if in_source_package:
    with codecs.open(pkg_info, "r", 'utf-8') as f:
        version_line = [line.rstrip("\r") for line in f.read().split("\n") if line.startswith("Version: ")][0]
        frida_version = version_line[9:]
    long_description = None
else:
    frida_version = os.environ['FRIDA_VERSION']
    long_description = codecs.open(os.path.join(package_dir, "README.md"), "r", 'utf-8').read()
    frida_extension = os.environ['FRIDA_EXTENSION']
frida_major_version = int(frida_version.split(".")[0])


class UrllibTransport(xmlrpclib.Transport):
    def __init__(self, *args, **kwargs):
        xmlrpclib.Transport.__init__(self, *args, **kwargs)

    def request(self, host, handler, request_body, verbose=0):
        self.verbose = verbose
        scheme = "https"
        url = "%(scheme)s://%(host)s%(handler)s" % locals()
        req = Request(url, data=request_body, headers={'Content-Type': 'text/xml'})
        fp = urlopen(req)
        return self.parse_response(fp)


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
                client = xmlrpclib.ServerProxy("https://pypi.python.org/pypi", transport=UrllibTransport())
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
                                    "Prebuilds only provided for Python 2.7 and 3.4+.")

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
    name="frida",
    version=frida_version,
    description="Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Frida Developers",
    author_email="oleavr@frida.re",
    url="https://www.frida.re",
    license="wxWindows Library Licence, Version 3.1",
    zip_safe=True,
    keywords="frida debugger dynamic instrumentation inject javascript windows macos linux ios iphone ipad android qnx",
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
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: JavaScript",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    packages=['frida'],
    ext_modules=[Extension('_frida', [])],
    cmdclass={
        'build_ext': FridaPrebuiltExt
    }
)
