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
import re
from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.extension import Extension
import shutil
import struct
import subprocess
from collections import namedtuple
import sys
try:
    from urllib.request import urlopen, Request
except:
    from urllib2 import urlopen, Request
try:
    from urllib.parse import urljoin
except:
    from urlparse import urljoin
try:
    from html.parser import HTMLParser
except:
    from HTMLParser import HTMLParser
import zipfile


DEFAULT_INDEX_URL = "https://pypi.org/simple/"

python_version = sys.version_info[0:2]
python_major_version = python_version[0]
PY2 = python_major_version == 2

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

Tag = namedtuple("Tag", ["tagname", "attrs"])
ParsedUrlInfo = namedtuple("ParsedUrlInfo",
                           ["url", "filename", "major", "minor", "micro"])


def get_index_url_from_pip():
    cmd = [sys.executable, "-m", "pip", "config", "get", "global.index-url"]
    try:
        return subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        print("Warning: Failed to get index-url from pip. ({}: {})".format(
            type(e).__name__, e))
        raise
    except OSError as e:
        print(
            "Warning: Failed to get index-url from pip. (Failed to execute "
            "{}, {}: {}".format(cmd, type(e).__name__, e)
        )
        raise


def get_index_url():
    """get `index-url` from environment or pip
    Use FRIDA_INDEX_URL environment variable to customize index-url compatibale
    with PEP 503.
    """
    index_url = os.environ.get("FRIDA_INDEX_URL")
    if index_url:
        return index_url
    try:
        index_url = get_index_url_from_pip()
    except (subprocess.CalledProcessError, OSError):
        return DEFAULT_INDEX_URL
    else:
        return index_url


# XXX Writing a whole HTML parser from scratch is not possible, and I'm not
#     familiar with HTML spec.
#     Is it a good idea to add bs4 (or something similar) to `pyproject.toml`?
class PEP503PageParser(HTMLParser):

    def __init__(self, name, version, os_version):
        HTMLParser.__init__(self)
        filename_pattern = (
            r"^{}\-{}\-py(?P<major>\d+)\.(?P<minor>\d+)(\.(?P<micro>\d+))?-{}.egg$"
        ).format(*map(re.escape, [name, version, os_version]))
        if PY2:
            filename_pattern = filename_pattern.decode("utf-8")
        self._filename_pattern = re.compile(filename_pattern)

    def reset(self):
        HTMLParser.reset(self)
        self._path = []
        self.urls = []

    def handle_starttag(self, tag, attrs):
        self._path.append(Tag(tag, dict(attrs)))

    def handle_endtag(self, tag):
        if tag == u"a":
            while True:
                if self._path.pop().tagname == tag:
                    break
        else:
            if self._path and self._path[-1].tagname == tag:
                self._path.pop()

    def handle_data(self, data):
        if not (self._path
                and self._path[-1].tagname == u"a"
                and self._path[-1].attrs.get("href")):
            return

        match = self._filename_pattern.match(data)
        if match:
            self.urls.append(ParsedUrlInfo(
                self._path[-1].attrs["href"],
                data,
                *map(
                    lambda g: int(g) if g else None,
                    map(match.group, ["major", "minor", "micro"])
                )
            ))


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
            system = platform.system()
            arch = struct.calcsize('P') * 8
            if system == 'Windows':
                os_version = "win-amd64" if arch == 64 else "win32"
            elif system == 'Darwin':
                if platform.machine() == 'x86_64':
                    os_version = "macosx-10.9-x86_64"
                elif python_major_version == 2:
                    os_version = "macosx-11.0-fat64"
                else:
                    os_version = "macosx-11.0-arm64"
            elif system == 'Linux':
                os_name = 'android' if subprocess.check_output(["uname", "-o"]).decode('utf-8').rstrip() == 'Android' else 'linux'
                machine = platform.machine()
                if machine == "" or "86" in machine:
                    arch_name = "x86_64" if arch == 64 else "i686"
                else:
                    arch_name = machine
                os_version = "{}-{}".format(os_name, arch_name)
            else:
                raise NotImplementedError("unsupported OS")

            egg_path = os.path.expanduser(
                "~/frida-{}-py{}.{}-{}.egg".format(frida_version, python_version[0], python_version[1], os_version))
            print("looking for prebuilt extension in home directory, i.e.", egg_path)

            try:
                with open(egg_path, "rb") as cache:
                    egg_data = cache.read()
            except IOError as e:
                print("prebuilt extension not found in home directory, will try downloading it")

                print("querying pypi for available prebuilds")
                # index_url is a url compatible with PEP 503
                index_url = get_index_url().strip()
                frida_url = urljoin(index_url, "frida/")  # slash is necessary here
                timeout = 20
                errmsg = (
                    "unable to download it within {} seconds; "
                    "please download it mamuallt to {}"
                ).format("{}", egg_path)

                print("downloading package list from", frida_url)
                try:
                    links_html = urlopen(frida_url, timeout=timeout).read().decode("utf-8")
                except Exception:
                    print(errmsg.format(timeout))
                    raise

                parser = PEP503PageParser("frida", frida_version, os_version)
                parser.feed(links_html)
                urls = [url for url in parser.urls if url.major == python_major_version]

                if len(urls) == 0:
                    raise NotImplementedError("could not find prebuilt Frida extension; "
                                              "prebuilds only provided for Python 2.7 and 3.4+")

                url = urls[0]
                egg_url = urljoin(frida_url, url.url)

                try:
                    print("downloading prebuilt extension from", egg_url)
                    timeout = 120  # We'll assume the user has at least 200 kB/s transfer speed.
                    egg_data = urlopen(egg_url, timeout=timeout).read()
                except Exception:
                    print(errmsg.format(timeout))
                    raise

            # TODO check the hash digest
            egg_file = BytesIO(egg_data)

            print("extracting prebuilt extension")
            egg_zip = zipfile.ZipFile(egg_file)
            extension_member = [info for info in egg_zip.infolist() if info.filename.endswith(target_extension)][0]
            extension_data = egg_zip.read(extension_member)
            if system == 'Windows' and python_major_version >= 3:
                extension_data = re.sub(b"python[3-9][0-9].dll",
                                        "python{0}{1}.dll".format(*python_version).encode('utf-8'), extension_data)
            with open(target, 'wb') as f:
                f.write(extension_data)
        else:
            shutil.copyfile(frida_extension, target)


if __name__ == "__main__":
    setup(
        name="frida",
        version=frida_version,
        description="Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers",
        long_description=long_description,
        long_description_content_type="text/markdown",
        author="Frida Developers",
        author_email="oleavr@frida.re",
        url="https://frida.re",
        install_requires=["setuptools"],
        license="wxWindows Library Licence, Version 3.1",
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
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: Implementation :: CPython",
            "Programming Language :: JavaScript",
            "Topic :: Software Development :: Debuggers",
            "Topic :: Software Development :: Libraries :: Python Modules"
        ],
        packages=['frida'],
        ext_modules=[Extension('_frida', [])],
        cmdclass={
            'build_ext': FridaPrebuiltExt
        },
        zip_safe=False
    )
