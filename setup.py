# -*- coding: utf-8 -*-
from __future__ import print_function

import sys
import os
import platform
import re
import zipfile
import shutil
import struct
import codecs
import subprocess
import hashlib
from collections import namedtuple
from functools import partial
try:
    from io import BytesIO
except:
    try:
        from cStringIO import StringIO as BytesIO
    except:
        from StringIO import StringIO as BytesIO
try:
    from urllib.request import urlopen, Request
except:
    from urllib2 import urlopen, Request
try:
    from urllib.parse import urljoin, urlparse, urlunparse
except:
    from urlparse import urljoin, urlparse, urlunparse
try:
    from html.parser import HTMLParser
except:
    from HTMLParser import HTMLParser

from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.extension import Extension


DEFAULT_INDEX_URL = "https://pypi.org/simple/"

python_version = sys.version_info[0:2]
python_major_version = python_version[0]

package_dir = os.path.dirname(os.path.realpath(__file__))
pkg_info = os.path.join(package_dir, "PKG-INFO")
in_source_package = os.path.isfile(pkg_info)
if in_source_package:
    with codecs.open(pkg_info, "r", 'utf-8') as f:
        version_line = [line.rstrip("\r") for line in f.read().split("\n") if line.startswith("Version: ")][0]
        frida_version = version_line[9:]
    long_description = None
else:
    frida_version = os.environ.get('FRIDA_VERSION', None)
    long_description = codecs.open(os.path.join(package_dir, "README.md"), "r", 'utf-8').read()
    frida_extension = os.environ.get('FRIDA_EXTENSION', None)

index_url_pip_configs = ("global.index-url", "global.extra-index-url")

Tag = namedtuple("Tag", ["tagname", "attrs"])
ParsedUrlInfo = namedtuple("ParsedUrlInfo",
                           ["url", "filename", "major", "minor", "micro"])


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
                elif os_name == 'android' and machine.startswith("armv"):
                    arch_name = 'armv7l'
                else:
                    arch_name = machine
                os_version = "{}-{}".format(os_name, arch_name)
            elif system == 'FreeBSD':
                os_version = "freebsd-" + platform.machine()
            else:
                raise NotImplementedError("unsupported OS")

            egg_path = os.path.expanduser(
                "~{}frida-{}-py{}.{}-{}.egg".format(os.sep, frida_version, python_version[0], python_version[1], os_version))
            print("looking for prebuilt extension in home directory, i.e.", egg_path)

            try:
                with open(egg_path, "rb") as cache:
                    egg_data = cache.read()
            except:
                egg_data = None

            if egg_data is None:
                print("prebuilt extension not found in home directory, will try downloading it")

                print("querying pypi for available prebuilds")
                # index_url is a url compatible with PEP 503
                index_url = get_index_url().strip()
                index_url = normalize_url(index_url)
                frida_url = urljoin(index_url, "frida/")  # slash is necessary here
                timeout = 20
                errmsg = (
                    "unable to download it within {} seconds; "
                    "please download it manually to {}"
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
            else:
                egg_url = None

            egg_file = BytesIO(egg_data)

            if egg_url is not None:
                print("checking hash")
                check_pep503_hash(egg_file, egg_url)

            print("extracting prebuilt extension")
            egg_zip = zipfile.ZipFile(egg_file)
            extension_member = [info for info in egg_zip.infolist() if info.filename.endswith(target_extension)][0]
            extension_data = egg_zip.read(extension_member)
            if system == 'Windows' and python_major_version >= 3:
                trailer = b"\x00" if python_version[1] >= 10 else b"\x00\x00"
                extension_data = re.sub(b"python[3-9][0-9][0-9]\\.dll\x00",
                                        "python{0}{1}.dll".format(*python_version).encode('utf-8') + trailer,
                                        extension_data)
            with open(target, 'wb') as f:
                f.write(extension_data)
        else:
            shutil.copyfile(frida_extension, target)


def get_index_url():
    """get `index-url` from environment or pip
    Use FRIDA_INDEX_URL environment variable to customize index-url compatible
    with PEP 503.
    """
    index_url = os.environ.get("FRIDA_INDEX_URL", None)
    if index_url is not None:
        return index_url

    for config_name in index_url_pip_configs:
        try:
            index_url = get_index_url_from_pip(config_name)
        except (subprocess.CalledProcessError, OSError):
            pass
        else:
            return index_url

    print("using default index URL: {}".format(DEFAULT_INDEX_URL))
    return DEFAULT_INDEX_URL


def get_index_url_from_pip(config_name):
    assert config_name in index_url_pip_configs

    return subprocess.check_output([sys.executable, "-m", "pip", "config", "get", config_name],
                                   stderr=subprocess.PIPE).decode("utf-8")


def normalize_url(url):
    parse_result = urlparse(url)
    path = parse_result.path
    if not path.endswith("/"):
        path += "/"
    return urlunparse((
        parse_result.scheme, parse_result.netloc, path,
        parse_result.params, parse_result.query, parse_result.fragment,
    ))


class PEP503PageParser(HTMLParser):
    def __init__(self, name, version, os_version):
        HTMLParser.__init__(self)
        filename_pattern = (
            r"^{}\-{}\-py(?P<major>\d+)\.(?P<minor>\d+)(\.(?P<micro>\d+))?-{}.egg$"
        ).format(*map(re.escape, [name, version, os_version]))
        if python_major_version == 2:
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
            if len(self._path) > 0 and self._path[-1].tagname == tag:
                self._path.pop()

    def handle_data(self, data):
        if not (len(self._path) > 0
                and self._path[-1].tagname == u"a"
                and self._path[-1].attrs.get("href")):
            return

        match = self._filename_pattern.match(data)
        if match is not None:
            self.urls.append(ParsedUrlInfo(
                self._path[-1].attrs["href"],
                data,
                *map(
                    lambda g: int(g) if g else None,
                    map(match.group, ["major", "minor", "micro"])
                )
            ))


def check_pep503_hash(bytes_io, url):
    parse_result = urlparse(url)
    fragment = parse_result.fragment
    if fragment == "":
        return

    hashname, hashvalue = fragment.split("=")
    if hashname not in {"md5", "sha1", "sha224", "sha256", "sha348", "sha512"}:
        raise ValueError("Unsupported hash algorithm: {}, hashvalue={}".format(
            hashname, hashvalue,
        ))

    h = hashlib.new(hashname)
    for block in iter(partial(bytes_io.read, 4096), b""):  # iterate until EOF
        h.update(block)
    digest = h.hexdigest()
    bytes_io.seek(0)  # reset offset

    if digest == hashvalue:
        return
    else:
        raise ValueError(
            "`{}` hash checking failed! Expected: {}, but got: {}".format(
                hashname, hashvalue, digest)
        )


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
