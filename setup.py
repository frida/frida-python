import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.extension import Extension


PACKAGE_DIR = Path(__file__).resolve().parent


def detect_version():
    pkg_info = PACKAGE_DIR / "PKG-INFO"
    in_source_package = pkg_info.exists()
    if in_source_package:
        version_line = [line for line in pkg_info.read_text(encoding="utf-8").split("\n")
                        if line.startswith("Version: ")][0].strip()
        version = version_line[9:]
    else:
        sys.path.insert(0, os.environ.get("MESON_SOURCE_ROOT", str(PACKAGE_DIR)))
        from releng.frida_version import detect
        version = detect(PACKAGE_DIR).name.replace("-dev.", ".dev")
    return version


class FridaPrebuiltExt(build_ext):
    def build_extension(self, ext):
        target = self.get_ext_fullpath(ext.name)
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(frida_extension, target)


class FridaDemandBuiltExt(build_ext):
    def build_extension(self, ext):
        make = PACKAGE_DIR / "make.bat" if platform.system() == "Windows" else "make"
        subprocess.run([make], check=True)

        outputs = [entry for entry in (PACKAGE_DIR / "build" / "src").glob("_frida.*") if entry.is_file()]
        assert len(outputs) == 1
        target = self.get_ext_fullpath(ext.name)
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(outputs[0], target)


frida_version = detect_version()
long_description = (PACKAGE_DIR / "README.md").read_text(encoding="utf-8")
frida_extension = os.environ.get("FRIDA_EXTENSION", None)

cmdclass = {}
cmdclass["build_ext"] = FridaPrebuiltExt if frida_extension is not None else FridaDemandBuiltExt


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
        install_requires=["typing_extensions; python_version<'3.11'"],
        python_requires=">=3.7",
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
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: Implementation :: CPython",
            "Programming Language :: JavaScript",
            "Topic :: Software Development :: Debuggers",
            "Topic :: Software Development :: Libraries :: Python Modules",
        ],
        packages=["frida", "_frida"],
        package_data={"frida": ["py.typed"], "_frida": ["py.typed", "__init__.pyi"]},
        ext_modules=[
            Extension(
                name="_frida",
                sources=["src/_frida.c"],
                py_limited_api=True,
            )
        ],
        cmdclass=cmdclass,
        zip_safe=False,
    )
