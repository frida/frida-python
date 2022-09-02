import codecs
import os
import shutil

from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.extension import Extension

package_dir = os.path.dirname(os.path.realpath(__file__))

frida_version = os.environ.get("FRIDA_VERSION", None)
long_description = codecs.open(os.path.join(package_dir, "README.md"), "r", "utf-8").read()
frida_extension = os.environ.get("FRIDA_EXTENSION", None)


class FridaPrebuiltExt(build_ext):
    def build_extension(self, ext):
        target = self.get_ext_fullpath(ext.name)
        target_dir = os.path.dirname(target)
        os.makedirs(target_dir, exist_ok=True)

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
        package_data={"frida": ["py.typed"], "_frida": ["py.typed"]},
        ext_modules=[Extension("_frida", [])],
        cmdclass={"build_ext": FridaPrebuiltExt},
        zip_safe=False,
    )
