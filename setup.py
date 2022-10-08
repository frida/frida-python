import os
import platform
import shutil

from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.extension import Extension

package_dir = os.path.dirname(os.path.realpath(__file__))
pkg_info = os.path.join(package_dir, "PKG-INFO")
in_source_package = os.path.isfile(pkg_info)
if in_source_package:
    with open(pkg_info, "r", encoding="utf-8") as f:
        version_line = [line for line in f if line.startswith("Version: ")][0].strip()
    frida_version = version_line[9:]
else:
    frida_version = os.environ.get("FRIDA_VERSION", "0.0.0")
with open(os.path.join(package_dir, "README.md"), "r", encoding="utf-8") as f:
    long_description = f.read()
frida_extension = os.environ.get("FRIDA_EXTENSION", None)


class FridaPrebuiltExt(build_ext):
    def build_extension(self, ext):
        target = self.get_ext_fullpath(ext.name)
        target_dir = os.path.dirname(target)
        os.makedirs(target_dir, exist_ok=True)

        shutil.copyfile(frida_extension, target)


class FridaMissingDevkitBuildExt(build_ext):
    def build_extension(self, ext):
        raise RuntimeError(
            "Need frida-core devkit to build from source.\n"
            "Download one from https://github.com/frida/frida/releases, "
            "extract it to a directory,\n"
            "and then add an environment variable named FRIDA_CORE_DEVKIT "
            "pointing at the directory."
        )


include_dirs = []
library_dirs = []
libraries = []
extra_link_args = []

cmdclass = {}
if frida_extension is not None:
    cmdclass["build_ext"] = FridaPrebuiltExt
else:
    devkit_dir = os.environ.get("FRIDA_CORE_DEVKIT", None)
    if devkit_dir is not None:
        include_dirs += [devkit_dir]
        library_dirs += [devkit_dir]
        libraries += ["frida-core"]

        system = platform.system()
        if system == "Windows":
            pass
        elif system == "Darwin":
            extra_link_args += [
                "-Wl,-exported_symbol,_PyInit__frida",
                "-Wl,-dead_strip",
            ]
            if "_PYTHON_HOST_PLATFORM" not in os.environ:
                if platform.machine() == "arm64":
                    host_arch = "arm64"
                    macos_req = "11.0"
                else:
                    host_arch = "x86_64"
                    macos_req = "10.9"
                os.environ["_PYTHON_HOST_PLATFORM"] = f"macosx-{macos_req}-{host_arch}"
                os.environ["ARCHFLAGS"] = f"-arch {host_arch}"
                os.environ["MACOSX_DEPLOYMENT_TARGET"] = macos_req
        else:
            version_script = os.path.join(package_dir, "src", "_frida.version")
            if not os.path.exists(version_script):
                with open(version_script, "w", encoding="utf-8") as f:
                    f.write(
                        "\n".join(
                            [
                                "{",
                                "  global:",
                                "    PyInit__frida;",
                                "",
                                "  local:",
                                "    *;",
                                "};",
                            ]
                        )
                    )
            extra_link_args += [
                f"-Wl,--version-script,{version_script}",
                "-Wl,--gc-sections",
            ]
    else:
        cmdclass["build_ext"] = FridaMissingDevkitBuildExt


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
        install_requires=["setuptools", "typing_extensions; python_version<'3.8'"],
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
                include_dirs=include_dirs,
                library_dirs=library_dirs,
                libraries=libraries,
                extra_link_args=extra_link_args,
                py_limited_api=True,
            )
        ],
        cmdclass=cmdclass,
        zip_safe=False,
    )
