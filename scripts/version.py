from pathlib import Path
import sys


def detect():
    root_dir = Path(__file__).parent.parent.resolve()
    pkg_info = root_dir / "PKG-INFO"
    in_source_package = pkg_info.exists()
    if in_source_package:
        version_line = [line for line in pkg_info.read_text(encoding="utf-8")
                        if line.startswith("Version: ")][0].strip()
        version = version_line[9:]
    else:
        sys.path.insert(0, str(root_dir))
        from releng.frida_version import detect
        version = detect(root_dir).name
    return version


if __name__ == "__main__":
    print(detect())
