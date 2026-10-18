"""Build dist/textkit.pyz, a zip application running textkit.cli."""

import pathlib
import shutil
import zipapp

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main():
    """Copy the package into dist/build and archive it."""
    dist = ROOT / "dist"
    build = dist / "build"
    shutil.rmtree(build, ignore_errors=True)
    shutil.copytree(ROOT / "textkit", build / "textkit",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (build / "__main__.py").write_text(
        "import sys\n\nfrom textkit.cli import main\n\nsys.exit(main())\n", encoding="utf-8")
    target = dist / "textkit.pyz"
    zipapp.create_archive(build, target, interpreter="/usr/bin/env python3")
    print(f"built {target.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
