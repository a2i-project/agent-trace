"""Check textkit's sources: python3 tools/lint.py PATH...

A path is a file or a directory searched for .py files. Every file must hold no
NotImplementedError, no tab, no line over 99 characters, and a docstring on
the module and on every top-level function. Exit status 1 when one does not.
"""

import ast
import pathlib
import sys


def files(paths):
    """Yield the .py files the paths name, in sorted order."""
    for p in map(pathlib.Path, paths):
        if p.is_dir():
            yield from sorted(p.rglob("*.py"))
        else:
            yield p


def check(path):
    """Return the problems found in one file."""
    text = path.read_text(encoding="utf-8")
    problems = []
    for n, line in enumerate(text.splitlines(), 1):
        if "NotImplementedError" in line:
            problems.append(f"{path}:{n}: not implemented")
        if "\t" in line:
            problems.append(f"{path}:{n}: tab")
        if len(line) > 99:
            problems.append(f"{path}:{n}: line longer than 99 characters")
    tree = ast.parse(text, filename=str(path))
    if ast.get_docstring(tree) is None:
        problems.append(f"{path}: no module docstring")
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and ast.get_docstring(node) is None:
            problems.append(f"{path}:{node.lineno}: {node.name} has no docstring")
    return problems


def main(argv):
    """Lint the paths in argv and return the exit status."""
    if not argv:
        print("usage: lint.py PATH...", file=sys.stderr)
        return 2
    problems = [p for f in files(argv) for p in check(f)]
    for p in problems:
        print(p)
    print(f"lint: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
