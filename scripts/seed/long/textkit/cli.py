"""Command line: python3 -m textkit.cli NAME ARG...

Calls the textkit function NAME with the arguments. An argument that parses as
JSON is passed as the value it denotes, any other as a string. The result is
printed as JSON.
"""

import json
import sys

from . import MODULES


def find(name):
    """Return the public textkit function called name, or None."""
    if name.startswith("_"):
        return None
    for module in MODULES:
        func = getattr(module, name, None)
        if callable(func):
            return func
    return None


def parse(arg):
    """Return arg as the JSON value it denotes, or as a string."""
    try:
        return json.loads(arg)
    except ValueError:
        return arg


def main(argv=None):
    """Run the command line on argv and return the exit status."""
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: textkit NAME ARG...", file=sys.stderr)
        return 2
    func = find(argv[0])
    if func is None:
        print(f"textkit: no function {argv[0]}", file=sys.stderr)
        return 2
    try:
        result = func(*[parse(a) for a in argv[1:]])
    except (TypeError, ValueError) as e:
        print(f"textkit: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
