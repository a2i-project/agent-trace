"""List helpers. Each function is specified in docs/spec/."""


# Specified in docs/spec/11-chunk.md.
def chunk(items, size):
    """Return items split into consecutive lists of size items."""
    raise NotImplementedError("chunk")


# Specified in docs/spec/12-flatten.md.
def flatten(nested):
    """Return the items of the lists in nested, one level deep."""
    raise NotImplementedError("flatten")


# Specified in docs/spec/13-dedupe.md.
def dedupe(items):
    """Return items without repeats, keeping the first occurrence of each."""
    raise NotImplementedError("dedupe")


# Specified in docs/spec/14-rotate.md.
def rotate(items, k):
    """Return items rotated left by k places."""
    raise NotImplementedError("rotate")


# Specified in docs/spec/15-interleave.md.
def interleave(a, b):
    """Return the items of a and b alternately."""
    raise NotImplementedError("interleave")
