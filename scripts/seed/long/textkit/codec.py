"""Encoding helpers. Each function is specified in docs/spec/."""


# Specified in docs/spec/16-caesar.md.
def caesar(text, shift):
    """Return text with each ASCII letter shifted by shift places."""
    raise NotImplementedError("caesar")


# Specified in docs/spec/17-rle_encode.md.
def rle_encode(text):
    """Return the run-length encoding of text."""
    raise NotImplementedError("rle_encode")


# Specified in docs/spec/18-rle_decode.md.
def rle_decode(code):
    """Return the text whose run-length encoding is code."""
    raise NotImplementedError("rle_decode")


# Specified in docs/spec/19-hex_bytes.md.
def hex_bytes(text):
    """Return the UTF-8 bytes of text as hexadecimal pairs."""
    raise NotImplementedError("hex_bytes")


# Specified in docs/spec/20-checksum.md.
def checksum(text):
    """Return the 16-bit sum of the UTF-8 bytes of text."""
    raise NotImplementedError("checksum")
