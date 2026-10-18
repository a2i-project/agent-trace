# 20. checksum

Module: `textkit/codec.py`. Tests: `tests/test_codec.py`.

    checksum(text)

Encode text as UTF-8 and return the sum of its byte values modulo 65536, as an int.

Examples:

    checksum("abc") == 294
    checksum("") == 0
    checksum("é") == 364
