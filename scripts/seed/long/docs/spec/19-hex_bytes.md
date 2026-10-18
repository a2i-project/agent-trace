# 19. hex_bytes

Module: `textkit/codec.py`. Tests: `tests/test_codec.py`.

    hex_bytes(text)

Encode text as UTF-8 and return each byte as two lowercase hexadecimal digits, the pairs separated by single spaces.

Examples:

    hex_bytes("Hi") == "48 69"
    hex_bytes("é") == "c3 a9"
    hex_bytes("") == ""
