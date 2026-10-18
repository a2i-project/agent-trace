# 18. rle_decode

Module: `textkit/codec.py`. Tests: `tests/test_codec.py`.

    rle_decode(code)

The inverse of rle_encode: code is a sequence of a decimal count of one or more digits followed by one character that is not a digit. Return the characters repeated by their counts. A character without a count before it, a count of zero, or a count at the end raises ValueError.

Examples:

    rle_decode("3a1b2c") == "aaabcc"
    rle_decode("12x") == "x" * 12
    rle_decode("") == ""
    rle_decode("a") raises ValueError
    rle_decode("3") raises ValueError
