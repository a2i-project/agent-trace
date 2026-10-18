# 17. rle_encode

Module: `textkit/codec.py`. Tests: `tests/test_codec.py`.

    rle_encode(text)

Replace every run of one repeated character by the run's length in decimal followed by the character. The empty string encodes to the empty string. Text that contains an ASCII digit raises ValueError.

Examples:

    rle_encode("aaabcc") == "3a1b2c"
    rle_encode("") == ""
    rle_encode("x" * 12) == "12x"
    rle_encode("a1") raises ValueError
