# 16. caesar

Module: `textkit/codec.py`. Tests: `tests/test_codec.py`.

    caesar(text, shift)

Shift every ASCII letter shift places forward in the alphabet, wrapping from z to a and keeping its case; shift may be negative or larger than 26. Every other character is unchanged.

Examples:

    caesar("Abc, xyz", 2) == "Cde, zab"
    caesar("Cde", -2) == "Abc"
    caesar("a", 27) == "b"
