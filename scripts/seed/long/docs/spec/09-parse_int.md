# 9. parse_int

Module: `textkit/numbers.py`. Tests: `tests/test_numbers.py`.

    parse_int(text, default=None)

Strip surrounding whitespace. When what remains is an optional + or - sign followed by one or more ASCII digits and nothing else, return it as an int. Otherwise return default. Underscores, decimal points and other bases are not accepted.

Examples:

    parse_int(" 42 ") == 42
    parse_int("-7") == -7
    parse_int("x", 0) == 0
    parse_int("1_000") is None
    parse_int("3.0") is None
