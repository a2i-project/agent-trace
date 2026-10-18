# 2. truncate

Module: `textkit/strings.py`. Tests: `tests/test_strings.py`.

    truncate(text, width)

When text has at most width characters, return it unchanged. Otherwise return its first width - 3 characters followed by three dots, so the result has exactly width characters. A width below 3 raises ValueError.

Examples:

    truncate("abcdef", 5) == "ab..."
    truncate("abc", 3) == "abc"
    truncate("abcd", 3) == "..."
    truncate("abc", 2) raises ValueError
