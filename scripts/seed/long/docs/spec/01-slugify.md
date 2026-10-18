# 1. slugify

Module: `textkit/strings.py`. Tests: `tests/test_strings.py`.

    slugify(text)

Lowercase the text. Every run of one or more characters that are not an ASCII letter or digit becomes a single hyphen. Leading and trailing hyphens are removed.

Examples:

    slugify("Hello, World!") == "hello-world"
    slugify("  A--b  ") == "a-b"
    slugify("") == ""
    slugify("Ünïcode 2026") == "n-code-2026"
