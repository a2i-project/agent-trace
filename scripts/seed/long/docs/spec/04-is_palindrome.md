# 4. is_palindrome

Module: `textkit/strings.py`. Tests: `tests/test_strings.py`.

    is_palindrome(text)

Keep only the ASCII letters and digits of text, lowercased. Return True when that string equals its reverse. The empty string is a palindrome.

Examples:

    is_palindrome("A man, a plan, a canal: Panama") is True
    is_palindrome("abc") is False
    is_palindrome("") is True
    is_palindrome("No 'x' in Nixon") is True
