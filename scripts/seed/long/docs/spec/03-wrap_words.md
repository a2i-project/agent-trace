# 3. wrap_words

Module: `textkit/strings.py`. Tests: `tests/test_strings.py`.

    wrap_words(text, width)

Split text on whitespace into words. Fill lines greedily: a word goes on the current line when the line, a space and the word fit in width characters, otherwise it starts a new line. A word longer than width stands alone on its line, unbroken. Return the lines joined by a newline, with no trailing newline. Text with no words gives the empty string.

Examples:

    wrap_words("the quick brown fox", 10) == "the quick\nbrown fox"
    wrap_words("a b c", 1) == "a\nb\nc"
    wrap_words("extraordinary day", 5) == "extraordinary\nday"
    wrap_words("   ", 4) == ""
