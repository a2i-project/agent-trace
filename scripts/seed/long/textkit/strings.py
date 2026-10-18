"""String helpers. Each function is specified in docs/spec/."""


# Specified in docs/spec/01-slugify.md.
def slugify(text):
    """Return text as a lowercase slug of letters, digits and hyphens."""
    raise NotImplementedError("slugify")


# Specified in docs/spec/02-truncate.md.
def truncate(text, width):
    """Return text cut to at most width characters, ending in an ellipsis when cut."""
    raise NotImplementedError("truncate")


# Specified in docs/spec/03-wrap_words.md.
def wrap_words(text, width):
    """Return text wrapped into lines of at most width characters."""
    raise NotImplementedError("wrap_words")


# Specified in docs/spec/04-is_palindrome.md.
def is_palindrome(text):
    """Return whether text reads the same backwards, ignoring case and punctuation."""
    raise NotImplementedError("is_palindrome")


# Specified in docs/spec/05-count_vowels.md.
def count_vowels(text):
    """Return the number of vowels in text."""
    raise NotImplementedError("count_vowels")
