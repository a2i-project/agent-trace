def count_words(text):
    """Return a dict mapping each word to the number of times it occurs.

    Words are compared ignoring case and surrounding punctuation, so
    "Hello," and "hello" are the same word.
    """
    counts = {}
    for word in text.split():
        counts[word] = counts.get(word, 0) + 1
    return counts
