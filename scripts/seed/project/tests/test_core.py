import unittest

from wordstats import count_words


class CountWordsTest(unittest.TestCase):
    def test_counts_repeated_words(self):
        self.assertEqual(count_words("a b a"), {"a": 2, "b": 1})

    def test_ignores_case_and_punctuation(self):
        self.assertEqual(count_words("Hello, hello world."), {"hello": 2, "world": 1})

    def test_empty_text(self):
        self.assertEqual(count_words(""), {})


if __name__ == "__main__":
    unittest.main()
