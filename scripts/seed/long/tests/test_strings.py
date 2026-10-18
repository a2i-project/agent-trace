import unittest

from textkit import strings


class StringsTest(unittest.TestCase):
    def test_module_loads(self):
        self.assertTrue(callable(strings.slugify))


if __name__ == "__main__":
    unittest.main()
