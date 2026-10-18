import unittest

from textkit import numbers


class NumbersTest(unittest.TestCase):
    def test_module_loads(self):
        self.assertTrue(callable(numbers.clamp))


if __name__ == "__main__":
    unittest.main()
