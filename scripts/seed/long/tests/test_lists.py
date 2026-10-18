import unittest

from textkit import lists


class ListsTest(unittest.TestCase):
    def test_module_loads(self):
        self.assertTrue(callable(lists.chunk))


if __name__ == "__main__":
    unittest.main()
