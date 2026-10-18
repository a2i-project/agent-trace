import unittest

from textkit import codec


class CodecTest(unittest.TestCase):
    def test_module_loads(self):
        self.assertTrue(callable(codec.caesar))


if __name__ == "__main__":
    unittest.main()
