import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from wordstats.cli import main


class CliTest(unittest.TestCase):
    def run_cli(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(text)
        self.addCleanup(os.unlink, f.name)
        out = io.StringIO()
        with redirect_stdout(out):
            status = main([f.name])
        return status, out.getvalue()

    def test_prints_most_frequent_first(self):
        status, out = self.run_cli("the cat. The dog. the end")
        self.assertEqual(status, 0)
        self.assertEqual(out.splitlines()[0], "the 3")

    def test_usage_error(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
