import subprocess
import sys
import unittest


class CliTests(unittest.TestCase):
    def test_help_names_file_and_stdin_inputs(self):
        result = subprocess.run(
            [sys.executable, "-m", "agent_tail", "--help"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("JSONL file or - for standard input", result.stdout)


if __name__ == "__main__":
    unittest.main()
