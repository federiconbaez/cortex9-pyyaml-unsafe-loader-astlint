"""Checks the claims made in PRACTICE.md."""
import unittest

from pyyaml_loader_lint.analyzer import analyze_source


class PracticeClaims(unittest.TestCase):
    def test_ex3_loader_from_unimported_module_needs_human(self):
        (f,) = analyze_source("from yaml import load\nload(s, Loader=yaml.FullLoader)\n", "x.py", "5.4")
        self.assertEqual(f.resolution, "NEEDS_HUMAN")

    def test_ex3_unsafeloader_missing_in_313(self):
        (f,) = analyze_source("import yaml\nyaml.load(s, Loader=yaml.UnsafeLoader)\n", "x.py", "3.13")
        self.assertEqual(f.policy, "NOT_IN_VERSION")

    def test_ex2_531_fixes_1747_not_14343(self):
        (f,) = analyze_source("import yaml\nyaml.full_load(s)\n", "x.py", "5.3.1")
        self.assertEqual((f.cve_2020_1747, f.cve_2020_14343), ("NOT_AFFECTED", "AFFECTED"))


if __name__ == "__main__":
    unittest.main()
