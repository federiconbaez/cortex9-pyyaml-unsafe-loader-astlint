import json
import unittest
from pathlib import Path

from pyyaml_loader_lint.analyzer import analyze_source
from pyyaml_loader_lint.cli import exit_code, run

ROOT = Path(__file__).resolve().parent.parent
CODE = ROOT / "fixtures" / "code"
EXP = json.loads((ROOT / "fixtures" / "expected.json").read_text())["expected"]
VERSIONS = {"unknown": None, "3.13": "3.13", "5.3": "5.3", "5.4": "5.4", "6.0": "6.0"}


class FixtureExpectations(unittest.TestCase):
    def test_all_fixtures_all_versions(self):
        for label, ver in VERSIONS.items():
            findings, errors = run([str(CODE)], ver)
            self.assertEqual(errors, [])
            got = {f"{f.path}:{f.line}": [f.policy, f.cve_2017_18342, f.cve_2020_1747,
                                          f.cve_2020_14343] for f in findings}
            self.assertEqual(set(got), set(EXP), f"finding locations differ at {label}")
            for k, want in EXP.items():
                with self.subTest(fixture=k, version=label):
                    self.assertEqual(got[k], want[label])


class VersionPrecision(unittest.TestCase):
    SRC = "import yaml\nyaml.load(s, Loader=yaml.FullLoader)\n"

    def status(self, v):
        (f,) = analyze_source(self.SRC, "x.py", v)
        return f.cve_2020_14343, f.cve_2020_1747

    def test_fullloader_on_54_and_later_is_not_flagged_for_14343(self):
        for v in ["5.4", "5.4.1", "6.0", "6.0.1"]:
            self.assertEqual(self.status(v)[0], "NOT_AFFECTED", v)

    def test_boundaries(self):
        self.assertEqual(self.status("5.3.1"), ("AFFECTED", "NOT_AFFECTED"))
        self.assertEqual(self.status("5.4b1"), ("AFFECTED", "NOT_AFFECTED"))
        # 5.1 pre-releases: loader set not modelled, CVE ranges still apply.
        self.assertEqual(self.status("5.1b7"), ("AFFECTED", "AFFECTED"))
        self.assertEqual(self.status("5.1b6"), ("AFFECTED", "NOT_AFFECTED"))

    def test_unparsable_version_is_unknown(self):
        (f,) = analyze_source(self.SRC, "x.py", "latest")
        self.assertEqual(f.cve_2020_14343, "UNKNOWN_VERSION")
        self.assertIn("unparsable", f.notes[0])

    def test_policy_is_independent_of_cve(self):
        a = analyze_source(self.SRC, "x.py", "5.3")[0]
        b = analyze_source(self.SRC, "x.py", "6.0")[0]
        self.assertEqual(a.policy, b.policy)
        self.assertEqual(a.policy, "CONSERVATIVE_WARN")


class Resolution(unittest.TestCase):
    def one(self, src, v="5.4"):
        fs = analyze_source(src, "x.py", v)
        self.assertEqual(len(fs), 1, fs)
        return fs[0]

    def test_alias_module(self):
        f = self.one("import yaml as y\ny.unsafe_load(s)\n")
        self.assertEqual((f.resolution, f.policy), ("RESOLVED", "UNSAFE_BY_DESIGN"))

    def test_alias_member(self):
        f = self.one("from yaml import load as l, SafeLoader as S\nl(s, S)\n")
        self.assertEqual(f.policy, "SAFE")

    def test_local_rebinding_of_alias(self):
        f = self.one("from yaml import load as l\nl = lambda s: s\nl(s)\n")
        self.assertEqual(f.resolution, "NEEDS_HUMAN")

    def test_comprehension_target_shadows(self):
        f = self.one("import yaml\n[yaml.load(s) for yaml in mods]\n")
        self.assertEqual(f.resolution, "NEEDS_HUMAN")

    def test_non_yaml_module_with_same_attr(self):
        self.assertEqual(analyze_source("import json\njson.load(s)\n", "x.py", "5.4"), [])

    def test_unimported_name_is_ignored(self):
        self.assertEqual(analyze_source("load(s)\n", "x.py", "5.4"), [])


class ExitCodes(unittest.TestCase):
    def test_codes(self):
        safe = analyze_source("import yaml\nyaml.safe_load(s)\n", "a.py", "5.4")
        warn = analyze_source("import yaml\nyaml.full_load(s)\n", "a.py", "5.4")
        bad = analyze_source("import yaml\nyaml.full_load(s)\n", "a.py", "5.3")
        nh = analyze_source("import yaml\nyaml.load(s, Loader=L)\n", "a.py", "5.4")
        self.assertEqual(exit_code(safe, [], False), 0)
        self.assertEqual(exit_code(warn, [], False), 0)
        self.assertEqual(exit_code(warn, [], True), 1)
        self.assertEqual(exit_code(bad, [], False), 1)
        self.assertEqual(exit_code(nh, [], False), 3)


class NoExecution(unittest.TestCase):
    def test_fixture_that_raises_on_import_is_only_parsed(self):
        fs = analyze_source((CODE / "f20_not_executed.py").read_text(), "f20", "5.4")
        self.assertEqual([f.policy for f in fs], ["SAFE"])

    def test_fixtures_contain_no_yaml_documents_or_tags(self):
        for p in CODE.glob("*.py"):
            t = p.read_text()
            self.assertNotIn("!!python", t, p.name)
            self.assertNotIn("python/object", t, p.name)


if __name__ == "__main__":
    unittest.main()
