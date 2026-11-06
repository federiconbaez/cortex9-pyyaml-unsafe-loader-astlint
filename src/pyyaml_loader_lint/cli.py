"""Command line interface.

Exit codes: 0 no blocking finding; 1 UNSAFE_BY_DESIGN or any CVE AFFECTED
(or CONSERVATIVE_WARN with --fail-on-warn); 2 usage or parse error;
3 only NEEDS_HUMAN / DEPENDS_ON_VERSION / UNKNOWN_VERSION remain.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import Finding, analyze_source

FIELDS = ["path", "line", "col", "call", "resolution", "effective_loader", "policy",
          "cve_2017_18342", "cve_2020_1747", "cve_2020_14343", "notes"]


def iter_files(paths: list[str]) -> list[tuple[Path, str]]:
    out = []
    for p in paths:
        P = Path(p)
        if P.is_dir():
            for f in sorted(P.rglob("*.py")):
                out.append((f, f.relative_to(P).as_posix()))
        else:
            out.append((P, P.name))
    return out


def run(paths: list[str], version: str | None) -> tuple[list[Finding], list[dict]]:
    findings, errors = [], []
    for f, rel in iter_files(paths):
        try:
            src = f.read_text(encoding="utf-8")
            findings.extend(analyze_source(src, rel, version))
        except (SyntaxError, UnicodeDecodeError) as e:
            errors.append({"path": rel, "error": f"{type(e).__name__}: {e}"})
    return findings, errors


def exit_code(findings: list[Finding], errors: list[dict], fail_on_warn: bool) -> int:
    if errors:
        return 2
    cves = lambda f: (f.cve_2017_18342, f.cve_2020_1747, f.cve_2020_14343)
    if any(f.policy == "UNSAFE_BY_DESIGN" or "AFFECTED" in cves(f) for f in findings):
        return 1
    if fail_on_warn and any(f.policy == "CONSERVATIVE_WARN" for f in findings):
        return 1
    if any(f.resolution == "NEEDS_HUMAN" or f.policy == "DEPENDS_ON_VERSION"
           or "UNKNOWN_VERSION" in cves(f) for f in findings):
        return 3
    return 0


def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\n")
    w.writeheader()
    for f in findings:
        w.writerow(f.row())
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pyyaml-loader-lint",
                                 description="Static check of PyYAML loader usage (no code execution).")
    ap.add_argument("paths", nargs="+", help="Python files or directories")
    ap.add_argument("--pyyaml-version", default=None,
                    help="installed PyYAML version, e.g. 5.3.1; omitted means unknown")
    ap.add_argument("--format", choices=["json", "csv"], default="json")
    ap.add_argument("--fail-on-warn", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    findings, errors = run(a.paths, a.pyyaml_version)
    if a.format == "csv":
        sys.stdout.write(to_csv(findings))
        for e in errors:
            print(f"error: {e['path']}: {e['error']}", file=sys.stderr)
    else:
        json.dump({"pyyaml_version": a.pyyaml_version, "findings": [f.row() for f in findings],
                   "errors": errors}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return exit_code(findings, errors, a.fail_on_warn)


if __name__ == "__main__":
    raise SystemExit(main())
