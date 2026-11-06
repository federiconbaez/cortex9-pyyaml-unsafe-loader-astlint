"""Regenerate results/ from fixtures/code for a fixed list of PyYAML versions."""
import collections
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from pyyaml_loader_lint.cli import FIELDS, run  # noqa: E402

VERSIONS = [None, "3.13", "5.1", "5.3", "5.3.1", "5.4", "6.0"]


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rows, by_version = [], {}
    for v in VERSIONS:
        findings, errors = run([str(ROOT / "fixtures" / "code")], v)
        assert not errors, errors
        label = v or "unknown"
        by_version[label] = [f.row() for f in findings]
        for f in findings:
            rows.append({"pyyaml_version": label, **f.row()})
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["pyyaml_version"] + FIELDS, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    (out / "findings.csv").write_text(buf.getvalue())
    (out / "findings.json").write_text(json.dumps(by_version, indent=1) + "\n")

    summ = io.StringIO()
    sw = csv.writer(summ, lineterminator="\n")
    sw.writerow(["pyyaml_version", "column", "value", "count"])
    for label, fs in by_version.items():
        for col in ["policy", "cve_2017_18342", "cve_2020_1747", "cve_2020_14343"]:
            for val, n in sorted(collections.Counter(f[col] for f in fs).items()):
                sw.writerow([label, col, val, n])
    (out / "summary.csv").write_text(summ.getvalue())

    sums = "".join(
        f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n"
        for n in ["findings.csv", "findings.json", "summary.csv"])
    (out / "SHA256SUMS").write_text(sums)
    print(f"{len(rows)} rows for {len(VERSIONS)} versions -> {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results")
