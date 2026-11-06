# cortex9-pyyaml-unsafe-loader-astlint

[Español](README.es.md) · [Practice guide](PRACTICE.md) · [CI](https://github.com/federiconbaez/cortex9-pyyaml-unsafe-loader-astlint/actions/workflows/ci.yml)

A static checker that reads Python source with `ast.parse` and reports every
PyYAML loading call it can resolve, with three **separate** answers:

1. **Policy** (version-independent where possible): `SAFE`,
   `CONSERVATIVE_WARN`, `UNSAFE_BY_DESIGN`, plus `DEPENDS_ON_VERSION`,
   `TYPE_ERROR_IN_VERSION`, `NOT_IN_VERSION`, `NEEDS_HUMAN`.
2. **CVE status** per advisory, given the PyYAML version you pass:
   `AFFECTED`, `NOT_AFFECTED`, `NOT_APPLICABLE`, `UNKNOWN_VERSION`,
   `NEEDS_HUMAN`.
3. **Resolution**: `RESOLVED` or `NEEDS_HUMAN` (aliases it cannot prove,
   shadowing, star imports, dynamic access, `**kwargs`).

It never imports, runs or loads anything it analyses, and the repository
contains no YAML documents or payloads. **It is a linter, not a reproduction
of any CVE.**

## Version model (read from PyYAML sources and GitHub advisories)

| PyYAML | `load()` signature | Default loader |
|---|---|---|
| < 5.1 (3.13 read) | `load(stream, Loader=Loader)` | `Loader` (unsafe) |
| 5.1 – 5.x (5.1, 5.3.1, 5.4 read) | `load(stream, Loader=None)` | warns, `FullLoader` |
| ≥ 6.0 (6.0 read) | `load(stream, Loader)` | none: `TypeError` |

| Advisory | Range | Applies to |
|---|---|---|
| CVE-2017-18342 / GHSA-rprw-h62v-c2w7 | `< 5.1` | `load()` using the default loader |
| CVE-2020-1747 / GHSA-6757-jp84-gxfx | `>= 5.1b7, < 5.3.1` | `full_load` / `FullLoader` |
| CVE-2020-14343 / GHSA-8q59-q68h-6hv4 | `< 5.4` | `full_load` / `FullLoader` |

Consequences encoded in the tool:

- `FullLoader` on 5.4 or later is **not** reported as affected by
  CVE-2020-14343. Its policy stays `CONSERVATIVE_WARN`, because recommending
  `SafeLoader` for untrusted input is a separate, conservative choice.
- **Inference (labelled in every finding's `notes`):** `CFullLoader` gets
  the same CVE status as `FullLoader`, because `yaml/cyaml.py` builds it on
  `FullConstructor`. The advisories only name `full_load` and `FullLoader`;
  this was not confirmed by running the C extension.
- `Loader`, `UnsafeLoader`, `CLoader`, `CUnsafeLoader` and `unsafe_load*` are
  `UNSAFE_BY_DESIGN`. They are documented as unsafe, so they are not CVEs.
- With no `--pyyaml-version`, a call whose answer depends on the version is
  reported as `UNKNOWN_VERSION` or `DEPENDS_ON_VERSION`, not as affected.

## Usage

```sh
PYTHONPATH=src python3 -m pyyaml_loader_lint path/to/code --pyyaml-version 5.4
PYTHONPATH=src python3 -m pyyaml_loader_lint path/to/code --format csv
# or, in a venv: python3 -m venv .venv && . .venv/bin/activate && pip install . && pyyaml-loader-lint ...
```

Exit codes: `0` nothing blocking; `1` `UNSAFE_BY_DESIGN` or any `AFFECTED`
(also `CONSERVATIVE_WARN` with `--fail-on-warn`); `2` parse error; `3` only
items that need a human or a version.

## Tests and results

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/gen_results.py            # rewrites results/
(cd results && sha256sum -c SHA256SUMS)
```

- `fixtures/code/` has 24 small Python files (code only, no YAML).
  `fixtures/expected.json` holds hand-written expectations for 25 call sites
  × 5 versions (unknown, 3.13, 5.3, 5.4, 6.0), checked by the tests. `f18`
  must produce no finding.
- `results/` holds 175 rows (25 findings × 7 versions: unknown, 3.13, 5.1,
  5.3, 5.3.1, 5.4, 6.0) in CSV and JSON, a per-version summary and
  `SHA256SUMS`.
- Example from `results/summary.csv`, CVE-2020-14343 column: 7 `AFFECTED` at
  5.3, 0 at 5.4 (7 `NOT_AFFECTED`), 7 `UNKNOWN_VERSION` with no version; 8
  `NEEDS_HUMAN` in every version.

Tested locally with Python 3.13.5 and 3.10. Standard library only.

**Coverage is static, not runtime.** The tool sees only calls it can resolve
in one file. It does not observe what runs at runtime, does not follow
imports across modules, and does not claim to find every PyYAML load in a
program. No external verification of results has been performed.

## Files to read first

`src/pyyaml_loader_lint/versions.py` (version facts),
`src/pyyaml_loader_lint/analyzer.py` (binding collection, resolution,
`classify`), `tests/test_fixtures.py`.

See [SOURCES.md](SOURCES.md) and [LIMITATIONS.md](LIMITATIONS.md).
License: Apache-2.0.
