# Sources

Fetched 2026-11-06. SHA256 values are of the fetched copies (not committed).

## GitHub advisory database (read with `gh api`, read-only)

| Advisory | Command | Range / patched | CWE | SHA256 |
|---|---|---|---|---|
| GHSA-8q59-q68h-6hv4 (CVE-2020-14343) | `gh api /advisories/GHSA-8q59-q68h-6hv4` | `< 5.4` / 5.4 | CWE-20 | d5b95eca455d571bbdfc52f6e4516080de0557bb6ffc12a3febbb49d7c95cb52 |
| GHSA-6757-jp84-gxfx (CVE-2020-1747) | `gh api "/advisories?cve_id=CVE-2020-1747"` | `>= 5.1b7, < 5.3.1` / 5.3.1 | CWE-20 | 336e570886d914b833d8a1143d5622b1629af1e60be1e1ad0617b0ed9db5c3dd |
| GHSA-rprw-h62v-c2w7 (CVE-2017-18342) | `gh api "/advisories?cve_id=CVE-2017-18342"` | `< 5.1` / 5.1 | CWE-502 | 4a44a6d9c322c6f28bd171b30066eb086f99651f491ee6033e3596101acb8de3 |

Pages: https://github.com/advisories/GHSA-8q59-q68h-6hv4 ,
https://github.com/advisories/GHSA-6757-jp84-gxfx ,
https://github.com/advisories/GHSA-rprw-h62v-c2w7

GHSA-8q59-q68h-6hv4 description (quoted):

> A vulnerability was discovered in the PyYAML library in versions before 5.4,
> where it is susceptible to arbitrary code execution when it processes
> untrusted YAML files through the full_load method or with the FullLoader
> loader. [...] This flaw is due to an incomplete fix for CVE-2020-1747.

GHSA-rprw-h62v-c2w7 (quoted):

> In PyYAML before 5.1, the `yaml.load()` API could execute arbitrary code.

## PyYAML sources (raw.githubusercontent.com/yaml/pyyaml/&lt;tag&gt;/...)

| File | Used for | SHA256 |
|---|---|---|
| 3.13 `lib/yaml/__init__.py` | `def load(stream, Loader=Loader)`; no `full_load`/`unsafe_load` | 433ed620601332d1ef9aefef2e609c1536a2c999f9a6dbf6aec346b1dce59db7 |
| 5.1 `lib/yaml/__init__.py` | `def load(stream, Loader=None)`; `if Loader is None: load_warning('load'); Loader = FullLoader`; adds `full_load*`, `unsafe_load*` | 29eda001269ee22d072d4c5bcfc976094477fffaa9b29bc1048d6096d3b141b1 |
| 5.3.1 `lib/yaml/__init__.py` | same signature as 5.1 | 3f5ab784400fa5f8274a1f44bcb627545e82c8e1412fa0d3fe19d2aa18ed9c65 |
| 5.4 `lib/yaml/__init__.py` | same signature as 5.1 | 6e274eb2bc8c509b454f4843723f1b22151b70a0dc84ec0a29671937ff2b6846 |
| 6.0 `lib/yaml/__init__.py` | `def load(stream, Loader)` (required) | 3434bb4bc5e003bdbe858e8b4661b35164cfbf31b38d656b5a4f8e180fbbec00 |
| 5.4 `lib/yaml/cyaml.py` | `CFullLoader(CParser, FullConstructor, Resolver)`, `CLoader(CParser, Constructor, Resolver)` and the other C loaders | ae508f94e3d1ab9d1fac7291915118be0c3af7125389408e3bf183f429f28511 |
| 3.13 `lib3/yaml/loader.py` | `__all__ = ['BaseLoader', 'SafeLoader', 'Loader']` | (read, not stored) |
| 5.1 `lib3/yaml/loader.py` | adds `FullLoader` and `UnsafeLoader` | (read, not stored) |
| 5.1 and 6.0 `constructor.py` | `class Constructor(UnsafeConstructor)`, so `Loader` is unsafe | (read, not stored) |

`lib3/yaml/__init__.py` at 5.1 and 5.4 was also read: same `load`
signature as `lib/`.

## Fix commit for CVE-2020-14343

- https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc
- Diff SHA256: 06d4adb750796b9bf0efd75ecb3ad7bcd12705b61a9f2ef8b1dddd501b5078db
- The `python/module:`, `python/object:` and `python/object/new:`
  multi-constructors move from `FullConstructor` to `UnsafeConstructor`
  (in `lib/` and `lib3/`).
