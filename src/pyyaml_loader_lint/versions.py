"""PyYAML version model.

Every fact here was read from PyYAML sources at the named tag or from the
GitHub advisory JSON (see SOURCES.md). Nothing is inferred from names.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_VER = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:(a|b|rc)(\d+))?$")
_PRE_ORDER = {"a": 0, "b": 1, "rc": 2}


@dataclass(frozen=True, order=True)
class Version:
    """Comparable release with optional pre-release (a/b/rc)."""

    key: tuple

    @property
    def text(self) -> str:
        major, minor, micro, pre_rank, pre_n = self.key
        s = f"{major}.{minor}" + (f".{micro}" if micro else "")
        if pre_rank < 3:
            s += [k for k, v in _PRE_ORDER.items() if v == pre_rank][0] + str(pre_n)
        return s

    @property
    def is_prerelease(self) -> bool:
        return self.key[3] < 3


def parse_version(s: str | None) -> Version | None:
    """Return a Version, or None when s is absent or not understood."""
    if s is None:
        return None
    m = _VER.match(s.strip())
    if not m:
        return None
    major, minor, micro, pre, pre_n = m.groups()
    rank = _PRE_ORDER[pre] if pre else 3
    return Version((int(major), int(minor), int(micro or 0), rank, int(pre_n or 0)))


def V(s: str) -> Version:
    v = parse_version(s)
    assert v is not None, s
    return v


# Loader classes present in yaml/loader.py (and yaml/cyaml.py when libyaml is
# available) by tag. 3.13: BaseLoader, SafeLoader, Loader.
# 5.1+: BaseLoader, FullLoader, SafeLoader, Loader, UnsafeLoader.
LOADERS_3 = {"BaseLoader", "SafeLoader", "Loader", "CBaseLoader", "CSafeLoader", "CLoader"}
LOADERS_5 = LOADERS_3 | {"FullLoader", "UnsafeLoader", "CFullLoader", "CUnsafeLoader"}

# Module-level loading functions by tag (yaml/__init__.py).
FUNCS_3 = {"load", "load_all", "safe_load", "safe_load_all"}
FUNCS_5 = FUNCS_3 | {"full_load", "full_load_all", "unsafe_load", "unsafe_load_all"}

# Loader class -> constructor family (yaml/loader.py, yaml/cyaml.py).
FAMILY = {
    "BaseLoader": "base", "CBaseLoader": "base",
    "SafeLoader": "safe", "CSafeLoader": "safe",
    "FullLoader": "full", "CFullLoader": "full",
    "Loader": "unsafe", "CLoader": "unsafe",
    "UnsafeLoader": "unsafe", "CUnsafeLoader": "unsafe",
}

# Helper function -> Loader it passes (yaml/__init__.py, 5.1..6.0).
FUNC_LOADER = {
    "safe_load": "SafeLoader", "safe_load_all": "SafeLoader",
    "full_load": "FullLoader", "full_load_all": "FullLoader",
    "unsafe_load": "UnsafeLoader", "unsafe_load_all": "UnsafeLoader",
}

# Advisory ranges (GitHub advisory database JSON).
CVE_2017_18342 = ("GHSA-rprw-h62v-c2w7", None, V("5.1"))          # < 5.1
CVE_2020_1747 = ("GHSA-6757-jp84-gxfx", V("5.1b7"), V("5.3.1"))   # >=5.1b7,<5.3.1
CVE_2020_14343 = ("GHSA-8q59-q68h-6hv4", None, V("5.4"))          # < 5.4


def in_range(v: Version, lo: Version | None, hi: Version) -> bool:
    return (lo is None or v >= lo) and v < hi


def api_generation(v: Version | None) -> str:
    """Which `load()` signature applies.

    legacy  (<5.1 final): load(stream, Loader=Loader)  -> default is unsafe Loader
    full    (5.1..<6.0):  load(stream, Loader=None)    -> warns, uses FullLoader
    required(>=6.0):      load(stream, Loader)         -> Loader is mandatory
    unknown: version missing, unparsable, or a 5.1 pre-release (default not modelled)
    """
    if v is None:
        return "unknown"
    if v < V("5.1"):
        if v >= V("5.1a0"):
            return "unknown"
        return "legacy"
    if v < V("6.0"):
        return "full"
    return "required"


def loaders_for(v: Version | None) -> set[str] | None:
    if v is None or api_generation(v) == "unknown":
        return None
    return LOADERS_3 if v < V("5.1") else LOADERS_5


def funcs_for(v: Version | None) -> set[str] | None:
    if v is None or api_generation(v) == "unknown":
        return None
    return FUNCS_3 if v < V("5.1") else FUNCS_5
