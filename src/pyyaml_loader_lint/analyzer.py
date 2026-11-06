"""AST analysis. Parses source text with `ast.parse`; never imports or executes it."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field, asdict

from . import versions as vm

YAML_MODULES = {"yaml", "yaml.cyaml", "yaml.loader"}
LOAD_FUNCS = vm.FUNCS_5
LOADER_NAMES = set(vm.FAMILY)
INTERESTING = LOAD_FUNCS | LOADER_NAMES

OTHER = ("other",)


@dataclass
class Finding:
    path: str
    line: int
    col: int
    call: str
    resolution: str            # RESOLVED | NEEDS_HUMAN
    effective_loader: str | None
    policy: str
    cve_2017_18342: str
    cve_2020_1747: str
    cve_2020_14343: str
    notes: list[str] = field(default_factory=list)

    def row(self) -> dict:
        d = asdict(self)
        d["notes"] = "; ".join(self.notes)
        return d


class _Bindings(ast.NodeVisitor):
    """Collect every binding of every name in the module, flow-insensitively."""

    def __init__(self) -> None:
        self.b: dict[str, set[tuple]] = {}
        self.star_from_yaml = False

    def add(self, name: str, kind: tuple) -> None:
        self.b.setdefault(name, set()).add(kind)

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            if a.name == "yaml" or a.name.startswith("yaml."):
                if a.asname:
                    self.add(a.asname, ("module", a.name))
                else:
                    self.add("yaml", ("module", "yaml"))
            else:
                self.add(a.asname or a.name.split(".")[0], OTHER)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        is_yaml = node.level == 0 and mod in YAML_MODULES
        for a in node.names:
            if a.name == "*":
                if is_yaml:
                    self.star_from_yaml = True
                continue
            self.add(a.asname or a.name, ("member", a.name) if is_yaml else OTHER)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.add(node.id, OTHER)

    def visit_arg(self, node: ast.arg) -> None:
        self.add(node.arg, OTHER)
        self.generic_visit(node)

    def _def(self, node) -> None:
        self.add(node.name, OTHER)
        self.generic_visit(node)

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _def

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.add(node.name, OTHER)
        self.generic_visit(node)

    def visit_MatchAs(self, node) -> None:
        if node.name:
            self.add(node.name, OTHER)
        self.generic_visit(node)

    def visit_MatchStar(self, node) -> None:
        if node.name:
            self.add(node.name, OTHER)

    def visit_MatchMapping(self, node) -> None:
        if node.rest:
            self.add(node.rest, OTHER)
        self.generic_visit(node)

    # `global`/`nonlocal` do not bind by themselves; a following assignment
    # is caught by visit_Name.


class _Ambiguous:
    def __init__(self, reason: str, hint: str | None = None) -> None:
        self.reason = reason
        self.hint = hint  # yaml member name when known


def _resolve(expr: ast.AST, bnd: _Bindings):
    """Return ('module', m) | ('member', name) | _Ambiguous | None."""
    if isinstance(expr, ast.Name):
        kinds = bnd.b.get(expr.id, set())
        yaml_kinds = {k for k in kinds if k[0] in ("module", "member")}
        if not yaml_kinds:
            if not kinds and bnd.star_from_yaml and expr.id in INTERESTING:
                return _Ambiguous(f"'{expr.id}' may come from 'from yaml import *'", expr.id)
            return None
        if len(yaml_kinds) == 1 and len(kinds) == 1:
            return next(iter(yaml_kinds))
        hint = next((k[1] for k in yaml_kinds if k[0] == "member"), None)
        return _Ambiguous(f"name '{expr.id}' is bound more than once (shadowing or rebinding)", hint)
    if isinstance(expr, ast.Attribute):
        base = _resolve(expr.value, bnd)
        if base is None:
            return None
        if isinstance(base, _Ambiguous):
            if base.hint is None and expr.attr in INTERESTING:
                return _Ambiguous(base.reason, expr.attr)
            return base if expr.attr in INTERESTING else None
        if base[0] == "module":
            if base[1] == "yaml" and expr.attr in ("cyaml", "loader"):
                return ("module", "yaml." + expr.attr)
            return ("member", expr.attr)
        return None
    return None


def _call_name(func: ast.AST) -> str:
    try:
        return ast.unparse(func)
    except Exception:  # pragma: no cover
        return "<call>"


def _cve_full(v) -> tuple[str, str]:
    """Status of CVE-2020-1747 and CVE-2020-14343 for a FullConstructor-family load."""
    if v is None:
        return "UNKNOWN_VERSION", "UNKNOWN_VERSION"
    _, lo, hi = vm.CVE_2020_1747
    a = "AFFECTED" if vm.in_range(v, lo, hi) else "NOT_AFFECTED"
    _, lo, hi = vm.CVE_2020_14343
    b = "AFFECTED" if vm.in_range(v, lo, hi) else "NOT_AFFECTED"
    return a, b


def classify(func_member: str, loader_expr, has_star: bool, v, bnd) -> dict:
    """Pure classification given the resolved callee and Loader expression."""
    notes: list[str] = []
    gen = vm.api_generation(v)
    funcs, loaders = vm.funcs_for(v), vm.loaders_for(v)
    out = dict(resolution="RESOLVED", effective_loader=None, policy="",
               cve_2017_18342="NOT_APPLICABLE", cve_2020_1747="NOT_APPLICABLE",
               cve_2020_14343="NOT_APPLICABLE")
    default_used = False

    if func_member in LOADER_NAMES:
        loader = func_member
        notes.append("direct Loader construction")
    elif func_member in vm.FUNC_LOADER:
        loader = vm.FUNC_LOADER[func_member]
    else:  # load / load_all
        if loader_expr is None:
            if has_star:
                out.update(resolution="NEEDS_HUMAN", policy="NEEDS_HUMAN",
                           cve_2017_18342="NEEDS_HUMAN", cve_2020_1747="NEEDS_HUMAN",
                           cve_2020_14343="NEEDS_HUMAN")
                notes.append("*args/**kwargs may carry Loader")
                out["notes"] = notes
                return out
            default_used = True
            loader = None
        elif isinstance(loader_expr, ast.Constant) and loader_expr.value is None:
            default_used = True
            loader = None
            notes.append("explicit Loader=None")
        else:
            r = _resolve(loader_expr, bnd)
            if isinstance(r, tuple) and r[0] == "member" and r[1] in LOADER_NAMES:
                loader = r[1]
            else:
                why = r.reason if isinstance(r, _Ambiguous) else "Loader is not a statically known PyYAML loader"
                out.update(resolution="NEEDS_HUMAN", policy="NEEDS_HUMAN",
                           cve_2017_18342="NOT_APPLICABLE", cve_2020_1747="NEEDS_HUMAN",
                           cve_2020_14343="NEEDS_HUMAN")
                notes.append(why + f": {ast.unparse(loader_expr)}")
                out["notes"] = notes
                return out

    if funcs is not None and func_member in LOAD_FUNCS and func_member not in funcs:
        out.update(policy="NOT_IN_VERSION")
        notes.append(f"{func_member} does not exist in PyYAML {v.text}")
        out["notes"] = notes
        return out
    if loaders is not None and loader is not None and loader not in loaders:
        out.update(policy="NOT_IN_VERSION", effective_loader=loader)
        notes.append(f"{loader} does not exist in PyYAML {v.text}")
        out["notes"] = notes
        return out

    if default_used:
        if v is not None:
            _, _, hi = vm.CVE_2017_18342
            out["cve_2017_18342"] = "AFFECTED" if v < hi else "NOT_AFFECTED"
        else:
            out["cve_2017_18342"] = "UNKNOWN_VERSION"
        if gen == "legacy":
            loader = "Loader"
            notes.append("default Loader=Loader (pre-5.1 signature)")
            if "explicit Loader=None" in notes:
                out.update(policy="TYPE_ERROR_IN_VERSION", effective_loader=None,
                           cve_2017_18342="NOT_APPLICABLE")
                notes.append("Loader=None is called as a class: TypeError")
                out["notes"] = notes
                return out
        elif gen == "full":
            loader = "FullLoader"
            notes.append("Loader=None defaults to FullLoader with a warning (5.1 to 5.x signature)")
        elif gen == "required":
            out.update(policy="TYPE_ERROR_IN_VERSION")
            notes.append("Loader is a required argument in 6.0+")
            out["notes"] = notes
            return out
        else:
            out.update(policy="DEPENDS_ON_VERSION",
                       cve_2020_1747="UNKNOWN_VERSION", cve_2020_14343="UNKNOWN_VERSION")
            notes.append("default Loader depends on version: Loader (<5.1), FullLoader (5.1..5.x), required (6.0+)")
            out["notes"] = notes
            return out

    out["effective_loader"] = loader
    fam = vm.FAMILY[loader]
    if fam == "unsafe":
        out["policy"] = "UNSAFE_BY_DESIGN"
    elif fam == "full":
        out["policy"] = "CONSERVATIVE_WARN"
        a, b = _cve_full(v)
        out["cve_2020_1747"], out["cve_2020_14343"] = a, b
        if loader.startswith("C"):
            notes.append("INFERENCE: CVE status copied from FullLoader because cyaml.py builds CFullLoader on FullConstructor; advisories name only full_load/FullLoader")
    else:
        out["policy"] = "SAFE"
    out["notes"] = notes
    return out


def analyze_source(src: str, path: str, version: str | None) -> list[Finding]:
    v = vm.parse_version(version)
    notes_v = []
    if version is not None and v is None:
        notes_v.append(f"unparsable version '{version}' treated as unknown")
    tree = ast.parse(src, filename=path)
    bnd = _Bindings()
    bnd.visit(tree)
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        # Dynamic access that a static pass cannot follow.
        if isinstance(f, ast.Name) and f.id in ("getattr", "__import__") and node.args:
            tgt = node.args[0]
            dyn = False
            if f.id == "getattr":
                r = _resolve(tgt, bnd)
                dyn = isinstance(r, tuple) and r[0] == "module" or isinstance(r, _Ambiguous)
            elif isinstance(tgt, ast.Constant) and tgt.value in YAML_MODULES:
                dyn = True
            if dyn:
                findings.append(_nh(path, node, "dynamic access to the yaml module", notes_v))
            continue
        if isinstance(f, ast.Attribute) and f.attr == "import_module" and node.args \
                and isinstance(node.args[0], ast.Constant) and node.args[0].value in YAML_MODULES:
            findings.append(_nh(path, node, "importlib.import_module of yaml", notes_v))
            continue

        r = _resolve(f, bnd)
        if r is None:
            continue
        if isinstance(r, _Ambiguous):
            if r.hint in INTERESTING:
                findings.append(_nh(path, node, r.reason, notes_v))
            continue
        if r[0] != "member" or r[1] not in INTERESTING:
            continue
        member = r[1]
        loader_expr = None
        for kw in node.keywords:
            if kw.arg == "Loader":
                loader_expr = kw.value
        if loader_expr is None and len(node.args) >= 2 and member in ("load", "load_all"):
            loader_expr = node.args[1]
        has_star = any(isinstance(a, ast.Starred) for a in node.args) or any(
            kw.arg is None for kw in node.keywords)
        c = classify(member, loader_expr, has_star, v, bnd)
        findings.append(Finding(path=path, line=node.lineno, col=node.col_offset,
                                call=_call_name(f), notes=notes_v + c.pop("notes"), **c))
    findings.sort(key=lambda x: (x.path, x.line, x.col))
    return findings


def _nh(path, node, reason, notes_v) -> Finding:
    return Finding(path=path, line=node.lineno, col=node.col_offset, call=_call_name(node.func),
                   resolution="NEEDS_HUMAN", effective_loader=None, policy="NEEDS_HUMAN",
                   cve_2017_18342="NEEDS_HUMAN", cve_2020_1747="NEEDS_HUMAN",
                   cve_2020_14343="NEEDS_HUMAN", notes=notes_v + [reason])
