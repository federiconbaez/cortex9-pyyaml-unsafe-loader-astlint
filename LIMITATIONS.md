# Limitations

- **Static and flow-insensitive.** A name is treated as a PyYAML binding only
  if every binding of that name in the file comes from one PyYAML import.
  Any other binding anywhere in the file (assignment, parameter, def/class,
  loop or comprehension target, `except ... as`, match pattern, `del`) makes
  calls through that name `NEEDS_HUMAN`. This is conservative: some safe code
  is sent to a human.
- **Per file.** Re-exports across modules (`from mypkg import load` where
  `mypkg` re-exports PyYAML) are not followed and produce no finding.
- **Custom loaders.** Subclasses of PyYAML loaders, or loaders with extra
  constructors registered via `add_constructor`/`add_multi_constructor`, are
  `NEEDS_HUMAN` (when passed as `Loader=`) or not analysed.
- **Not covered:** `scan`, `parse`, `compose*`, dumping functions,
  `yaml.YAMLObject` subclasses, and other YAML libraries (ruamel.yaml etc.).
- **Version input is trusted.** The tool does not read installed packages or
  lock files. Without `--pyyaml-version`, results are `UNKNOWN_VERSION` or
  `DEPENDS_ON_VERSION`. PyYAML 5.1 pre-releases are treated as "loader set
  not modelled"; the advisory ranges are still applied to them.
- **No runtime coverage.** The tool never runs code, so it cannot see loads
  reached through dynamic dispatch, other modules, or generated code. It is
  not a complete inventory of PyYAML use.
- **CFullLoader (inference)** shares `FullConstructor` with `FullLoader` in
  `yaml/cyaml.py`; giving it the same CVE status is an inference from source,
  not a statement in the advisories.
- **Policy is a recommendation.** `CONSERVATIVE_WARN` for `FullLoader` on
  ≥ 5.4 is a conservative choice, not a vulnerability claim.
- **No exploitation content.** The tool and the fixtures contain no YAML
  documents. Nothing here demonstrates code execution.
- CI is defined in `.github/workflows/ci.yml` and runs on GitHub Actions
  (Python 3.10–3.13; live status: the Actions page linked from the README).
  It was also run locally with Python 3.13.5 and 3.10.
