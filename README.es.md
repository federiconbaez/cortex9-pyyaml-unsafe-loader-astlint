# cortex9-pyyaml-unsafe-loader-astlint

[English](README.md) · [Guía práctica](PRACTICE.md)

Verificador estático que lee código Python con `ast.parse` y reporta cada
llamada de carga de PyYAML que puede resolver, con tres respuestas
**separadas**:

1. **Política**: `SAFE`, `CONSERVATIVE_WARN`, `UNSAFE_BY_DESIGN`, y además
   `DEPENDS_ON_VERSION`, `TYPE_ERROR_IN_VERSION`, `NOT_IN_VERSION`,
   `NEEDS_HUMAN`.
2. **Estado por CVE** según la versión que indiques: `AFFECTED`,
   `NOT_AFFECTED`, `NOT_APPLICABLE`, `UNKNOWN_VERSION`, `NEEDS_HUMAN`.
3. **Resolución**: `RESOLVED` o `NEEDS_HUMAN` (alias no demostrables,
   sombreado, `import *`, acceso dinámico, `**kwargs`).

Nunca importa ni ejecuta lo que analiza, y el repositorio no contiene
documentos YAML ni payloads. **Es un linter, no una reproducción de un CVE.**

## Modelo de versiones

- < 5.1: `load(stream, Loader=Loader)`, por defecto inseguro
  (CVE-2017-18342, `< 5.1`).
- 5.1 a 5.x: `load(stream, Loader=None)`, avisa y usa `FullLoader`.
- ≥ 6.0: `Loader` obligatorio; sin él, `TypeError`.
- CVE-2020-1747: `>= 5.1b7, < 5.3.1`. CVE-2020-14343: `< 5.4`. Ambos se
  aplican a `full_load` y `FullLoader`.

`FullLoader` en 5.4 o posterior **no** se marca como afectado por
CVE-2020-14343; su política sigue siendo `CONSERVATIVE_WARN` (recomendar
`SafeLoader` para entrada no confiable es una decisión aparte). Sin
`--pyyaml-version`, lo que depende de la versión sale `UNKNOWN_VERSION` o
`DEPENDS_ON_VERSION`.

## Uso y pruebas

```sh
PYTHONPATH=src python -m pyyaml_loader_lint ruta/al/codigo --pyyaml-version 5.4
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/gen_results.py && (cd results && sha256sum -c SHA256SUMS)
```

Los resultados (175 filas, 7 versiones) y sus conteos están descritos en
[README.md](README.md#tests-and-results). Ver [SOURCES.md](SOURCES.md) y
[LIMITATIONS.md](LIMITATIONS.md). Licencia Apache-2.0.
