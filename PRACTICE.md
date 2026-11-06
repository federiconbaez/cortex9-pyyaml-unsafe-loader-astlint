# Guía práctica / Practice guide

Ejercicios **offline y locales** de revisión de código defensiva. No hay
YAML malicioso, no se ejecuta nada de lo analizado y no se interactúa con
ningún host ni laboratorio. *English summary at the end.*

## Objetivos

1. Saber qué loader usa realmente cada llamada de PyYAML según la versión.
2. Separar tres preguntas: ¿la política lo permite?, ¿la versión está en el
   rango de un CVE?, ¿el análisis puede probar a qué apunta el nombre?
3. Entender por qué CVE-2020-14343 fue un "fix incompleto" de CVE-2020-1747
   leyendo el diff del commit de corrección.
4. Escribir reglas y tests para un analizador AST.

## Prerrequisitos

Python ≥ 3.10, sin dependencias. Lectura: los tres advisories y los
`__init__.py` por tag listados en [SOURCES.md](SOURCES.md); módulo `ast` de la
biblioteca estándar.

## Comandos locales

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m pyyaml_loader_lint fixtures/code --pyyaml-version 5.3 --format csv
PYTHONPATH=src python3 -m pyyaml_loader_lint fixtures/code/f07_load_no_loader.py --pyyaml-version 6.0
python3 scripts/gen_results.py /tmp/out && diff -r results /tmp/out
```

## Ejercicios graduados

**Nivel 1 — una llamada, cinco versiones.** Ejecuta el CLI sobre
`f07_load_no_loader.py` con versión vacía, 3.13, 5.3, 5.4 y 6.0. Anota
`effective_loader`, `policy` y las tres columnas CVE. Justifica cada valor con
una línea de `__init__.py` del tag correspondiente.

**Nivel 2 — fronteras.** Para `yaml.full_load(s)`, prueba 5.3, 5.3.1, 5.4b1 y
5.4. ¿Por qué 5.3.1 arregla CVE-2020-1747 pero sigue afectado por
CVE-2020-14343? (Verificado en `tests/test_practice.py`: en 5.3.1, 1747
`NOT_AFFECTED` y 14343 `AFFECTED`.) Lee el diff de `a001f27` y di qué tres
multi-constructores se movieron.

**Nivel 3 — resolución de nombres.** Predice y luego verifica:
`from yaml import load` seguido de `load(s, Loader=yaml.FullLoader)` sin
`import yaml` (→ `NEEDS_HUMAN`); `yaml.UnsafeLoader` con versión 3.13
(→ `NOT_IN_VERSION`). Ambos verificados en `tests/test_practice.py`.

**Nivel 4 — sombreado.** Estudia `f10`, `f11`, `f22`. Escribe un caso
nuevo donde el análisis flow-insensitive dé `NEEDS_HUMAN` aunque el código
sea seguro, y documenta por qué es aceptable.

**Nivel 5 — ampliar el modelo (código).** Agrega soporte para
`yaml.add_constructor(..., Loader=X)`: un registro sobre `SafeLoader` debería
cambiar la política de llamadas posteriores con `SafeLoader` a
`NEEDS_HUMAN`. Añade fixture, expectativa y test.

**Nivel 6 — aplicación defensiva.** Escribe un script que lea `requirements.txt`
o un lock file, obtenga la versión de PyYAML y llame al CLI con
`--pyyaml-version`. Usa los códigos de salida en un pre-commit local.

**Nivel 7 — corrección sugerida.** Implementa un modo `--suggest` que proponga
`safe_load` o `Loader=yaml.SafeLoader` solo cuando la resolución sea
`RESOLVED`. No reescribas archivos automáticamente.

## Vínculo con los CVE

| Caso real | En el código |
|---|---|
| CVE-2017-18342: `load()` sin Loader usa `Loader` inseguro antes de 5.1 | `versions.api_generation` = `legacy`; columna `cve_2017_18342` |
| CVE-2020-1747 / CVE-2020-14343: `FullLoader` construye objetos Python | familia `full` en `versions.FAMILY`; `_cve_full` |
| Fix en 5.4 mueve constructores a `UnsafeConstructor` | rango `< 5.4` en `versions.CVE_2020_14343` |
| 6.0 exige `Loader` | `TYPE_ERROR_IN_VERSION` |

El linter no demuestra explotación: solo dice qué loader se usaría y si la
versión cae en un rango publicado.

---

## English summary

Offline defensive code-review exercises; no YAML payloads, nothing executed.
Levels: (1) one call across five versions, justified from each tag's
`__init__.py`; (2) the 5.3.1 / 5.4 boundaries and the three multi-constructors
moved by commit a001f27; (3) name-resolution predictions (checked in
`tests/test_practice.py`); (4) design a safe case that the flow-insensitive
pass sends to a human; (5) add `add_constructor` awareness; (6) wire the CLI
to a lock-file version in a local pre-commit; (7) a non-destructive
`--suggest` mode.
