import json
import pickle  # noqa: F401  (name only; nothing is loaded)


def read(stream):
    return json.load(stream)
