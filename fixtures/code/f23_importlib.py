import importlib


def read(stream):
    mod = importlib.import_module("yaml")
    return mod.load(stream)
