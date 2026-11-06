import yaml


def read(stream, loader_cls):
    return yaml.load(stream, Loader=loader_cls)
