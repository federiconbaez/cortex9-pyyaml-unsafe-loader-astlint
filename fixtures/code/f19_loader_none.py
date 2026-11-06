import yaml


def read(stream):
    return yaml.load(stream, Loader=None)
