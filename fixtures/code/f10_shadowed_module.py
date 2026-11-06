import yaml


def read(stream, yaml=None):
    return yaml.load(stream)
