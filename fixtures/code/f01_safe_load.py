import yaml


def read(stream):
    return yaml.safe_load(stream)
