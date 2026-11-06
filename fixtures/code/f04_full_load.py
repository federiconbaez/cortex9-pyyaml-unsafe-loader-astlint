import yaml


def read(stream):
    return yaml.full_load(stream)
