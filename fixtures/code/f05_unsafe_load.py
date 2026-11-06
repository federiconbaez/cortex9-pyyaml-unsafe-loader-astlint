import yaml


def read(stream):
    return yaml.unsafe_load(stream)
