import yaml


def read(stream, **opts):
    return yaml.load(stream, **opts)
