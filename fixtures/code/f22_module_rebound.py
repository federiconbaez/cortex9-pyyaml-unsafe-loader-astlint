import yaml

yaml = None


def read(stream):
    return yaml.load(stream)
