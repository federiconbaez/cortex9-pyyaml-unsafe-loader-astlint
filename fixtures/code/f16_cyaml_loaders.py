import yaml


def read_fast(stream):
    return yaml.load(stream, Loader=yaml.CSafeLoader)


def read_fast_full(stream):
    return yaml.load(stream, Loader=yaml.CFullLoader)


def read_fast_unsafe(stream):
    return yaml.load(stream, Loader=yaml.CLoader)
