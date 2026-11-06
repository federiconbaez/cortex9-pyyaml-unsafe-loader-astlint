import yaml


def read(stream):
    fn = getattr(yaml, "load")
    return fn(stream)
