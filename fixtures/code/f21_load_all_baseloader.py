from yaml import load_all, BaseLoader


def read(stream):
    return list(load_all(stream, Loader=BaseLoader))
