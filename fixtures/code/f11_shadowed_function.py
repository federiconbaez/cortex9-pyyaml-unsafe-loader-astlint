from yaml import load


def load(path):
    with open(path) as fh:
        return fh.read()


def read(path):
    return load(path)
