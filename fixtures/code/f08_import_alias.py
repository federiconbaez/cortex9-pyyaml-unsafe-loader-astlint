import yaml as y


def read(stream):
    return y.load(stream, y.FullLoader)
