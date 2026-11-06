from yaml import *


def read(stream):
    return load(stream, Loader=FullLoader)
