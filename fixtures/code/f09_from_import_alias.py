from yaml import load as l
from yaml import UnsafeLoader as UL


def read(stream):
    return l(stream, Loader=UL)
