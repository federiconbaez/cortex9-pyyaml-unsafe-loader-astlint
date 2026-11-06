from yaml.cyaml import CUnsafeLoader
import yaml


def read(stream):
    return yaml.load(stream, Loader=CUnsafeLoader)
