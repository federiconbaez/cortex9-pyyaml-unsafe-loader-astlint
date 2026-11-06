import yaml


def read(stream):
    loader = yaml.FullLoader(stream)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
