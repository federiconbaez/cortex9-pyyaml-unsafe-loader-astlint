# If the linter ever imported or executed this file, the next line would
# raise and the test suite would fail.
raise RuntimeError("fixture executed: the linter must only parse")

import yaml

yaml.safe_load("")
