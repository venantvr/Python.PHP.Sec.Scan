# config/loader.py

import yaml


def load_rules(path="config/rules.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return config
