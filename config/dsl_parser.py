# config/dsl_parser.py
from typing import Dict, Any

import yaml


def parse_dsl(file_path: str = "../config/rules.yaml") -> Dict[str, Any]:
    """Parse le fichier DSL et retourne les règles structurées."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            dsl = yaml.safe_load(f)
        print(f"Parsed DSL content: {dsl}")
    except FileNotFoundError:
        print(f"Erreur : Fichier {file_path} introuvable")
        return {}
    except yaml.YAMLError as e:
        print(f"Erreur YAML dans {file_path}: {e}")
        return {}

    if not dsl or 'rules' not in dsl:
        print(f"Erreur : Clé 'rules' absente ou DSL vide dans {file_path}")
        return {}

    rules = {}
    for rule in dsl.get('rules', []):
        rule_name = rule.get('name')
        if not rule_name:
            print(f"Erreur : Règle sans nom dans {file_path}")
            continue
        rules[rule_name] = {
            "name": rule_name,
            "sources": rule.get("sources", []),
            "sinks": rule.get("sinks", []),
            "filters": rule.get("filters", []),
            "patterns": rule.get("patterns", [])
        }
        print(f"Loaded rule: {rule_name}")
    print(f"All loaded rules: {list(rules.keys())}")
    return rules
