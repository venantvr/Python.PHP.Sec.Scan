# cli.py

import argparse

from scanner import main

VULN_TYPES = [
    "sql_injection",
    "xss",
    "rce",
    "file_inclusion",
    "auth_bypass",
    "insecure_upload",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="phpsecscan : analyse statique hybride de sécurité pour projets PHP"
    )
    parser.add_argument(
        "path",
        help="Chemin vers le répertoire du projet PHP à analyser"
    )
    parser.add_argument(
        "--vuln-types",
        nargs="+",
        choices=VULN_TYPES,
        help="Liste des types de vulnérabilités à rechercher"
    )
    parser.add_argument(
        "--output",
        default="report/report.json",
        help="Chemin de sortie pour le rapport JSON"
    )
    return parser.parse_args()


def run():
    args = parse_args()
    main(args.path, vuln_types=args.vuln_types)


if __name__ == "__main__":
    run()
