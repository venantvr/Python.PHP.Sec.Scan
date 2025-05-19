# cli.py
import argparse
import os

from scanner import main

VULN_TYPES = [
    "sql_injection",
    "xss",
    "rce",
    "file_inclusion",
    "auth_bypass",
    "insecure_upload",
    "session_fixation",
]


def parse_args():
    """Parse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(description="phpsecscan : analyse statique hybride de sécurité pour projets PHP")
    parser.add_argument("path", help="Chemin vers le répertoire du projet PHP à analyser")
    parser.add_argument("--vuln-types", nargs="+", choices=VULN_TYPES, help="Types de vulnérabilités à rechercher")
    parser.add_argument("--output", default="report/report.json", help="Chemin de sortie pour le rapport JSON")
    parser.add_argument("--exclude-dirs", nargs="+", default=["vendor", ".git"], help="Dossiers à exclure de l'analyse")
    args = parser.parse_args()
    if not os.path.isdir(args.path):
        parser.error(f"Le chemin {args.path} n'est pas un répertoire valide")
    return args


def run():
    """Exécute l'analyse avec les arguments fournis."""
    args = parse_args()
    main(args.path, vuln_types=args.vuln_types, output_file=args.output)


if __name__ == "__main__":
    run()
