# cli.py
import argparse
import sys

from analysis.scanner import Scanner


def main():
    """Point d'entrée CLI pour analyser des fichiers PHP ou répertoires."""
    parser = argparse.ArgumentParser(description="Analyse statique de code PHP pour détecter les vulnérabilités.")
    parser.add_argument('--files', nargs='*', help="Fichiers PHP à analyser")
    parser.add_argument('--dir', help="Répertoire contenant les fichiers PHP")
    parser.add_argument('--vuln-types', nargs='*', default=['xss', 'sql_injection', 'auth_bypass'],
                        help="Types de vulnérabilités à détecter")
    parser.add_argument('--output', default="report/scan_report.json",
                        help="Chemin du fichier de sortie JSON")
    parser.add_argument('--verbose', action='store_true', help="Activer les logs détaillés")
    args = parser.parse_args()

    if not args.files and not args.dir:
        parser.error("Vous devez spécifier au moins --files ou --dir")

    scanner = Scanner(args.vuln_types, args.verbose)
    if args.files:
        results = scanner.scan_files(args.files)
    else:
        results = scanner.scan_directory(args.dir)

    scanner.print_summary()
    scanner.save_results(args.output)

    # Code de retour : 1 si vulnérabilités détectées, 0 sinon
    total_vulns = sum(len(r['vulnerabilities']) for r in results.values())
    sys.exit(1 if total_vulns > 0 else 0)


if __name__ == "__main__":
    main()
