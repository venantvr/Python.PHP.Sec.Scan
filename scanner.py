# scanner.py - Point d'entrée principal

import json

from parser.php_parser import parse_php_file
from utils.filewalker import find_php_files


def main(project_path, vuln_types=None):
    vuln_types = vuln_types or []

    php_files = find_php_files(project_path)
    all_results = []

    for file_path in php_files:
        tree = parse_php_file(file_path)

        # Placeholder pour la suite : analyse de flux et détection
        result = {
            "file": file_path,
            "vulnerabilities": [
                # À remplir plus tard
            ]
        }

        all_results.append(result)

    # Génération du rapport
    with open("report.json", "w", encoding="utf8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    print("Analyse terminée. Rapport écrit dans report.json")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scanner.py <chemin_projet_php>")
        sys.exit(1)

    project_dir = sys.argv[1]
    main(project_dir)
