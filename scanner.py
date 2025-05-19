# scanner.py - Point d'entrée principal

import json

from parser.php_parser import parse_php_file
from utils.filewalker import find_php_files


def main(project_path, vuln_types=None):
    vuln_types = vuln_types or []  # Liste des vulnérabilités à analyser

    php_files = find_php_files(project_path)
    all_results = []

    for file_path in php_files:
        ast = parse_php_file(file_path)
        # Ici appeler l'analyse de flux et les détecteurs (à implémenter)
        # Placeholder résultat
        result = {
            "file": file_path,
            "vulnerabilities": []
        }
        all_results.append(result)

    # Générer rapport JSON
    with open("report.json", "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"Analyse terminée. Rapport généré dans report.json")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scanner.py <chemin_projet_php>")
        sys.exit(1)
    project_dir = sys.argv[1]
    main(project_dir)
