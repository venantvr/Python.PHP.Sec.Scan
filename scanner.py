# scanner.py

import json
import os

from analysis.taint_tracker import TaintTracker
from parser.php_parser import parse_php_file
from utils.filewalker import find_php_files


def main(project_path, vuln_types=None, output_path="report/report.json"):
    vuln_types = vuln_types or []

    php_files = find_php_files(project_path)
    all_results = []

    for file_path in php_files:
        with open(file_path, "rb") as f:
            source_code = f.read()

        tree = parse_php_file(file_path)
        tracker = TaintTracker(source_code)
        vulnerabilities = tracker.analyze_tree(tree, file_path)

        result = {
            "file": file_path,
            "vulnerabilities": vulnerabilities
        }
        all_results.append(result)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"Analyse terminée. Rapport généré dans {output_path}")
