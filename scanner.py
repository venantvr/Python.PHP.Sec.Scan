# scanner.py
import datetime
import json
from typing import List, Optional

from analysis.taint_tracker import TaintTracker
from parser.php_parser import parse_php_file
from utils.filewalker import find_php_files


def main(project_path: str, vuln_types: Optional[List[str]] = None, output_file: str = "report/report.json") -> None:
    """Point d'entrée principal pour l'analyse de sécurité."""
    vuln_types = vuln_types or []
    php_files = find_php_files(project_path)
    all_results = []

    for file_path in php_files:
        try:
            tree, code = parse_php_file(file_path)
            if tree and code:
                tracker = TaintTracker(code.encode('utf-8'), vuln_types)
                vulnerabilities = tracker.analyze(tree, file_path)
                all_results.append({
                    "file": file_path,
                    "vulnerabilities": vulnerabilities
                })
        except Exception as e:
            all_results.append({
                "file": file_path,
                "vulnerabilities": [{"type": "error", "message": f"Erreur d'analyse: {e}"}]
            })

    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "results": all_results,
        "total_vulnerabilities": sum(len(r["vulnerabilities"]) for r in all_results if not any(v["type"] == "error" for v in r["vulnerabilities"]))
    }

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Analyse terminée. Rapport écrit dans {output_file}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <chemin_projet_php>")
        sys.exit(1)
    main(sys.argv[1])
