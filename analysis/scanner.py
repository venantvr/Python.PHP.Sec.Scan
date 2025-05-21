# analysis/scanner.py
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from analysis.taint_tracker import TaintTracker

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Scanner:
    """Gère l'analyse de multiples fichiers PHP ou d'une arborescence pour détecter les vulnérabilités."""

    def __init__(self, vuln_types: List[str], verbose: bool = False):
        """Initialise le scanner avec les types de vulnérabilités."""
        self.vuln_types = vuln_types
        self.verbose = verbose
        self.logger = logger
        self.logger.setLevel(logging.INFO if verbose else logging.WARNING)
        # Dictionnaire pour stocker les résultats : {fichier: {vulns, warnings}}
        self.results: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    def scan_file(self, file_path: str) -> None:
        """Analyse un seul fichier PHP."""
        if not file_path.endswith('.php'):
            self.logger.warning(f"Ignoré (pas un fichier PHP) : {file_path}")
            return
        self.logger.info(f"Analyse du fichier : {file_path}")
        result = TaintTracker.analyze_file(file_path, self.vuln_types, self.verbose)
        if result['vulnerabilities'] or result['warnings']:
            self.results[file_path] = result
            self.logger.info(f"Résultats pour {file_path}: {len(result['vulnerabilities'])} vulnérabilités, {len(result['warnings'])} avertissements")

    def scan_files(self, file_paths: List[str]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """Analyse une liste de fichiers PHP."""
        self.results.clear()
        for file_path in file_paths:
            self.scan_file(file_path)
        return self.results

    def scan_directory(self, dir_path: str) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """Analyse tous les fichiers PHP dans une arborescence."""
        self.results.clear()
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            self.logger.error(f"Répertoire invalide : {dir_path}")
            return self.results
        self.logger.info(f"Analyse du répertoire : {dir_path}")
        for file_path in dir_path.rglob('*.php'):
            self.scan_file(str(file_path))
        return self.results

    def save_results(self, output_path: str) -> None:
        """Sauvegarde les résultats dans un fichier JSON."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2)
            self.logger.info(f"Résultats sauvegardés dans : {output_path}")
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde dans {output_path}: {e}")

    def print_summary(self) -> None:
        """Affiche un résumé des résultats en console."""
        total_vulns = sum(len(r['vulnerabilities']) for r in self.results.values())
        total_warnings = sum(len(r['warnings']) for r in self.results.values())
        self.logger.info(f"Total : {total_vulns} vulnérabilités, {total_warnings} avertissements dans {len(self.results)} fichiers")
        for file_path, result in self.results.items():
            if result['vulnerabilities']:
                self.logger.info(f"{file_path}: {len(result['vulnerabilities'])} vulnérabilités")
                for vuln in result['vulnerabilities']:
                    self.logger.info(f"  - {vuln['type']} à la ligne {vuln['line']}: {vuln['trace']}")
            if result['warnings']:
                self.logger.info(f"{file_path}: {len(result['warnings'])} avertissements")
                for warning in result['warnings']:
                    self.logger.info(f"  - {warning['message']} à la ligne {warning['line']}")
