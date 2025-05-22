from typing import Set, Dict, List


class TaintState:
    """Gère l'état des variables tainted et sanitized pendant l'analyse."""

    def __init__(self):
        self.tainted_vars: Set[str] = set()  # Noms des variables tainted
        self.tainted_vars_info: Dict[str, int] = {}  # {var_name: line_number}
        self.sanitized_vars: Dict[str, Set[str]] = {}  # {var_name: set(vuln_types sanitized)}

    def mark_tainted(self, var_name: str, line: int) -> None:
        """Marque une variable comme tainted et enregistre sa ligne d'origine."""
        self.tainted_vars.add(var_name)
        self.tainted_vars_info[var_name] = line

    def is_tainted(self, var_name: str) -> bool:
        """Vérifie si une variable est tainted."""
        return var_name in self.tainted_vars

    def mark_sanitized(self, var_name: str, vuln_types: List[str]) -> None:
        """Marque une variable comme sanitized pour certains types de vulnérabilités."""
        if var_name not in self.sanitized_vars:
            self.sanitized_vars[var_name] = set()
        self.sanitized_vars[var_name].update(vuln_types)

    def is_sanitized_for(self, var_name: str, vuln_type: str) -> bool:
        """Vérifie si une variable est sanitized pour un type de vulnérabilité spécifique."""
        return vuln_type in self.sanitized_vars.get(var_name, set())

    def get_tainted_vars(self) -> Set[str]:
        """Retourne l'ensemble des variables tainted."""
        return self.tainted_vars

    def get_tainted_vars_info(self) -> Dict[str, int]:
        """Retourne les informations sur les variables tainted (nom et ligne)."""
        return self.tainted_vars_info

    def get_sanitized_vars(self) -> Dict[str, Set[str]]:
        """Retourne les variables sanitized et les types de vulnérabilités associées."""
        return self.sanitized_vars

    def clear(self) -> None:
        """Réinitialise tous les états."""
        self.tainted_vars.clear()
        self.tainted_vars_info.clear()
        self.sanitized_vars.clear()
