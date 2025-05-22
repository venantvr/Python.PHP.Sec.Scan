from typing import List, Dict, Any


class WarningManager:
    """Gère la création et le stockage des avertissements pendant l'analyse."""

    def __init__(self):
        self.warnings: List[Dict[str, Any]] = []

    def add_warning(self, warning_type: str, **kwargs) -> None:
        """Ajoute un avertissement avec un type et des métadonnées."""
        warning = {"type": warning_type, **kwargs}
        self.warnings.append(warning)
        # logger.info(f"Warning added: {warning_type} - {kwargs}")

    def get_warnings(self) -> List[Dict[str, Any]]:
        """Retourne la liste des avertissements."""
        return self.warnings

    def clear(self) -> None:
        """Réinitialise la liste des avertissements."""
        self.warnings.clear()
