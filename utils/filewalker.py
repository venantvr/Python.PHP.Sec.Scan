# utils/filewalker.py
import os
from typing import List, Optional


def find_php_files(root_dir: str, ignored_paths: Optional[List[str]] = None) -> List[str]:
    """Parcourt récursivement un dossier pour trouver les fichiers PHP, en ignorant certains chemins."""
    ignored_paths = ignored_paths or ['vendor', '.git', 'tests']
    php_files = []
    try:
        for dirpath, _, filenames in os.walk(root_dir, onerror=lambda e: print(f"Erreur d'accès: {e}")):
            if any(ignored in dirpath for ignored in ignored_paths):
                continue
            for f in filenames:
                if f.endswith(".php"):
                    php_files.append(os.path.join(dirpath, f))
    except Exception as e:
        print(f"Erreur lors de l'exploration de {root_dir}: {e}")
    return php_files
