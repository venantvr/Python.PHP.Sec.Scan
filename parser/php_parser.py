# parser/php_parser.py
import tree_sitter_php as tsphp
from tree_sitter import Language, Parser

# Initialiser le parseur pour PHP
PHP_LANGUAGE = Language(tsphp.language_php())
parser = Parser(PHP_LANGUAGE)

# Liste des fonctions dangereuses à détecter
DANGEROUS_FUNCTIONS = {'eval', 'exec', 'system', 'shell_exec', 'passthru'}

def parse_php_file(file_path):
    """
    Parse un fichier PHP et retourne son arbre syntaxique.
    """
    try:
        with open(file_path, 'r', encoding='utf8', errors='replace') as f:
            code = f.read()
        tree = parser.parse(code.encode("utf8"))
        return tree, code
    except UnicodeDecodeError:
        print(f"Erreur d'encodage dans {file_path}")
        return None, None
    except Exception as e:
        print(f"Erreur lors de l'analyse de {file_path}: {e}")
        return None, None

def analyze_php_code(code):
    """
    Analyse du code PHP et détection d'appels à des fonctions dangereuses.
    Retourne une liste de messages d'avertissement.
    """
    tree = parser.parse(code.encode("utf8"))
    root_node = tree.root_node
    issues = []

    def traverse(node):
        if node.type == 'function_call_expression':
            name_node = node.child_by_field_name('name')
            if name_node and name_node.type == 'name':
                func_name = code[name_node.start_byte:name_node.end_byte]
                if func_name in DANGEROUS_FUNCTIONS:
                    line = code[:name_node.start_byte].count('\n') + 1
                    issues.append(f"Appel à la fonction dangereuse '{func_name}' à la ligne {line}")
        for child in node.children:
            traverse(child)

    traverse(root_node)
    return issues

def analyze_php_file(file_path):
    """
    Analyse un fichier PHP et retourne les vulnérabilités détectées.
    """
    try:
        with open(file_path, 'r', encoding='utf8', errors='replace') as f:
            code = f.read()
        return analyze_php_code(code)
    except Exception as e:
        return [f"Erreur lors de l'analyse de {file_path}: {e}"]
