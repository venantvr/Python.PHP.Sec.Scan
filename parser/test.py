import tree_sitter_php as tspython
from tree_sitter import Language, Parser

# Initialiser le parseur pour PHP
PHP_LANGUAGE = Language(tspython.language_php())
parser = Parser(PHP_LANGUAGE)

# Liste des fonctions dangereuses à détecter
DANGEROUS_FUNCTIONS = {'eval', 'exec', 'system', 'shell_exec', 'passthru'}


# noinspection PyShadowingNames
def parse_and_analyze(code):
    """
    Parse le code PHP et recherche les appels à des fonctions dangereuses.
    Retourne une liste de problèmes trouvés avec les numéros de ligne.
    """
    # Parser le code
    tree = parser.parse(bytes(code, "utf8"))
    root_node = tree.root_node

    issues = []

    # Parcourir l'arbre syntaxique
    def traverse(node):
        if node.type == 'function_call_expression':
            # Vérifier si le nom de la fonction est dans DANGEROUS_FUNCTIONS
            name_node = node.child_by_field_name('name')
            if name_node and name_node.type == 'name':
                func_name = code[name_node.start_byte:name_node.end_byte].decode('utf8')
                if func_name in DANGEROUS_FUNCTIONS:
                    # Obtenir le numéro de ligne
                    line = code[:name_node.start_byte].decode('utf8').count('\n') + 1
                    issues.append(f"Appel à la fonction dangereuse '{func_name}' à la ligne {line}")

        # Parcourir les nœuds enfants
        for child in node.children:
            traverse(child)

    traverse(root_node)
    return issues


# Exemple de code PHP à analyser
php_code = """<?php
echo "Hello, World!";
eval("echo 'Test';");
system("ls -l");
$x = 1;
?>
"""

# Analyser le code
issues = parse_and_analyze(php_code)

# Afficher les résultats
if issues:
    print("Problèmes de sécurité détectés :")
    for issue in issues:
        print(f"- {issue}")
else:
    print("Aucun problème de sécurité détecté.")


# Exemple : Parser un fichier PHP
# noinspection PyShadowingNames
def analyze_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf8') as f:
            code = f.read()
        issues = parse_and_analyze(code)
        print(f"\nAnalyse du fichier : {file_path}")
        if issues:
            print("Problèmes de sécurité détectés :")
            for issue in issues:
                print(f"- {issue}")
        else:
            print("Aucun problème de sécurité détecté.")
    except FileNotFoundError:
        print(f"Erreur : Le fichier {file_path} n'existe pas.")
    except Exception as e:
        print(f"Erreur lors de l'analyse du fichier : {e}")


# Tester avec un fichier PHP
# Créer un fichier de test
with open("test.php", "w") as f:
    f.write(php_code)

analyze_file("test.php")
