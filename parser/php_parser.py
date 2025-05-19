# parser/php_parser.py

import os

from tree_sitter import Language, Parser

# Préparer Tree-sitter PHP (à faire une fois)
# Télécharge et compile tree-sitter-php selon doc officielle

LANG_SO_PATH = 'build/my-languages.so'

if not os.path.exists(LANG_SO_PATH):
    Language.build_library(
        # Où compiler la lib
        LANG_SO_PATH,
        # Repo tree-sitter-php cloné localement
        ['tree-sitter-php']
    )

PHP_LANGUAGE = Language(LANG_SO_PATH, 'php')
parser = Parser()
parser.set_language(PHP_LANGUAGE)


def parse_php_file(filepath):
    with open(filepath, 'rb') as f:
        source_code = f.read()
    tree = parser.parse(source_code)
    return tree  # AST Tree-sitter, à parcourir dans l'analyse
