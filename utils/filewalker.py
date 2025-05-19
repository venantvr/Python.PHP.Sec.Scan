# utils/filewalker.py

import os


def find_php_files(root_dir):
    php_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            if f.endswith(".php"):
                php_files.append(os.path.join(dirpath, f))
    return php_files
