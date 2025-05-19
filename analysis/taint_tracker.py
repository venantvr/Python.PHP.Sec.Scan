# analysis/taint_tracker.py
from typing import List, Dict, Set, Any

from tree_sitter import Node

from config.loader import load_rules
from utils.text import get_node_text


class TaintTracker:
    """Suit les flux de données pour détecter les vulnérabilités via taint tracking."""

    def __init__(self, source_code: bytes, vuln_types: List[str]):
        self.source_code = source_code
        self.rules = {k: v for k, v in load_rules().items() if k in vuln_types or k in ['sources', 'filters', 'auth_checks', 'session_functions', 'upload_functions']}
        self.tainted_vars: Set[str] = set()
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.sanitized_vars: Dict[str, Set[str]] = {}  # {var: {vuln_types_safe}}

    def is_source(self, node: Node) -> bool:
        """Vérifie si un nœud est une source de données utilisateur."""
        text = get_node_text(node, self.source_code)
        return text in self.rules.get('sources', [])

    def is_filter_call(self, node: Node) -> tuple[bool, str]:
        """Vérifie si un nœud est un appel de fonction de désinfection."""
        func = node.child_by_field_name('function')
        if func:
            func_name = get_node_text(func, self.source_code)
            for vuln_type, filters in self.rules.get('filters', {}).items():
                if func_name in filters:
                    return True, vuln_type
        return False, ""

    def get_sink_type(self, func_name: str) -> str:
        """Identifie le type de vulnérabilité associé à un sink."""
        for vuln_type, sinks in self.rules.get('sinks', {}).items():
            if func_name in sinks:
                return vuln_type
        return ""

    def is_auth_check(self, node: Node) -> bool:
        """Vérifie si un nœud contient une comparaison faible dans une vérification d'authentification."""
        if node.type == 'binary_expression':
            operator = get_node_text(node.child_by_field_name('operator'), self.source_code)
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            if operator == '==' and left and right:
                left_text = get_node_text(left, self.source_code)
                right_text = get_node_text(right, self.source_code)
                return any(check in left_text or check in right_text for check in self.rules.get('auth_checks', []))
        return False

    def is_session_fixation(self, node: Node) -> bool:
        """Détecte l'absence de régénération de session après connexion."""
        if node.type == 'function_call_expression':
            func = node.child_by_field_name('function')
            if func and get_node_text(func, self.source_code) in self.rules.get('session_functions', []):
                return False  # session_regenerate_id trouvé
        return True  # Pas de régénération trouvée dans le contexte

    def analyze_sink(self, node: Node, file_path: str) -> None:
        """Analyse un sink pour détecter les vulnérabilités."""
        func_node = node.child_by_field_name('function')
        if not func_node:
            return
        func_name = get_node_text(func_node, self.source_code)
        vuln_type = self.get_sink_type(func_name)
        if not vuln_type:
            return

        args_node = node.child_by_field_name('arguments')
        if args_node:
            for arg in args_node.named_children:
                if arg.type == 'variable_name':
                    arg_name = get_node_text(arg, self.source_code)
                    if arg_name in self.tainted_vars and vuln_type not in self.sanitized_vars.get(arg_name, set()):
                        self.vulnerabilities.append({
                            "type": vuln_type,
                            "sink": func_name,
                            "variable": arg_name,
                            "line": node.start_point[0] + 1,
                            "file": file_path,
                            "trace": f"Source tainted: {arg_name} → Sink: {func_name}"
                        })

    def track_taint(self, node: Node, file_path: str, in_auth_context: bool = False) -> None:
        """Suit récursivement les flux de données dans l'AST."""
        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            if left.type == 'variable_name' and right:
                var_name = get_node_text(left, self.source_code)
                if self.is_source(right):
                    self.tainted_vars.add(var_name)
                elif any(get_node_text(c, self.source_code) in self.tainted_vars for c in right.named_children if c.type == 'variable_name'):
                    self.tainted_vars.add(var_name)

        elif node.type == 'function_call_expression':
            is_filter, vuln_type = self.is_filter_call(node)
            if is_filter:
                args = node.child_by_field_name('arguments')
                if args and args.named_children and args.named_children[0].type == 'variable_name':
                    var_name = get_node_text(args.named_children[0], self.source_code)
                    self.sanitized_vars.setdefault(var_name, set()).add(vuln_type)
            else:
                self.analyze_sink(node, file_path)

        elif node.type == 'binary_expression' and self.is_auth_check(node):
            self.vulnerabilities.append({
                "type": "auth_bypass",
                "sink": "weak_comparison",
                "line": node.start_point[0] + 1,
                "file": file_path,
                "trace": f"Comparaison faible (==) détectée dans une vérification d'authentification"
            })

        elif node.type == 'function_call_expression' and get_node_text(node.child_by_field_name('function'), self.source_code) in self.rules.get('upload_functions', []):
            args = node.child_by_field_name('arguments')
            if args and any(arg.type == 'variable_name' and get_node_text(arg, self.source_code) in self.tainted_vars for arg in args.named_children):
                self.vulnerabilities.append({
                    "type": "insecure_upload",
                    "sink": "move_uploaded_file",
                    "line": node.start_point[0] + 1,
                    "file": file_path,
                    "trace": "Upload de fichier sans validation détectée"
                })

        # Vérifier les contextes d'authentification (ex. login)
        in_auth_context = in_auth_context or (
                node.type == 'function_call_expression' and get_node_text(node.child_by_field_name('function'), self.source_code) in self.rules.get('auth_functions',
                                                                                                                                                    []))

        for child in node.children:
            self.track_taint(child, file_path, in_auth_context)

    # noinspection PyUnresolvedReferences
    def analyze(self, tree: Node, file_path: str) -> List[Dict[str, Any]]:
        """Analyse l'AST pour détecter les vulnérabilités."""
        self.tainted_vars.clear()
        self.vulnerabilities.clear()
        self.sanitized_vars.clear()

        # Vérifier la session fixation dans les contextes d'authentification
        login_nodes = [n for n in tree.root_node.children if
                       n.type == 'function_call_expression' and get_node_text(n.child_by_field_name('function'), self.source_code) in self.rules.get('auth_functions',
                                                                                                                                                     [])]
        for node in login_nodes:
            if self.is_session_fixation(node):
                self.vulnerabilities.append({
                    "type": "session_fixation",
                    "sink": "session_start",
                    "line": node.start_point[0] + 1,
                    "file": file_path,
                    "trace": "Absence de session_regenerate_id après connexion"
                })

        self.track_taint(tree.root_node, file_path)
        return self.vulnerabilities
