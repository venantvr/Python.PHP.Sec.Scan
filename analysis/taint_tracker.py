# analysis/taint_tracker.py
import re
from typing import List, Dict, Set, Any

import tree_sitter_php as tsphp
from tree_sitter import Node, Language, Parser

from config.dsl_parser import parse_dsl
from utils.text import get_node_text

# Initialiser le parseur pour PHP
PHP_LANGUAGE = Language(tsphp.language_php())
PARSER = Parser(PHP_LANGUAGE)


class TaintTracker:
    """Suit les flux de données pour détecter les vulnérabilités via taint tracking."""

    def __init__(self, source_code: bytes, vuln_types: List[str]):
        self.source_code = source_code
        self.rules = parse_dsl()
        self.vuln_types = vuln_types
        self.tainted_vars: Set[str] = set()
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.sanitized_vars: Dict[str, Set[str]] = {}  # {var: {vuln_types_safe}}
        print(f"Initialized rules: {self.rules}")  # Trace de débogage

    def is_source(self, node: Node) -> bool:
        """Vérifie si un nœud est une source de données utilisateur."""
        text = get_node_text(node, self.source_code)
        print(f"Checking source: node_type={node.type}, text={text}")  # Trace de débogage
        if node.type == 'subscript_expression':
            # Vérifier les enfants manuellement si object n'est pas trouvé
            object_node = node.child_by_field_name('object')
            object_text = get_node_text(object_node, self.source_code) if object_node else None
            print(f"Subscript object: {object_text}")  # Trace de débogage
            # Inspecter les enfants pour déboguer
            for child in node.named_children:
                child_text = get_node_text(child, self.source_code)
                print(f"Subscript child: type={child.type}, text={child_text}")  # Trace de débogage
            for rule_name in self.vuln_types:
                rule = self.rules.get(rule_name, {})
                for source in rule.get('sources', []):
                    # Motif plus tolérant pour gérer les guillemets
                    pattern = source['pattern'].replace('[*]', r'\[\'?.*?\'?\]')
                    print(f"Testing pattern: {pattern} against text: {text}")  # Trace de débogage
                    if re.match(pattern, text, re.DOTALL):
                        print(f"Source detected (regex): {text}, pattern={pattern}")  # Trace de débogage
                        return True
                    # Vérifier l'objet directement
                    if object_text in ['$_GET', '$_POST', '$_REQUEST']:
                        print(f"Source detected (object): {text}, object={object_text}")  # Trace de débogage
                        return True
                    # Vérifier les enfants
                    for child in node.named_children:
                        if child.type == 'variable_name' and get_node_text(child, self.source_code) in ['$_GET', '$_POST', '$_REQUEST']:
                            print(f"Source detected (child): {text}, child={get_node_text(child, self.source_code)}")  # Trace de débogage
                            return True
        return False

    def is_filter_call(self, node: Node) -> tuple[bool, List[str]]:
        """Vérifie si un nœud est un appel de fonction de désinfection."""
        func = node.child_by_field_name('function')
        if func:
            func_name = get_node_text(func, self.source_code)
            print(f"Checking filter: func_name={func_name}")  # Trace de débogage
            for rule_name in self.vuln_types:
                rule = self.rules.get(rule_name, {})
                for filter in rule.get('filters', []):
                    if func_name == filter['function']:
                        print(f"Filter detected: {func_name}")  # Trace de débogage
                        return True, filter.get('sanitizes', [])
        return False, []

    def get_sink_info(self, func_name: str) -> tuple[str, List[Dict]]:
        """Identifie le type de vulnérabilité et les arguments à vérifier pour un sink."""
        for rule_name in self.vuln_types:
            rule = self.rules.get(rule_name, {})
            for sink in rule.get('sinks', []):
                if func_name == sink['function']:
                    print(f"Sink detected: {func_name}, vuln: {sink['vuln']}")  # Trace de débogage
                    return sink['vuln'], sink['args']
        return "", []

    def analyze_sink(self, node: Node, file_path: str) -> None:
        """Analyse un sink pour détecter les vulnérabilités."""
        func_node = node.child_by_field_name('function')
        if not func_node:
            return
        func_name = get_node_text(func_node, self.source_code)
        vuln_type, args_to_check = self.get_sink_info(func_name)
        if not vuln_type:
            return

        args_node = node.child_by_field_name('arguments')
        if args_node:
            args = args_node.named_children
            print(f"Analyzing sink: {func_name}, args_count={len(args)}")  # Trace de débogage
            for arg_rule in args_to_check:
                arg_index = arg_rule['index']
                arg_type = arg_rule['type']
                if arg_index < len(args):
                    arg = args[arg_index]
                    print(f"Checking arg {arg_index}: type={arg.type}")  # Trace de débogage
                    if arg.type == 'argument' and arg.named_children:
                        actual_arg = arg.named_children[0]
                        print(f"Actual arg type: {actual_arg.type}")  # Trace de débogage
                        if arg_type == 'variable' and actual_arg.type == 'variable_name':
                            var_name = get_node_text(actual_arg, self.source_code)
                            print(f"Variable arg: {var_name}, tainted: {var_name in self.tainted_vars}")  # Trace de débogage
                            if var_name in self.tainted_vars and vuln_type not in self.sanitized_vars.get(var_name, set()):
                                self.vulnerabilities.append({
                                    "type": vuln_type,
                                    "sink": func_name,
                                    "variable": var_name,
                                    "line": node.start_point[0] + 1,
                                    "file": file_path,
                                    "trace": f"Source tainted: {var_name} → Sink: {func_name}"
                                })
                        elif arg_type == 'string' and actual_arg.type in ['string', 'encapsed_string']:
                            def find_variables(n: Node):
                                if n.type in ['variable_name', 'encapsed_variable']:
                                    var_name = get_node_text(n, self.source_code)
                                    print(f"Variable in string: {var_name}, tainted: {var_name in self.tainted_vars}")  # Trace de débogage
                                    if var_name in self.tainted_vars and vuln_type not in self.sanitized_vars.get(var_name, set()):
                                        print(f"Adding vulnerability: {vuln_type} for {var_name} at line {node.start_point[0] + 1}")  # Trace de débogage
                                        self.vulnerabilities.append({
                                            "type": vuln_type,
                                            "sink": func_name,
                                            "variable": var_name,
                                            "line": node.start_point[0] + 1,
                                            "file": file_path,
                                            "trace": f"Source tainted: {var_name} → Sink: {func_name} (in string)"
                                        })
                                for child in n.children:
                                    find_variables(child)

                            find_variables(actual_arg)

    def analyze_pattern(self, node: Node, file_path: str) -> None:
        """Analyse les motifs spécifiques (ex. auth_bypass)."""
        for rule_name in self.vuln_types:
            rule = self.rules.get(rule_name, {})
            for pattern in rule.get('patterns', []):
                operator = get_node_text(node.child_by_field_name('operator'), self.source_code) if node.child_by_field_name('operator') else None
                print(f"Checking pattern: node_type={node.type}, operator={operator}")  # Trace de débogage
                if pattern['type'] == node.type and pattern.get('operator') == operator:
                    print(f"Adding auth_bypass vulnerability at line {node.start_point[0] + 1}")  # Trace de débogage
                    self.vulnerabilities.append({
                        "type": pattern['vuln'],
                        "sink": "weak_comparison",
                        "line": node.start_point[0] + 1,
                        "file": file_path,
                        "trace": f"Comparaison faible (==) détectée"
                    })

    def track_taint(self, node: Node, file_path: str) -> None:
        """Suit récursivement les flux de données dans l'AST."""
        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            if left and left.type == 'variable_name' and right:
                var_name = get_node_text(left, self.source_code)
                print(f"Assignment: var={var_name}, right_type={right.type}")  # Trace de débogage
                if self.is_source(right):
                    self.tainted_vars.add(var_name)
                    print(f"Tainted var: {var_name}")  # Trace de débogage
                elif any(get_node_text(c, self.source_code) in self.tainted_vars for c in right.named_children if c.type == 'variable_name'):
                    self.tainted_vars.add(var_name)

        elif node.type == 'function_call_expression':
            is_filter, sanitized_types = self.is_filter_call(node)
            if is_filter:
                args = node.child_by_field_name('arguments')
                if args and args.named_children and args.named_children[0].type == 'argument' and args.named_children[0].named_children:
                    var_name = get_node_text(args.named_children[0].named_children[0], self.source_code)
                    self.sanitized_vars.setdefault(var_name, set()).update(sanitized_types)
            else:
                self.analyze_sink(node, file_path)

        elif node.type == 'binary_expression':
            self.analyze_pattern(node, file_path)

        for child in node.children:
            self.track_taint(child, file_path)

    def analyze(self, tree: Node, file_path: str) -> List[Dict[str, Any]]:
        """Analyse l'AST pour détecter les vulnérabilités."""
        self.tainted_vars.clear()
        self.vulnerabilities.clear()
        self.sanitized_vars.clear()
        self.track_taint(tree.root_node, file_path)
        return self.vulnerabilities
