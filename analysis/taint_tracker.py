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
        self.warnings: List[Dict[str, Any]] = []  # Nouvelle liste pour les avertissements
        self.sanitized_vars: Dict[str, Set[str]] = {}  # {var: {vuln_types_safe}}
        self.sink_nodes: List[Node] = []  # Stocker les nœuds des sinks
        print(f"Initialized rules: {self.rules}")  # Trace de débogage

    def is_source(self, node: Node) -> bool:
        """Vérifie si un nœud est une source de données utilisateur."""
        text = get_node_text(node, self.source_code)
        print(f"Checking source: node_type={node.type}, text={text}")  # Trace de débogage
        if node.type == 'subscript_expression':
            object_node = node.child_by_field_name('object')
            object_text = get_node_text(object_node, self.source_code) if object_node else None
            print(f"Subscript object: {object_text}")  # Trace de débogage
            for child in node.named_children:
                child_text = get_node_text(child, self.source_code)
                print(f"Subscript child: type={child.type}, text={child_text}")  # Trace de débogage
            for rule_name in self.vuln_types:
                rule = self.rules.get(rule_name, {})
                for source in rule.get('sources', []):
                    pattern = source['pattern'].replace('[*]', r'\[\'?.*?\'?\]')
                    print(f"Testing pattern: {pattern} against text: {text}")  # Trace de débogage
                    if re.match(pattern, text, re.DOTALL):
                        print(f"Source detected (regex): {text}, pattern={pattern}")  # Trace de débogage
                        return True
                    if object_text in ['$_GET', '$_POST', '$_REQUEST']:
                        print(f"Source detected (object): {text}, object={object_text}")  # Trace de débogage
                        return True
                    for child in node.named_children:
                        if child.type == 'variable_name' and get_node_text(child, self.source_code) in ['$_GET', '$_POST', '$_REQUEST']:
                            print(f"Source detected (child): {text}, child={get_node_text(child, self.source_code)}")  # Trace de débogage
                            return True
        return False

    def is_filter_call(self, node: Node) -> tuple[bool, List[str]]:
        """Vérifie si un nœud est un appel de fonction ou méthode de désinfection."""
        sanitized_types = []
        is_filter = False
        warning = None

        if node.type == 'function_call_expression':
            func_node = node.child_by_field_name('function')
            if func_node:
                func_name = get_node_text(func_node, self.source_code)
                print(f"Checking filter: func_name={func_name}")  # Trace de débogage
                for rule_name in self.vuln_types:
                    rule = self.rules.get(rule_name, {})
                    for filter in rule.get('filters', []):
                        if filter.get('function') == func_name:
                            print(f"Filter detected: {func_name}")  # Trace de débogage
                            is_filter = True
                            sanitized_types = filter.get('sanitizes', [])
                            warning = filter.get('warning')
                            break
                    if is_filter:
                        break
        elif node.type == 'member_call_expression':
            method_node = node.child_by_field_name('name')
            if method_node:
                method_name = get_node_text(method_node, self.source_code)
                print(f"Checking filter: method_name={method_name}")  # Trace de débogage
                for rule_name in self.vuln_types:
                    rule = self.rules.get(rule_name, {})
                    for filter in rule.get('filters', []):
                        if filter.get('method') and method_name in filter['method']:
                            print(f"Filter detected: {filter['method']}")  # Trace de débogage
                            is_filter = True
                            sanitized_types = filter.get('sanitizes', [])
                            warning = filter.get('warning')
                            break
                    if is_filter:
                        break

        if is_filter and warning:
            self.warnings.append({
                "type": "non_preferred_filter",
                "function": func_name if node.type == 'function_call_expression' else method_name,
                "line": node.start_point[0] + 1,
                "file": None,  # Sera défini dans analyze
                "message": warning
            })
            print(f"Warning added: {warning} for {func_name or method_name}")  # Trace de débogage

        return is_filter, sanitized_types

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
            print(f"Tainted vars before sink analysis: {self.tainted_vars}")  # Trace de débogage
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

        elif node.type in ['function_call_expression', 'member_call_expression']:
            func_node = node.child_by_field_name('function') or node.child_by_field_name('name')
            if func_node:
                func_name = get_node_text(func_node, self.source_code)
                print(f"Processing call: {func_name}")  # Trace de débogage
                args_node = node.child_by_field_name('arguments')
                if args_node and func_name not in ['mysqli_query', 'mysql_query', 'echo', 'print', 'htmlspecialchars', 'htmlentities', 'mysqli_real_escape_string',
                                                   'filter_var', 'sanitize_text_field']:
                    args = args_node.named_children
                    func_def = self.find_function_definition(func_name, node)
                    print(f"Function definition for {func_name}: {'found' if func_def else 'not found'}")  # Trace de débogage
                    if func_def:
                        params = self.get_function_params(func_def)
                        print(f"Parameters for {func_name}: {params}")  # Trace de débogage
                        for i, arg in enumerate(args):
                            if i < len(params) and arg.type == 'argument' and arg.named_children:
                                arg_var = get_node_text(arg.named_children[0], self.source_code)
                                print(f"Argument {i}: {arg_var}, tainted: {arg_var in self.tainted_vars}")  # Trace de débogage
                                if arg_var in self.tainted_vars:
                                    param_var = params[i]
                                    self.tainted_vars.add(param_var)
                                    print(f"Propagated taint: {arg_var} -> {param_var} in {func_name}")  # Trace de débogage
            is_filter, sanitized_types = self.is_filter_call(node)
            if is_filter:
                args = node.child_by_field_name('arguments')
                if args and args.named_children and args.named_children[0].type == 'argument' and args.named_children[0].named_children:
                    var_name = get_node_text(args.named_children[0].named_children[0], self.source_code)
                    self.sanitized_vars.setdefault(var_name, set()).update(sanitized_types)
            elif self.get_sink_info(func_name)[0]:  # Si c'est un sink, stocker le nœud
                self.sink_nodes.append(node)

        elif node.type == 'binary_expression':
            self.analyze_pattern(node, file_path)

        for child in node.children:
            self.track_taint(child, file_path)

    def find_function_definition(self, func_name: str, current_node: Node) -> Node | None:
        """Trouve la déclaration de la fonction dans l'AST."""
        def search(node: Node) -> Node | None:
            if node.type == 'function_definition':
                name_node = node.child_by_field_name('name')
                if name_node and get_node_text(name_node, self.source_code) == func_name:
                    print(f"Found function definition: {func_name}")  # Trace de débogage
                    return node
            for child in node.children:
                result = search(child)
                if result:
                    return result
            return None
        root = current_node
        while root.parent:
            root = root.parent
        return search(root)

    def get_function_params(self, func_def: Node) -> List[str]:
        """Extrait les noms des paramètres d'une fonction."""
        params = []
        parameters_node = func_def.child_by_field_name('parameters')
        print(f"Parameters node: {'found' if parameters_node else 'not found'}")  # Trace de débogage
        if parameters_node:
            print(f"Parameters node type: {parameters_node.type}")  # Trace de débogage
            for param in parameters_node.children:
                print(f"Parameter child: type={param.type}, text={get_node_text(param, self.source_code)}")  # Trace de débogage
                if param.type == 'simple_parameter':
                    for child in param.children:
                        if child.type == 'variable_name':
                            param_name = get_node_text(child, self.source_code)
                            params.append(param_name)
                            print(f"Found parameter: {param_name}")  # Trace de débogage
        return params

    def analyze(self, tree: Node, file_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """Analyse l'AST pour détecter les vulnérabilités et avertissements."""
        self.tainted_vars.clear()
        self.vulnerabilities.clear()
        self.warnings.clear()
        self.sanitized_vars.clear()
        self.sink_nodes.clear()
        self.track_taint(tree.root_node, file_path)
        print(f"Tainted vars after taint propagation: {self.tainted_vars}")  # Trace de débogage
        for sink_node in self.sink_nodes:
            self.analyze_sink(sink_node, file_path)
        for warning in self.warnings:
            warning['file'] = file_path
        return {"vulnerabilities": self.vulnerabilities, "warnings": self.warnings}
