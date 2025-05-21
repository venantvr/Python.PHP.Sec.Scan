# analysis/taint_tracker.py
import logging
import re
from typing import List, Dict, Set, Any

import tree_sitter_php as tsphp
from tree_sitter import Node, Language, Parser

from config.dsl_parser import parse_dsl
from utils.text import get_node_text

# Initialisation du parseur PHP
PHP_LANGUAGE = Language(tsphp.language_php())
PARSER = Parser(PHP_LANGUAGE)

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TaintTracker:
    """Suit les flux de données pour détecter les vulnérabilités via taint tracking."""

    def __init__(self, source_code: bytes, vuln_types: List[str], verbose: bool = False):
        """Initialise le tracker avec le code source et les types de vulnérabilités."""
        self.source_code = source_code
        self.rules = parse_dsl()  # Charge rules.dsl
        self.vuln_types = vuln_types
        self.tainted_vars: Set[str] = set()  # Variables tainted
        self.vulnerabilities: List[Dict[str, Any]] = []  # Vulnérabilités détectées
        self.warnings: List[Dict[str, Any]] = []  # Avertissements (ex. htmlentities)
        self.sanitized_vars: Dict[str, Set[str]] = {}  # Variables sanitized
        self.sink_nodes: List[Node] = []  # Nœuds sinks à analyser
        self.verbose = verbose
        self.logger = logger
        self.logger.setLevel(logging.INFO if verbose else logging.WARNING)

        # Chargement dynamique des sinks et filtres
        self.sink_functions = self._load_sinks()
        self.filter_functions = self._load_filters()

        # Dictionnaire des handlers par type de nœud (logique métier)
        self.node_handlers = {
            'assignment_expression': self.handle_assignment,
            'function_call_expression': self.handle_function_call,
            'member_call_expression': self.handle_member_call,
            'echo_statement': self.handle_echo_statement,
            'binary_expression': self.handle_binary_expression,
        }

    @staticmethod
    def analyze_file(file_path: str, vuln_types: List[str], verbose: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """Analyse un fichier PHP et retourne les vulnérabilités et avertissements."""
        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()
            tree = PARSER.parse(source_code)
            tracker = TaintTracker(source_code, vuln_types, verbose)
            return tracker.analyze(tree, file_path)
        except FileNotFoundError:
            logger.error(f"Fichier introuvable : {file_path}")
            return {"vulnerabilities": [], "warnings": []}
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de {file_path}: {e}")
            return {"vulnerabilities": [], "warnings": []}

    def _load_sinks(self) -> Dict[str, Set[str]]:
        """Charge les sinks depuis rules.dsl, organisés par node_type."""
        sinks = {'function_call_expression': set(), 'echo_statement': set()}
        for rule in self.rules.values():
            if rule['name'] in self.vuln_types:
                for sink in rule.get('sinks', []):
                    node_type = sink.get('node_type')
                    if node_type in sinks:
                        if 'function' in sink:
                            sinks[node_type].add(sink['function'])
                        elif node_type == 'echo_statement':
                            sinks[node_type].add('echo')
        self.logger.info(f"Loaded sinks: {sinks}")
        return sinks

    def _load_filters(self) -> Dict[str, Dict[str, Any]]:
        """Charge les filtres depuis rules.dsl, avec sanitizes et warnings."""
        filters = {'function': {}, 'method': {}}
        for rule in self.rules.values():
            if rule['name'] in self.vuln_types:
                for f in rule.get('filters', []):
                    if 'function' in f:
                        filters['function'][f['function']] = {
                            'sanitizes': f.get('sanitizes', []),
                            'warning': f.get('warning')
                        }
                    elif 'method' in f:
                        for method in f['method']:
                            filters['method'][method] = {
                                'sanitizes': f.get('sanitizes', []),
                                'warning': f.get('warning')
                            }
        self.logger.info(f"Loaded filters: {filters}")
        return filters

    def is_source(self, node: Node) -> bool:
        """Vérifie si un nœud est une source de données utilisateur (ex. $_GET)."""
        text = get_node_text(node, self.source_code)
        self.logger.info(f"Checking source: node_type={node.type}, text={text}")
        if node.type == 'subscript_expression':
            object_node = node.child_by_field_name('object')
            object_text = get_node_text(object_node, self.source_code) if object_node else None
            for child in node.named_children:
                child_text = get_node_text(child, self.source_code)
                self.logger.info(f"Subscript child: type={child.type}, text={child_text}")
            for rule_name in self.vuln_types:
                rule = self.rules.get(rule_name, {})
                for source in rule.get('sources', []):
                    pattern = source['pattern'].replace('[*]', r"\['?.*?'?\]")
                    self.logger.info(f"Testing pattern: {pattern} against text: {text}")
                    if re.match(pattern, text, re.DOTALL):
                        self.logger.info(f"Source detected (regex): {text}")
                        return True
                    if object_text in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', '$_ENV']:
                        self.logger.info(f"Source detected (object): {text}, object={object_text}")
                        return True
                    for child in node.named_children:
                        if child.type == 'variable_name' and get_node_text(child, self.source_code) in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER',
                                                                                                        '$_ENV']:
                            self.logger.info(f"Source detected (child): {text}, child={get_node_text(child, self.source_code)}")
                            return True
        elif node.type == 'variable_name':
            var_text = get_node_text(node, self.source_code)
            if var_text in ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', '$_ENV']:
                self.logger.info(f"Source detected (direct variable): {var_text}")
                return True
        return False

    def is_filter_call(self, node: Node) -> tuple[bool, List[str], str | None]:
        """Vérifie si un nœud est un appel de fonction/méthode de sanitization."""
        sanitized_types = []
        is_filter = False
        warning = None
        filter_name = None

        if node.type == 'function_call_expression':
            func_node = node.child_by_field_name('function')
            if func_node:
                filter_name = get_node_text(func_node, self.source_code)
                self.logger.info(f"Checking filter: func_name={filter_name}")
                if filter_name in self.filter_functions['function']:
                    is_filter = True
                    filter_info = self.filter_functions['function'][filter_name]
                    sanitized_types = filter_info['sanitizes']
                    warning = filter_info.get('warning')
        elif node.type == 'member_call_expression':
            method_node = node.child_by_field_name('name')
            if method_node:
                filter_name = get_node_text(method_node, self.source_code)
                self.logger.info(f"Checking filter: method_name={filter_name}")
                if filter_name in self.filter_functions['method']:
                    is_filter = True
                    filter_info = self.filter_functions['method'][filter_name]
                    sanitized_types = filter_info['sanitizes']
                    warning = filter_info.get('warning')

        if is_filter and warning:
            self.warnings.append({
                "type": "non_preferred_filter",
                "function": filter_name,
                "line": node.start_point[0] + 1,
                "file": None,  # Défini dans analyze
                "message": warning
            })
            self.logger.info(f"Warning added: {warning} for {filter_name}")

        return is_filter, sanitized_types, filter_name

    def handle_assignment(self, node: Node) -> None:
        """Propage le taint via les assignations."""
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')
        if left and left.type == 'variable_name' and right:
            var_name = get_node_text(left, self.source_code)
            self.logger.info(f"Assignment: var={var_name}, right_type={right.type}")
            if self.is_source(right):
                self.tainted_vars.add(var_name)
                self.logger.info(f"Tainted var: {var_name} (source)")
            elif right.type == 'function_call_expression':
                func_node = right.child_by_field_name('function')
                if func_node:
                    func_name = get_node_text(func_node, self.source_code)
                    func_def = self.find_function_definition(func_name, right)
                    if func_def and self.has_tainted_return(func_def):
                        self.tainted_vars.add(var_name)
                        self.logger.info(f"Tainted var: {var_name} (function return)")
            elif any(get_node_text(c, self.source_code) in self.tainted_vars
                     for c in right.named_children if c.type == 'variable_name'):
                self.tainted_vars.add(var_name)
                self.logger.info(f"Tainted var: {var_name} (variable)")

    def handle_function_call(self, node: Node) -> None:
        """Gère les appels de fonctions pour propagation et sinks."""
        func_node = node.child_by_field_name('function')
        if func_node:
            func_name = get_node_text(func_node, self.source_code)
            self.logger.info(f"Processing call: {func_name}")
            is_filter, sanitized_types, filter_name = self.is_filter_call(node)
            if is_filter:
                args = node.child_by_field_name('arguments')
                if args and args.named_children and args.named_children[0].type == 'argument' and args.named_children[0].named_children:
                    var_name = get_node_text(args.named_children[0].named_children[0], self.source_code)
                    self.sanitized_vars.setdefault(var_name, set()).update(sanitized_types)
                    self.logger.info(f"Sanitized var: {var_name} by {filter_name}")
            elif func_name in self.sink_functions['function_call_expression']:
                self.sink_nodes.append(node)
                self.logger.info(f"Sink detected: {func_name}")
            elif func_name not in self.filter_functions['function']:
                args = node.child_by_field_name('arguments')
                if args:
                    func_def = self.find_function_definition(func_name, node)
                    if func_def:
                        params = self.get_function_params(func_def)
                        for i, arg in enumerate(args.named_children):
                            if i < len(params) and arg.type == 'argument' and arg.named_children:
                                arg_var = get_node_text(arg.named_children[0], self.source_code)
                                if arg_var in self.tainted_vars:
                                    param_var = params[i]
                                    self.tainted_vars.add(param_var)
                                    self.logger.info(f"Propagated taint: {arg_var} -> {param_var} in {func_name}")

    def handle_member_call(self, node: Node) -> None:
        """Gère les appels de méthodes pour sanitization."""
        is_filter, sanitized_types, filter_name = self.is_filter_call(node)
        if is_filter:
            args = node.child_by_field_name('arguments')
            if args and args.named_children and args.named_children[0].type == 'argument' and args.named_children[0].named_children:
                var_name = get_node_text(args.named_children[0].named_children[0], self.source_code)
                self.sanitized_vars.setdefault(var_name, set()).update(sanitized_types)
                self.logger.info(f"Sanitized var: {var_name} by {filter_name}")

    def handle_echo_statement(self, node: Node) -> None:
        """Gère les echo comme sinks."""
        if 'echo' in self.sink_functions['echo_statement']:
            self.sink_nodes.append(node)
            self.logger.info("Echo detected as sink")

    def handle_binary_expression(self, node: Node, file_path: str) -> None:
        """Analyse les comparaisons faibles (ex. auth_bypass)."""
        operator = get_node_text(node.child_by_field_name('operator'), self.source_code) if node.child_by_field_name('operator') else None
        self.logger.info(f"Checking pattern: node_type={node.type}, operator={operator}")
        for rule_name in self.vuln_types:
            rule = self.rules.get(rule_name, {})
            for pattern in rule.get('patterns', []):
                if pattern['type'] == node.type and pattern.get('operator') == operator:
                    self.vulnerabilities.append({
                        "type": pattern['vuln'],
                        "sink": "weak_comparison",
                        "line": node.start_point[0] + 1,
                        "file": file_path,
                        "trace": f"Comparaison faible (==) détectée"
                    })
                    self.logger.info(f"Adding auth_bypass vulnerability at line {node.start_point[0] + 1}")

    def get_sink_info(self, func_name: str, node_type: str) -> tuple[str, List[Dict]]:
        """Récupère les infos de vulnérabilité pour un sink."""
        for rule_name in self.vuln_types:
            rule = self.rules.get(rule_name, {})
            for sink in rule.get('sinks', []):
                if sink.get('node_type') == node_type and (sink.get('function') == func_name or (node_type == 'echo_statement' and func_name == 'echo')):
                    self.logger.info(f"Sink detected: {func_name}, vuln: {sink['vuln']}")
                    return sink['vuln'], sink['args']
        return "", []

    def analyze_sink(self, node: Node, file_path: str) -> None:
        """Analyse un sink pour détecter les vulnérabilités."""
        func_name = None
        args = []
        node_type = node.type
        if node.type == 'function_call_expression':
            func_node = node.child_by_field_name('function')
            if not func_node:
                return
            func_name = get_node_text(func_node, self.source_code)
            args_node = node.child_by_field_name('arguments')
            if args_node:
                args = args_node.named_children
        elif node.type == 'echo_statement':
            func_name = 'echo'
            args = node.named_children

        vuln_type, args_to_check = self.get_sink_info(func_name, node_type)
        if not vuln_type:
            return

        self.logger.info(f"Analyzing sink: {func_name}, args_count={len(args)}")
        self.logger.info(f"Tainted vars before sink analysis: {self.tainted_vars}")
        for arg_rule in args_to_check:
            arg_index = arg_rule['index']
            arg_type = arg_rule['type']
            if arg_index < len(args):
                arg = args[arg_index]
                self.logger.info(f"Checking arg {arg_index}: type={arg.type}")
                if arg.type == 'argument' and arg.named_children:  # function_call_expression
                    actual_arg = arg.named_children[0]
                    self.logger.info(f"Actual arg type: {actual_arg.type}")
                    if arg_type == 'variable' and actual_arg.type == 'variable_name':
                        var_name = get_node_text(actual_arg, self.source_code)
                        self.logger.info(f"Variable arg: {var_name}, tainted: {var_name in self.tainted_vars}")
                        if var_name in self.tainted_vars and vuln_type not in self.sanitized_vars.get(var_name, set()):
                            self.vulnerabilities.append({
                                "type": vuln_type,
                                "sink": func_name,
                                "variable": var_name,
                                "line": node.start_point[0] + 1,
                                "file": file_path,
                                "trace": f"Source tainted: {var_name} → Sink: {func_name}"
                            })
                            self.logger.info(f"Adding vulnerability: {vuln_type} for {var_name}")
                    elif arg_type == 'string' and actual_arg.type in ['string', 'encapsed_string']:
                        def find_variables(n: Node):
                            if n.type in ['variable_name', 'encapsed_variable']:
                                var_name = get_node_text(n, self.source_code)
                                self.logger.info(f"Variable in string: {var_name}, tainted: {var_name in self.tainted_vars}")
                                if var_name in self.tainted_vars and vuln_type not in self.sanitized_vars.get(var_name, set()):
                                    self.vulnerabilities.append({
                                        "type": vuln_type,
                                        "sink": func_name,
                                        "variable": var_name,
                                        "line": node.start_point[0] + 1,
                                        "file": file_path,
                                        "trace": f"Source tainted: {var_name} → Sink: {func_name} (in string)"
                                    })
                                    self.logger.info(f"Adding vulnerability: {vuln_type} for {var_name} (in string)")
                            for child in n.children:
                                find_variables(child)
                        find_variables(actual_arg)
                elif arg_type == 'variable' and arg.type == 'variable_name':  # echo_statement
                    var_name = get_node_text(arg, self.source_code)
                    self.logger.info(f"Variable arg: {var_name}, tainted: {var_name in self.tainted_vars}")
                    if var_name in self.tainted_vars and vuln_type not in self.sanitized_vars.get(var_name, set()):
                        self.vulnerabilities.append({
                            "type": vuln_type,
                            "sink": func_name,
                            "variable": var_name,
                            "line": node.start_point[0] + 1,
                            "file": file_path,
                            "trace": f"Source tainted: {var_name} → Sink: {func_name}"
                        })
                        self.logger.info(f"Adding vulnerability: {vuln_type} for {var_name}")

    def has_tainted_return(self, func_def: Node) -> bool:
        """Vérifie si une fonction retourne une valeur tainted."""
        def check_node(node: Node) -> bool:
            if node.type == 'return_statement' and node.named_children:
                return_value = node.named_children[0]
                self.logger.info(f"Checking return value: type={return_value.type}, text={get_node_text(return_value, self.source_code)}")
                if self.is_source(return_value):
                    self.logger.info("Tainted return detected: source")
                    return True
                if return_value.type == 'variable_name' and get_node_text(return_value, self.source_code) in self.tainted_vars:
                    self.logger.info(f"Tainted return detected: variable {get_node_text(return_value, self.source_code)}")
                    return True
                for child in return_value.named_children:
                    if check_node(child):
                        return True
            for child in node.children:
                if check_node(child):
                    return True
            return False

        self.logger.info("Analyzing function for tainted return")
        return check_node(func_def)

    def find_function_definition(self, func_name: str, current_node: Node) -> Node | None:
        """Trouve la déclaration de la fonction dans l'AST."""
        def search(node: Node) -> Node | None:
            if node.type == 'function_definition':
                name_node = node.child_by_field_name('name')
                if name_node and get_node_text(name_node, self.source_code) == func_name:
                    self.logger.info(f"Found function definition: {func_name}")
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
        self.logger.info(f"Parameters node: {'found' if parameters_node else 'not found'}")
        if parameters_node:
            self.logger.info(f"Parameters node type: {parameters_node.type}")
            for param in parameters_node.children:
                self.logger.info(f"Parameter child: type={param.type}, text={get_node_text(param, self.source_code)}")
                if param.type == 'simple_parameter':
                    for child in param.children:
                        if child.type == 'variable_name':
                            param_name = get_node_text(child, self.source_code)
                            params.append(param_name)
                            self.logger.info(f"Found parameter: {param_name}")
        return params

    def track_taint(self, node: Node, file_path: str) -> None:
        """Parcourt l'AST et appelle les handlers pour chaque type de nœud."""
        handler = self.node_handlers.get(node.type)
        if handler:
            handler(node, file_path) if node.type == 'binary_expression' else handler(node)
        for child in node.children:
            self.track_taint(child, file_path)

    def analyze(self, tree: Node, file_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """Analyse l'AST pour détecter les vulnérabilités et avertissements."""
        self.tainted_vars.clear()
        self.vulnerabilities.clear()
        self.warnings.clear()
        self.sanitized_vars.clear()
        self.sink_nodes.clear()
        self.track_taint(tree.root_node, file_path)
        self.logger.info(f"Tainted vars after propagation: {self.tainted_vars}")
        for sink_node in self.sink_nodes:
            self.analyze_sink(sink_node, file_path)
        for warning in self.warnings:
            warning['file'] = file_path
        return {"vulnerabilities": self.vulnerabilities, "warnings": self.warnings}