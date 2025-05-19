# analysis/taint_tracker.py

from config.loader import load_rules
from utils.text import get_node_text

SOURCES = {'$_GET', '$_POST', '$_COOKIE', '$_REQUEST'}
FILTER_FUNCTIONS = {'htmlspecialchars', 'mysqli_real_escape_string'}
SINK_FUNCTIONS = {'eval', 'mysqli_query', 'shell_exec', 'system', 'exec', 'passthru'}


# analysis/taint_tracker.py


class TaintTracker:
    def __init__(self, source_code: bytes):
        self.source_code = source_code
        self.rules = load_rules()
        self.tainted_vars = set()
        self.vulnerabilities = []

    def is_source(self, node):
        return get_node_text(node, self.source_code) in self.rules['sources']

    def is_filter_call(self, node):
        func = node.child_by_field_name('function')
        return func and get_node_text(func, self.source_code) in self.rules['filters']

    def get_sink_type(self, func_name):
        for vuln_type, sinks in self.rules.get("sinks", {}).items():
            if func_name in sinks:
                return vuln_type
        return None

    def analyze_sink(self, node, file_path):
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
                    if arg_name in self.tainted_vars:
                        self.vulnerabilities.append({
                            "type": vuln_type,
                            "sink": func_name,
                            "variable": arg_name,
                            "line": node.start_point[0] + 1,
                            "file": file_path
                        })
