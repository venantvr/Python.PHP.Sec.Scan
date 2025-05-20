# tests/test_taint_tracker.py
import tree_sitter_php as tsphp
from tree_sitter import Parser, Language

from analysis.taint_tracker import TaintTracker

# Initialiser le parseur pour PHP
PHP_LANGUAGE = Language(tsphp.language_php())
PARSER = Parser(PHP_LANGUAGE)


def test_taint_tracker_sql_injection():
    """Teste la détection d'une injection SQL."""
    code = """
    <?php
    $id = $_GET['id'];
    mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    vulns = tracker.analyze(tree, "test.php")
    assert len(vulns) == 1
    assert vulns[0]["type"] == "sql_injection"
    assert vulns[0]["sink"] == "mysqli_query"
    assert vulns[0]["variable"] == "$id"


def test_taint_tracker_xss_sanitized():
    """Teste la non-détection de XSS avec désinfection."""
    code = """
    <?php
    $input = $_GET['input'];
    $safe = htmlspecialchars($input);
    echo $safe;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    vulns = tracker.analyze(tree, "test.php")
    assert len(vulns) == 0


def test_taint_tracker_auth_bypass():
    """Teste la détection d'une comparaison faible."""
    code = """
    <?php
    if ($password == $_POST['password']) {
        login();
    }
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['auth_bypass'])
    vulns = tracker.analyze(tree, "test.php")
    assert len(vulns) == 1
    assert vulns[0]["type"] == "auth_bypass"
    assert "weak_comparison" in vulns[0]["sink"]


def test_taint_tracker_sql_injection_function_param():
    """Teste la détection d'une injection SQL via un paramètre de fonction."""
    code = """
    <?php
    function run_query($conn, $value) {
        mysqli_query($conn, "SELECT * FROM users WHERE id = $value");
    }
    $id = $_GET['id'];
    run_query($conn, $id);
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'])
    vulns = tracker.analyze(tree, "test.php")
    assert len(vulns) == 1
    assert vulns[0]["type"] == "sql_injection"
    assert vulns[0]["sink"] == "mysqli_query"
    assert vulns[0]["variable"] == "$value"
