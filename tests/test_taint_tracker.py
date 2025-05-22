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
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
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
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
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
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
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
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "sql_injection"
    assert vulns[0]["sink"] == "mysqli_query"
    assert vulns[0]["variable"] == "$value"


def test_taint_tracker_xss_htmlentities_warning():
    """Teste l'avertissement pour l'usage de htmlentities au lieu de sanitize_text_field."""
    code = """
    <?php
    $input = $_POST['data'];
    $safe = htmlentities($input);
    echo $safe;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    warnings = result["warnings"]
    assert len(vulns) == 0
    assert len(warnings) == 1
    assert warnings[0]["type"] == "non_preferred_filter"
    assert warnings[0]["function"] == "htmlentities"
    assert warnings[0]["message"] == "Use sanitize_text_field instead"
    assert warnings[0]["file"] == "test.php"


def test_taint_tracker_xss_class_method_sanitization():
    """Teste la détection d'une méthode de classe comme filtre XSS."""
    code = """
    <?php
    class Sanitizer {
        static function sanitizeText($input) {
            return sanitize_text_field($input);
        }
    }
    $input = $_POST['data'];
    $safe = Sanitizer::sanitizeText($input);
    echo $safe;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    warnings = result["warnings"]
    assert len(vulns) == 0
    assert len(warnings) == 0


def test_taint_tracker_xss_function_return():
    """Teste la détection d'une vulnérabilité XSS via le retour d'une fonction."""
    code = """
    <?php
    function get_tainted() {
        return $_POST['data'];
    }
    $x = get_tainted();
    echo $x;
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['xss'])
    result = tracker.analyze(tree, "test.php")
    vulns = result["vulnerabilities"]
    warnings = result["warnings"]
    assert len(vulns) == 1
    assert vulns[0]["type"] == "xss"
    assert vulns[0]["sink"] == "echo"
    assert vulns[0]["variable"] == "$x"
    assert len(warnings) == 0


def test_taint_tracker_unsanitized_source():
    """Teste l'avertissement pour une source lue sans sanitization."""
    code = """
    <?php
    $id = $_GET['id'];
    $var = $id; // Propagation sans sanitization
    ?>
    """
    tree = PARSER.parse(code.encode('utf-8'))
    tracker = TaintTracker(code.encode('utf-8'), ['sql_injection'], verbose=True)  # Activer verbose
    result = tracker.analyze(tree, "test.php")
    warnings = result["warnings"]
    assert len(warnings) >= 1
    assert any(w["type"] == "unsanitized_source" and w["variable"] == "$id" for w in warnings)
    assert any(w["type"] == "unsanitized_source" and w["variable"] == "$var" for w in warnings)
