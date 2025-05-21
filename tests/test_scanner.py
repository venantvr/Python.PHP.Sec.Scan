# tests/test_scanner.py
import json

from analysis.scanner import Scanner


def test_scan_single_file(tmp_path):
    """Teste l'analyse d'un seul fichier avec une vulnérabilité XSS."""
    file_path = tmp_path / "test.php"
    code = """
    <?php
    function get_tainted() {
        return $_POST['data'];
    }
    $x = get_tainted();
    echo $x;
    ?>
    """
    file_path.write_bytes(code.encode('utf-8'))

    scanner = Scanner(['xss'], verbose=False)
    scanner.scan_file(str(file_path))

    assert str(file_path) in scanner.results
    result = scanner.results[str(file_path)]
    assert len(result['vulnerabilities']) == 1
    assert result['vulnerabilities'][0]['type'] == 'xss'
    assert result['vulnerabilities'][0]['sink'] == 'echo'
    assert result['vulnerabilities'][0]['variable'] == '$x'
    assert len(result['warnings']) == 0


def test_scan_multiple_files(tmp_path):
    """Teste l'analyse de plusieurs fichiers."""
    file1 = tmp_path / "file1.php"
    file1.write_bytes("""
    <?php
    $input = $_GET['input'];
    echo $input;
    ?>
    """.encode('utf-8'))

    file2 = tmp_path / "file2.php"
    file2.write_bytes("""
    <?php
    $input = $_GET['input'];
    $safe = htmlspecialchars($input);
    echo $safe;
    ?>
    """.encode('utf-8'))

    scanner = Scanner(['xss'], verbose=False)
    results = scanner.scan_files([str(file1), str(file2)])

    assert len(results) == 1  # Seulement file1 a une vuln
    assert str(file1) in results
    assert len(results[str(file1)]['vulnerabilities']) == 1
    assert results[str(file1)]['vulnerabilities'][0]['type'] == 'xss'
    assert str(file2) not in results  # Pas de vuln/warning


def test_scan_directory(tmp_path):
    """Teste l'analyse d'une arborescence."""
    dir1 = tmp_path / "src"
    dir1.mkdir()
    file1 = dir1 / "vuln.php"
    file1.write_bytes("""
    <?php
    $input = $_POST['data'];
    echo $input;
    ?>
    """.encode('utf-8'))

    dir2 = dir1 / "sub"
    dir2.mkdir()
    file2 = dir2 / "safe.php"
    file2.write_bytes("""
    <?php
    $input = $_POST['data'];
    $safe = htmlspecialchars($input);
    echo $safe;
    ?>
    """.encode('utf-8'))

    scanner = Scanner(['xss'], verbose=False)
    results = scanner.scan_directory(str(tmp_path))

    assert len(results) == 1  # Seulement vuln.php a une vuln
    assert str(file1) in results
    assert len(results[str(file1)]['vulnerabilities']) == 1
    assert results[str(file1)]['vulnerabilities'][0]['type'] == 'xss'
    assert str(file2) not in results


def test_save_results(tmp_path):
    """Teste la sauvegarde des résultats."""
    file_path = tmp_path / "test.php"
    file_path.write_bytes("""
    <?php
    $input = $_GET['input'];
    echo $input;
    ?>
    """.encode('utf-8'))

    output_path = tmp_path / "report.json"
    scanner = Scanner(['xss'], verbose=False)
    scanner.scan_file(str(file_path))
    scanner.save_results(str(output_path))

    assert output_path.exists()
    with open(output_path, 'r', encoding='utf-8') as f:
        results = json.load(f)
    assert str(file_path) in results
    assert len(results[str(file_path)]['vulnerabilities']) == 1
