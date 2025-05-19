<?php
$password = "secret";
if ($password == $_POST['password']) { // Comparaison faible
    login();
}
if (password_verify($_POST['password'], $hash)) { // Sécurisé
    login();
}
?>