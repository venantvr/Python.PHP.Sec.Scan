<?php
$input = $_GET['input'];
echo $input; // XSS vulnérable
$safe = htmlspecialchars($input);
echo $safe; // Non vulnérable
?>