<?php
require("register_config.inc.php");
require("register_functions.inc.php");

$salt = register_getRandom(20);
$pw = "Hallo";
$hash = register_cryptStr("Hallo", $salt);

echo register_comparePW($pw, $hash, $salt);

?>