<?php
$REGISTER_FAILBANTIME = 600;
$REGISTER_FAILBANCOUNT = 5;
$REGISTER_SESSIONTIME = 1800;

$REGISTER_RECAPTCHA_PUBLIC = "";
$REGISTER_RECAPTCHA_PRIVATE = "";


$register_mysql = new mysqli('localhost', 'root', '', 'register');

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
?>