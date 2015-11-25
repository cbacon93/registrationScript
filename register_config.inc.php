<?php
$REGISTER_FAILBANTIME = 600;
$REGISTER_FAILBANCOUNT = 5;
$REGISTER_SESSIONTIME = 1800;


$register_mysql = new mysqli('localhost', 'root', '', 'marbbs');

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
?>