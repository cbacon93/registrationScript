<?php
session_start();
require("register_config.inc.php");
require("register_functions.inc.php");
register_force_https();


$register_userid = -1;
if (!($register_userid = register_checkSession($register_mysql))) {
	//header("Location: "); //not registered
	//exit();
}


if ($register_userid > 0) {
?>
<a href="register_login.php" class="btn btn-default btn-sm" role="button">Login</a> <a href="register_register.php" class="btn btn-default btn-sm" role="button">Register</a>
<?php
} else {
?>
<a href="register_login.php?logout" class="btn btn-default btn-sm" role="button">Logout</a>
<?php
}
?>

<br>
Content of the store can be seen here!
