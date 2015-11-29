<?php
session_start();
require("register_config.inc.php");
require("register_functions.inc.php");
register_force_https();


$warning = null;
$register_userid = -1;

if (register_login_checks($register_mysql, $warning, $register_userid)) {
	//header("Location: ");
	//exit(); //login successful
}

if ($register_userid) {
	//header("Location: ");
	//exit(); //already logged in
}

if ($warning) echo $warning;
?>

<form action="register_login.php" method="post">
<input type="text" name="username" value="<?php register_getDefaultValues("username"); ?>"><br>
<input type="password" name="password"><br>
<input type="submit" value="Login">
</form>
<a href="?logout">Logout</a>