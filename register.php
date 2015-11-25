<?php
session_start();
require("register_config.inc.php");
require("register_functions.inc.php");

if (isset($_POST['username']) && isset($_POST['password'])) {
	if ($warning = register_checkLogin($register_mysql, $_POST['username'], $_POST['password'])) {
		echo $warning;
	} else {
		echo "Login successful!";
	}
}

if ($register_userid = register_checkSession($register_mysql)) {
	echo "Successfully registered with userid: " . $register_userid;
}
?>

<form action="#" method="post">
<input type="text" name="username"><br>
<input type="password" name="password"><br>
<input type="submit" value="Login">
</form>