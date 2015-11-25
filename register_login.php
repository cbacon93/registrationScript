<?php
session_start();
require("register_config.inc.php");
require("register_functions.inc.php");
register_force_https();

//check login form input
if (isset($_POST['username']) && isset($_POST['password'])) {
	if ($warning = register_checkLogin($register_mysql, $_POST['username'], $_POST['password'])) {
		echo $warning;
	} else {
		//header("Location: ");
		//exit();
		echo "Login successful!";
	}
}

if (isset($_GET['logout'])) {
	register_deleteSession($register_mysql);
	echo "Logged out successfully";
}

if ($register_userid = register_checkSession($register_mysql)) {
	//header("Location: ");
	//exit();
	echo "Successfully registered with userid: " . $register_userid;
}
?>

<form action="register_login.php" method="post">
<input type="text" name="username"><br>
<input type="password" name="password"><br>
<input type="submit" value="Login">
</form>
<a href="?logout">Logout</a>