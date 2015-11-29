<?php
session_start();
require("register_config.inc.php");
require("register_functions.inc.php");
register_force_https();

$error = null;
if (isset($_GET['token'])) {
	if (!($error = register_activateToken($register_mysql, $_GET['token']))) {
		//header("location: ");
		//exit(); //token activated
	}
}

if ($error) {
		echo $error;
} else {
	if (isset($_GET['msg'])) {
		if ($_GET['msg'] == "activate") {
			echo "An activation key has been sent to your email adress. Please insert this code here to verify your email adress.";
		}
	}
}
?>
<form method="GET" action="#">
<input type="text" name="token" required>
<input type="submit" value="Submit">

</form>