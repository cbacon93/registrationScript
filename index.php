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


if ($register_userid > 0)
?>
<a href="?store=login" class="btn btn-default btn-sm" role="button">Login</a> <a href="?store=register" class="btn btn-default btn-sm" role="button">Register</a>
<?php
} else {
?>
<a href="?store=login&logout" class="btn btn-default btn-sm" role="button">Logout</a>
<?php
}
?>

<br>
Content of the store can be seen here!