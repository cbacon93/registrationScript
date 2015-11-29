<?php
session_start();
require("register_config.inc.php");
require("register_functions.inc.php");
register_force_https();

//already logged in-> redirect
if ($register_userid = register_checkSession($register_mysql)) {
	//header("Location: ");
	//exit();
}


$error = null;

//registration successful
if (register_register_check($register_mysql, $error)) {
	header("Location: register_token.php?msg=activate");
	exit();
}


if ($error) echo $error;
?>

<script src='https://www.google.com/recaptcha/api.js'></script>


<form action="register_register.php" method="post">
UN:<input type="text" name="username" value="<?php register_getDefaultValues("username"); ?>" required><br>
EM:<input type="email" name="email" value="<?php register_getDefaultValues("email"); ?>" required><br>
PW:<input type="password" name="password1" required><br>
PW:<input type="password" name="password2" required><br>
<div class="g-recaptcha" data-sitekey="<?php echo $GLOBALS['REGISTER_RECAPTCHA_PUBLIC']; ?>"></div>
<input type="submit" value="Register">
</form>