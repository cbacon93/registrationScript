<?php
session_start();
require("register_config.inc.php");
require("register_functions.inc.php");
register_force_https();

//already registered -> redirect
if ($register_userid = register_checkSession($register_mysql)) {
	//header("Location: ");
	//exit();
}

//register forms
if (isset($_POST['username']) && isset($_POST['email']) && isset($_POST['password1']) && isset($_POST['password2'])) {
	if ($error = register_addUser($register_mysql, $_POST['username'], $_POST['password1'], $_POST['password2'], $_POST['email'])) {
		echo $error;
	} else {
		echo "Registered successfully";
	}
}
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