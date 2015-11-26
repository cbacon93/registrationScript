<?php
session_start();
require("register_config.inc.php");
require("register_functions.inc.php");
register_force_https();
?>
<form method="GET" action="register_token.php">
<input type="text" name="token" required>
<input type="submit" value="Submit">

</form>