<?php


function register_force_https() {
	if(empty($_SERVER["HTTPS"]) || $_SERVER["HTTPS"] !== "on")
	{
		header("Location: https://" . $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"]);
		exit();
	}
}

//get random string
function register_getRandom($length) {
	$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	
	$returnstr = "";
	for ($i=0; $i < $length; $i++) {
		$random = rand(0, strlen($chars)-1);
		$returnstr .= $chars[$random];
	}
	
	return $returnstr;
}

//default values
function register_getDefaultValues($name) {
	if (isset($_POST[$name])) {
		echo htmlentities($_POST[$name]);
	}
}


function register_checkUsernameChars($username) {
	if (strlen($username) < 3 || strlen($username) > 20) {
		return false;
	}
	
	if (preg_match("/\A[a-zA-Z][a-zA-Z0-9\_\-]{2,19}\z/", $username)) {
		return true;
	}
	return false;
}

function register_checkPasswordChars($password) {
	//too small pw
	if (strlen($password) < 5 || strlen($password) > 100) {
		return false;
	}
	
	//too weak
	if (preg_match("/\A[0-9]{5,20}\z/", $password)) {
		return false;
	}
	
	return true;
}

//encrypt with sha256
function register_sha256($str) {
	return hash("sha256", $str);
}

//crypt string
function register_cryptStr($str, $salt) {
	return register_sha256($salt . register_sha256($str . $salt));
}

//compare password with crypted string
function register_comparePW($pw, $hash, $salt) {
	if (register_cryptStr($pw, $salt) == $hash) {
		return true;
	}
	return false;
}

//inserts a failed login into database
function register_insertFailedLogin($mysqli) {
	$stmt = $mysqli->prepare("INSERT INTO login_failed SET ip=?, time=UNIX_TIMESTAMP()");
	$stmt->bind_param("s", $_SERVER['REMOTE_ADDR']);
	$stmt->execute();
	$stmt->close();
}

//check how many failed login attempts were registered
function register_checkLoginFailed($mysqli) {
	$stmt = $mysqli->prepare("SELECT id FROM login_failed WHERE ip=? AND time>?");
	$time = time()-$GLOBALS['REGISTER_FAILBANTIME'];
	$stmt->bind_param("si", $_SERVER['REMOTE_ADDR'], $time);
	$stmt->execute();
	$stmt->store_result();
	$stmt->fetch();
	$count = $stmt->num_rows();
	$stmt->close();
	
	return $count;
}

//inserts a successful login into database
function register_insertSuccessLogin($mysqli, $uid) {
	$stmt = $mysqli->prepare("INSERT INTO login_success SET ip=?, uid=?, time=UNIX_TIMESTAMP()");
	$stmt->bind_param("si", $_SERVER['REMOTE_ADDR'], $uid);
	$stmt->execute();
	$stmt->close();
}

//checks login
function register_checkLogin($mysqli, $username, $password) {
	$n_un = strlen($username);
	$n_pw = strlen($password);
	$failmessageadd = "";
	
	if ($n_un >= 3 && $n_un <= 20 && $n_pw >= 3 && $n_pw <= 100) {
		
		//get failed login attempts
		$lfailed = register_checkLoginFailed($mysqli);
		if ($lfailed >= floor($GLOBALS['REGISTER_FAILBANCOUNT']/2)) {
			$failmessageadd = "If you forgot your password, please use the password recovery. You will be blocked after ". $GLOBALS['REGISTER_FAILBANCOUNT'] . " failed login attempts.";
			if ($lfailed >= $GLOBALS['REGISTER_FAILBANCOUNT']-1) {
				$failmessageadd = "You were banned because of too many failed login attempts. Please try again in " . $GLOBALS['REGISTER_FAILBANTIME']/60 . " minutes.";
				if ($lfailed >= $GLOBALS['REGISTER_FAILBANCOUNT']) {
					return $failmessageadd . "<br>";
				}
			}
			
		}
		
		//get user from db
		$stmt = $mysqli->prepare("SELECT id, password, salt, activated FROM user WHERE username=? LIMIT 1");
		$stmt->bind_param("s", $username);
		$stmt->execute();
		$stmt->bind_result($res_id, $res_pw, $res_salt, $res_act);
		$stmt->store_result();
		$stmt->fetch();
		
		//wrong username
		if ($stmt->num_rows != 1) {
			register_insertFailedLogin($mysqli);
			return "Username not found!<br>" . $failmessageadd;
		}
		$stmt->close();
		
		//not activated
		if ($res_act != 1) {
			return "User not activated!";
		}
		
		//password incorrect
		if (!register_comparePW($password, $res_pw, $res_salt)) {
			register_insertFailedLogin($mysqli);
			return "Password incorrect!<br>" . $failmessageadd;
		}
		
		//-> login successful
		register_insertSuccessLogin($mysqli, $res_id);
		register_newSession($mysqli, $res_id);
		
	} else {
		return "Invalid input!";
	}
}

//create new session
function register_newSession($mysqli, $userid) {
	$sid = register_getRandom(64);
	
	//delete obsolete sessions
	$time = time() - $GLOBALS['REGISTER_SESSIONTIME'];
	$stmt = $mysqli->prepare("DELETE FROM sessions WHERE uid=? AND ( last_active<? OR active=0 )");
	$stmt->bind_param("ii", $userid, $time);
	$stmt->execute();
	$stmt->close();
	
	//insert new session
	$stmt = $mysqli->prepare("INSERT INTO sessions SET ip=?, uid=?, sid=?, start_time=UNIX_TIMESTAMP(), last_active=UNIX_TIMESTAMP()");
	$stmt->bind_param("sis", $_SERVER['REMOTE_ADDR'], $userid, $sid);
	$stmt->execute();
	$stmt->close();
	
	$_SESSION['SESSID'] = $sid;
}

//check active session
function register_checkSession($mysqli) {
	if (!isset($_SESSION['SESSID'])) {
		return;
	}
	
	//get session from db
	$stmt = $mysqli->prepare("SELECT id, uid FROM sessions WHERE ip=? AND sid=? AND last_active>? AND active=1 ORDER BY ID DESC LIMIT 1");
	$time = time() - $GLOBALS['REGISTER_SESSIONTIME'];
	$stmt->bind_param("ssi", $_SERVER['REMOTE_ADDR'], $_SESSION['SESSID'], $time);
	$stmt->execute();
	$stmt->bind_result($res_id, $res_uid);
	$stmt->store_result();
	$stmt->fetch();
	
	if ($stmt->num_rows != 1) {
		return;
	}
	$stmt->close();
	
	//update last active time
	$stmt = $mysqli->prepare("UPDATE sessions SET last_active=UNIX_TIMESTAMP() WHERE id=? LIMIT 1");
	$stmt->bind_param("i", $res_id);
	$stmt->execute();
	$stmt->close();
	
	//return user id
	return $res_uid;
}

//delete session
function register_deleteSession($mysqli) {
	if (!isset($_SESSION['SESSID'])) {
		return;
	}
	//set session to inactive
	$stmt = $mysqli->prepare("UPDATE sessions SET active=0 WHERE ip=? AND sid=? LIMIT 1");
	$stmt->bind_param("ss", $_SERVER['REMOTE_ADDR'], $_SESSION['SESSID']);
	$stmt->execute();
	$stmt->close();
	
	unset($_SESSION['SESSID']);
}

//register user
function register_addUser($mysqli, $username, $pw1, $pw2, $email) {
	if (!register_checkUsernameChars($username)) {
		return "The username must met the following requirements:<ul><li>3-20 characters</li><li>only contains alphanumeric characters</li><li>first character must not be a number</li></ul>";
	}
	if ($pw1 != $pw2) {
		return "The two passwords do not match.";
	}
	if (!register_checkPasswordChars($pw1)) {
		return "The password is too weak.";
	}
	if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		return "The email is invalid";
	}
	$domain = explode("@", $email);
	if (!checkdnsrr($domain[1], 'MX')) {
		return "The email domain has no MX record.";
	}
	
	//captcha
	if (!isset($_POST['g-recaptcha-response'])) {
		return "Please check the captcha!";
	} else {
		$fields = array('secret' => $GLOBALS['REGISTER_RECAPTCHA_PRIVATE'], 'response' => $_POST['g-recaptcha-response'], 'remoteip' => $_SERVER['REMOTE_ADDR']);
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, 'https://www.google.com/recaptcha/api/siteverify');
		curl_setopt($ch, CURLOPT_POST, count($fields));
		curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt ($ch, CURLOPT_CAINFO, "C:\\xampp\\htdocs\\register_script\\registrationScript\\ca-bundle.crt");
		
		$response = curl_exec($ch);
		echo curl_error($ch);
		curl_close($ch);
		
		$res= json_decode($response, true);
		if (!$res['success']) {
			return "Please solve the Captcha!";
		}
	}

	//check if user or email is already registered
	$stmt = $mysqli->prepare("SELECT username, email FROM user WHERE username=? OR email=? LIMIT 1");
	$stmt->bind_param("ss", $username, $email);
	$stmt->execute();
	$stmt->bind_result($res_us, $res_em);
	$stmt->store_result();
	$stmt->fetch();
	
	if ($stmt->num_rows != 0) {
		$stmt->close();
		if (strtoupper($res_us) == strtoupper($username)) {
			return "The username has been already registered";
		} else {
			return "The email has been already registered";
		}
	}
	$stmt->close();
	
	//insert user
	$salt = register_getRandom(20);
	$pw = register_cryptStr($pw1, $salt);
	$stmt = $mysqli->prepare("INSERT INTO user SET username=?, email=?, password=?, salt=?, register_time=UNIX_TIMESTAMP()");
	$stmt->bind_param("ssss", $username, $email, $pw, $salt);
	$stmt->execute();
	$userid = $stmt->insert_id;
	$stmt->close();
	
	//delete obsolete tokens
	$mysqli->query("DELETE FROM user_tokens WHERE time<UNIX_TIMESTAMP()-3600 AND action<>'activate'");
	
	//add token for activating
	$token = register_getRandom(10);
	$stmt = $mysqli->prepare("INSERT INTO user_tokens SET token=?, uid=?, action='activate', time=UNIX_TIMESTAMP(), email=?");
	$stmt->bind_param("sis", $token, $userid, $email);
	$stmt->execute();
	$stmt->close();
	
	//send activation email
	register_sendActivationEmail($email, $token);
}


//activate token
function register_activateToken($mysqli, $token) {
	if (strlen($token) < 3 || strlen($token) > 100) {
		return "Invalid Token";
	}
	$lfailed = register_checkLoginFailed($mysqli);
	if ($lfailed >= $GLOBALS['REGISTER_FAILBANCOUNT']) {
		return "You have been banned for 10 minutes, please try again later.";
	}
	
	//get token
	$stmt = $mysqli->prepare("SELECT id, action, email, uid FROM user_tokens WHERE token=? AND ( time>UNIX_TIMESTAMP()-3600 OR action='activate' ) LIMIT 1");
	$stmt->bind_param("s", $token);
	$stmt->execute();
	$stmt->bind_result($res_id, $res_action, $res_email, $res_uid);
	$stmt->store_result();
	$stmt->fetch();
	
	if ($stmt->num_rows != 1) {
		$stmt->close();
		register_insertFailedLogin($mysqli);
		return "Invalid Token";
	}
	$stmt->close();
	
	//token found -> delete
	$stmt = $mysqli->prepare("DELETE FROM user_tokens WHERE id=? LIMIT 1");
	$stmt->bind_param("i", $res_id);
	$stmt->execute();
	$stmt->close();
	
	//execute token
	if ($res_action == "activate") {
		register_activateUser($mysqli, $res_uid);
	} else if ($res_action == "changeemail") {
		register_changeEmail($mysqli, $res_uid, $res_email);
	} else if ($res_action == "changeemail") {
		$salt = register_getRandom(20);
		$password = register_getRandom(20);
		$crpw = register_cryptStr($password, $salt);
		register_changePw($mysqli, $res_uid, $crpw, $salt);
		//send pw email
		register_sendNewPwEmail($res_email, $password);
	}
}

//activate user id
function register_activateUser($mysqli, $userid) {
	$stmt = $mysqli->prepare("UPDATE user SET activated=1 WHERE id=? LIMIT 1");
	$stmt->bind_param("i", $userid);
	$stmt->execute();
	$stmt->close();
}

//change user email
function register_changeEmail($mysqli, $userid, $newemail) {
	$stmt = $mysqli->prepare("UPDATE user SET email=? WHERE id=? LIMIT 1");
	$stmt->bind_param("si", $newemail, $userid);
	$stmt->execute();
	$stmt->close();
}

function register_changePw($mysqli, $userid, $pw, $salt) {
	$stmt = $mysqli->prepare("UPDATE user SET password=?, salt=? WHERE id=? LIMIT 1");
	$stmt->bind_param("si", $pw, $salt, $userid);
	$stmt->execute();
	$stmt->close();
}


function register_sendActivationEmail($empfaenger, $token) {
	$betreff = 'Marbbs account activation';
	
	$header = 'From: info@marbbs.com' . "\r\n" .
		'Reply-To: info@marbbs.com' . "\r\n" .
		'X-Mailer: PHP/' . phpversion();

	$nachricht = 'Dear user,\r\n\r\n'
		. 'thank you for registering at marbbs.com. To activate your account, please visit the link below or paste the key into the form at our webpage.\r\n'
		. '\r\n'
		. 'Key:\r\n'
		. $token
		. '\r\n'
		. 'https://localhost/register_token.php?token=' . $token
		. '\r\n'
		. '\r\n'
		. 'Best regards,\r\n'
		. 'Marcel Haupt';
	
	mail($empfaenger, $betreff, $nachricht, $header);
}

function register_sendChangeEmailEmail($empfaenger, $token) {
	$betreff = 'Marbbs email activation';
	
	$header = 'From: info@marbbs.com' . "\r\n" .
		'Reply-To: info@marbbs.com' . "\r\n" .
		'X-Mailer: PHP/' . phpversion();

	$nachricht = 'Dear user,\r\n\r\n'
		. 'You account has requested an email change. To activate your new email, please click on the link below.\r\n'
		. '\r\n'
		. 'Key:\r\n'
		. $token
		. '\r\n'
		. 'https://localhost/register_token.php?token=' . $token
		. '\r\n'
		. '\r\n'
		. 'Best regards,\r\n'
		. 'Marcel Haupt';
	
	mail($empfaenger, $betreff, $nachricht, $header);
}


function register_sendForgotPwEmail($empfaenger, $token) {
	$betreff = 'Marbbs forgot password';
	
	$header = 'From: info@marbbs.com' . "\r\n" .
		'Reply-To: info@marbbs.com' . "\r\n" .
		'X-Mailer: PHP/' . phpversion();

	$nachricht = 'Dear user,\r\n\r\n'
		. 'Your account requested a password reset. To reset your password, please click on the link below.\r\n'
		. '\r\n'
		. 'Key:\r\n'
		. $token
		. '\r\n'
		. 'https://localhost/register_token.php?token=' . $token
		. '\r\n'
		. '\r\n'
		. 'Best regards,\r\n'
		. 'Marcel Haupt';
	
	mail($empfaenger, $betreff, $nachricht, $header);
}


function register_sendNewPwEmail($empfaenger, $newpw) {
	$betreff = 'Marbbs forgot password';
	
	$header = 'From: info@marbbs.com' . "\r\n" .
		'Reply-To: info@marbbs.com' . "\r\n" .
		'X-Mailer: PHP/' . phpversion();

	$nachricht = 'Dear user,\r\n\r\n'
		. 'Your password has been reset. This is your new password:\r\n'
		. '\r\n'
		. $newpw
		. '\r\n'
		. 'Please change it as soon as possible.'
		. '\r\n'
		. '\r\n'
		. 'Best regards,\r\n'
		. 'Marcel Haupt';
	
	mail($empfaenger, $betreff, $nachricht, $header);
}
?>