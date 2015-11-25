<?php

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


function register_newSession($mysqli, $userid) {
	$sid = register_getRandom(64);
	
	$stmt = $mysqli->prepare("INSERT INTO sessions SET ip=?, uid=?, sid=?, start_time=UNIX_TIMESTAMP(), last_active=UNIX_TIMESTAMP()");
	$stmt->bind_param("sis", $_SERVER['REMOTE_ADDR'], $userid, $sid);
	$stmt->execute();
	$stmt->close();
	
	$_SESSION['SESSID'] = $sid;
}


function register_checkSession($mysqli) {
	if (!isset($_SESSION['SESSID'])) {
		return;
	}
	
	//get session from db
	$stmt = $mysqli->prepare("SELECT id, uid FROM sessions WHERE ip=? AND sid=? AND last_active>? ORDER BY ID DESC LIMIT 1");
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

?>