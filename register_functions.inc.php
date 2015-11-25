<?php

function register_getRandom($length) {
	$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	
	$returnstr = "";
	for ($i=0; $i < $length; $i++) {
		$random = rand(0, strlen($chars)-1);
		$returnstr .= $chars[$random];
	}
	
	return $returnstr;
}

function register_sha256($str) {
	return hash("sha256", $str);
}

function register_cryptStr($str, $salt) {
	return register_sha256($salt . register_sha256($str . $salt));
}

function register_comparePW($pw, $hash, $salt) {
	if (register_cryptStr($pw, $salt) == $hash) {
		return true;
	}
	return false;
}


function register_login($username, $password) {
	
}
?>