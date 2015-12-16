<?php

class UnitTest extends PHPUnit_Framework_TestCase {
  public function testIndexFile() {
    $this->assertTrue(php_check_syntax("index.php"));
  }
  public function testLoginFile() {
    $this->assertTrue(php_check_syntax("register_login.php"));
  }
  public function testRegisterFile() {
    $this->assertTrue(php_check_syntax("register_register.php"));
  }
  public function testTokenFile() {
    $this->assertTrue(php_check_syntax("register_token.php"));
  }
}

?>
