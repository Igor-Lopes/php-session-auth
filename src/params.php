<?php

$params = array();
/* Session */
$params['cookieExp'] = 0;
$params['sessionName'] = "php_auth";
$params['secure'] = false;
$params['httponly'] = true;

/* mysqli */
$params['serverName'] = "localhost";
$params['userName'] = "root";
$params['password'] = "root";
$params['dbName'] = "php_auth";

/* PHP Mailer*/
$params['host'] = "";
$params['port'] = 587;
$params['SMTPSecure'] = "";
$params['SMTPAuth'] = true;
$params['from'] = "";
$params['pwd']  = "";
$params['subject'] = "PHP Simple Auth - Activate your account";
$params['wordWrap'] = 50;

?>
