<?php

class Test extends PHPUnit_Framework_TestCase{

    private $conn;

    public function __construct(){
        $connString = 'mysql:host=127.0.0.1;dbname=simple_auth_test';
        $this->conn = new PDO($connString, 'root', '');
    }
}
