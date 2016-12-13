<?php

class Test extends PHPUnit_Framework_TestCase{

    private $conn;

    public function __construct(){
        $this->conn = new mysqli('127.0.0.1', 'root', '', 'simple_auth_test');
    }

    public function testDbCon(){
        $Username = 'Admin';
        $password = 'admin';
        $email = 'admin@email.com';

        $password = hash('sha512', $password);
        $password = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->conn->prepare('INSERT INTO users (Username, email, password) VALUES (?, ?, ?)');
        $stmt->bind_param('sss', $Username, $email, $password);
        $this->assertTrue($stmt->execute());
    }
}
