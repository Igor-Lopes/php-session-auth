<?php
class Test extends PHPUnit_Framework_TestCase{

    private $params;
    private $conn;

    public function __construct(){

      $this->params = array(
        'db_host' => '127.0.0.1',
        'db_user' => 'root',
        'db_password' => '',
        'db_name' => 'simple_auth_test',
        );

      $connString = 'mysql:host='.$this->params['db_host'].';dbname='.$this->params['db_name'];
      
      $this->conn = new PDO($connString, $this->params['db_user'], $this->params['db_password']);
    }
    public function testDbCon(){
        $Username = 'Admin';
        $password = 'admin';
        $email = 'admin@email.com';
        $password = hash('sha512', $password);
        $password = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->conn->prepare('INSERT INTO `users` (Username, email, password) VALUES (:Username, :email, :password)');
        $stmt->bindParam(':Username', $Username, PDO::PARAM_STR);
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->bindParam(':password', $password, PDO::PARAM_STR);
        $this->assertTrue($stmt->execute());
    }
}
