<?php

require_once __DIR__ . '/../src/SimpleAuth.php';

class Test extends PHPUnit_Framework_TestCase{

    private $simpleAuth;

    public function __construct(){

      $params = array(
        'db_host' => '127.0.0.1',
        'db_user' => 'root',
        'db_password' => '',
        'db_name' => 'simple_auth_test',
        );

      $this->simpleAuth = new SimpleAuth($params);

    }
    public function testDbCon(){
        $this->assertTrue($this->simpleAuth->createUser('Igor', 'test@email.com', 'test')['success']);
    }
}
