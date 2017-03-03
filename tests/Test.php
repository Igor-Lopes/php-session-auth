<?php

require_once __DIR__.'/../src/SimpleAuth.php';

class Test extends PHPUnit_Framework_TestCase
{
    private $simpleAuth;

    public function __construct()
    {
        $params = array(
        'db_host' => '127.0.0.1',
        'db_user' => 'root',
        'db_password' => '',
        'db_name' => 'simple_auth_test',
        );

        $this->simpleAuth = new SimpleAuth($params);
    }

    public function testCreateUser()
    {
        //Successful:
        $this->assertTrue($this->simpleAuth->createUser('Igor', 'test@email.com', 'test')['success']);
        //Failed - Same email:
        $this->assertFalse($this->simpleAuth->createUser('Igor', 'test@email.com', 'test')['success']);
    }

    public function testLogin()
    {
        //Failed: Incorrect Password
        $this->assertFalse($this->simpleAuth->login('test@email.com', 'incorrect')['success']);
        //Failed: Incorrect Email
        $this->assertFalse($this->simpleAuth->login('incorrect@email.com', 'test')['success']);
        //Successful:
        $this->assertTrue($this->simpleAuth->login('test@email.com', 'test')['success']);
    }

    public function testUpdatePassword()
    {
        //Failed: Incorrect Email
        $this->assertFalse($this->simpleAuth->login('incorrect@email.com', 'test', 'new_password')['success']);
        //Failed: Incorrect current Password
        $this->assertFalse($this->simpleAuth->updatePassword('test@email.com', 'incorrect', 'new_password')['success']);
        //Successful:
        $this->assertTrue($this->simpleAuth->updatePassword('test@email.com', 'test', 'new_password')['success']);
        //Test Login with new password:
        $this->assertTrue($this->simpleAuth->login('test@email.com', 'new_password')['success']);
    }

    public function testBruteForce()
    {
        //Lock account:
        for ($i = 0; $i < 6; ++$i) {
            $this->simpleAuth->login('test@email.com', 'incorrect');
        }
        //Correct credentials:
        $this->assertFalse($this->simpleAuth->login('test@email.com', 'new_password')['success']);
    }
    
}
