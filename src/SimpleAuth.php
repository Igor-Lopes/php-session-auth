<?php

    class SimpleAuth
    {
        private $conn;

        private $params;

        public function __construct(array $params = [])
        {
            $this->params = array(
              'secure' => false,
              'httponly' => false,
              'db_host' => 'localhost',
              'db_user' => 'root',
              'db_password' => 'root',
              'db_name' => 'sindlife',
              'num_attempts' => 5
              );

            $this->params = array_replace($this->params, $params);
            $connString = 'mysql:host='.$this->params['db_host'].';dbname='.$this->params['db_name'];
            $this->conn = new PDO($connString, $this->params['db_user'], $this->params['db_password']);
        }

        public function createUser($Username, $email, $password)
        {
            if ($this->checkIfEmailExists($email)) {
                $return['success'] = false;
                $return['message'] = 'Email already exists';

                return $return;
            } else {
                $password = hash('sha512', $password);
                $password = password_hash($password, PASSWORD_BCRYPT);
                //Activate account by default.
                $stmt = $this->conn->prepare('INSERT INTO `users` (Username, email, is_active, password) VALUES (:Username, :email, :isActive, :password)');
                $stmt->bindParam(':Username', $Username, PDO::PARAM_STR);
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->bindParam(':isActive', 'Y', PDO::PARAM_STR);
                $stmt->bindParam(':password', $password, PDO::PARAM_STR);
                $stmt->execute();

                $return['success'] = true;
                $return['message'] = 'User successful created';
                $return['username'] = $Username;
                $return['userId'] = $this->conn->lastInsertId();
                $return['email'] = $email;

                return $return;
            }
        }

        public function updatePassword($email, $currentPassword, $newPassword)
        {
            $stmt = $this->conn->prepare('SELECT `user_id`, `Username`, `password`, `is_active` FROM `users` WHERE `email` = :email LIMIT 1');
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_OBJ);
            $currentPassword = hash('sha512', $currentPassword);

            if ($stmt->rowCount() == 0) {
                $return['success'] = false;
                $return['message'] = 'Email not found';

                return $return;
            }
            if (password_verify($currentPassword, $result->password)) {
                $newPassword = hash('sha512', $newPassword);
                $newPassword = password_hash($newPassword, PASSWORD_BCRYPT);

                $stmt = $this->conn->prepare('UPDATE `users` SET `password` = :newPassword WHERE `email` = :email');
                $stmt->bindParam(':newPassword', $newPassword, PDO::PARAM_STR);
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->execute();

                $return['success'] = true;
                $return['message'] = 'Password Updated';

                return $return;
            } else {
                $return['success'] = false;
                $return['message'] = "Current password doesn't match ";

                return $return;
            }
        }

        private function checkIfEmailExists($email)
        {
            $stmt = $this->conn->prepare('SELECT * FROM `users` WHERE `email` = :email');
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();

            if ($stmt->rowCount() == 1) {
                return true;
            } else {
                return false;
            }
        }

        public function login($email, $password)
        {
            $stmt = $this->conn->prepare('SELECT `user_id`, `Username`, `password`, `is_active` FROM `users` WHERE `email` = :email LIMIT 1');
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_OBJ);
            $password = hash('sha512', $password);

            if ($stmt->rowCount() == 0) {
                $return['success'] = false;
                $return['message'] = 'Invalid credentials';

                return $return;
            }

            if ($result->is_active == 'N') {
                $return['success'] = false;
                $return['message'] = 'Account is not Active';

                return $return;
            }

            if ($this->checkBrute($result->user_id, $email)) {
                $return['success'] = false;
                $return['message'] = 'Account is locked';

                return $return;
            }

            if (password_verify($password, $result->password)) {
                $this->deleteAttempts($result->user_id);
                $return['success'] = true;
                $return['message'] = 'Login successful';

                return $return;
            } else {
                $this->addAttempt($result->user_id);
                $return['success'] = false;
                $return['message'] = 'Invalid credentials';

                return $return;
            }
        }

        private function checkBrute($userId, $email)
        {
            $currentDate = strtotime(date('Y-m-d H:i:s'));

            $stmt = $this->conn->prepare('SELECT `expire_time` FROM `attempts` WHERE `user_id` = :userId AND `expire_time` > :currentDate');
            $stmt->bindParam(':userId', $userId, PDO::PARAM_INT);
            $stmt->bindParam(':currentDate', $currentDate, PDO::PARAM_STR);
            $stmt->execute();

            if ($stmt->rowCount() >= $this->params['num_attempts']) {
                return true;
            } else {
                return false;
            }
        }

        private function addAttempt($userId)
        {
            $expireTime = strtotime(date('Y-m-d H:i:s', strtotime('+5 minutes')));
            $ip = $this->getIpAddress();

            $stmt = $this->conn->prepare('INSERT INTO `attempts` (user_id, ip, expire_time) VALUES (:userId, :ip, :expireTime)');
            $stmt->bindParam(':userId', $userId, PDO::PARAM_INT);
            $stmt->bindParam(':ip', $ip, PDO::PARAM_STR);
            $stmt->bindParam(':expireTime', $expireTime, PDO::PARAM_STR);
            $stmt->execute();
        }

        private function deleteAttempts($userId)
        {
            $stmt = $this->conn->prepare('DELETE FROM `attempts` WHERE `user_id` = :userId');
            $stmt->bindParam(':userId', $userId, PDO::PARAM_INT);
            $stmt->execute();
        }

        private function getIpAddress()
        {
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] != '') {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
            } else {
                return $_SERVER['REMOTE_ADDR'];
            }
        }
    }
