<?php

    require './vendor/autoload.php';

    class SimpleAuth{

        private $cookieExp;
        private $sessionName;
        private $secure;
        private $httponly;

        private $serverName;
        private $Username;
        private $password;
        private $dbName;
        private $conn;

        private $host;
        private $port;
        private $SMTPSecure;
        private $SMTPAuth;
        private $from;
        private $pwd;
        private $subject;
        private $wordWrap;

        public function __construct($params){

            $this->cookieExp = $params['cookieExp'];
            $this->sessionName = $params['sessionName'];
            $this->secure = $params['secure'];
            $this->httponly = $params['httponly'];

            $this-> startSecureSession();

            $this->host = $params['host'];
            $this->port = $params['port'];
            $this->SMTPSecure = $params['SMTPSecure'];
            $this->SMTPAuth = $params['SMTPAuth'];
            $this->from = $params['from'];
            $this->pwd = $params['pwd'];
            $this->subject = $params['subject'];
            $this->wordWrap = $params['wordWrap'];
            $this->serverName = $params['serverName'];
            $this->Username = $params['userName'];
            $this->password = $params['password'];
            $this->dbName = $params['dbName'];

            $this->conn = new mysqli($this->serverName, $this->Username, $this->password, $this->dbName);
        }

        public function startSecureSession(){
            if (ini_set('session.use_cookies', 1) === false || ini_set('session.use_only_cookies', 1) === false || ini_set('session.use_trans_sid', 0) === false) {
                exit();
            }
            $cookieParams = session_get_cookie_params();
            session_set_cookie_params($this->cookieExp, $cookieParams['path'], $cookieParams['domain'], $this->secure, $this->httponly);
            session_name($this->sessionName);
            session_start();
            session_regenerate_id(true);
        }

        public function createUser($Username, $email, $password){
            $password = hash('sha512', $password);
            $password = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $this->conn->prepare("INSERT INTO users (Username, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param('sss', $Username, $email, $password);
            $stmt->execute();
            $userId = $this->getUserByEmail($email);
            $this->addRequest($userId, 'A', $email);
        }

        public function getUserByEmail($email){
            $stmt = $this->conn->prepare("SELECT user_id FROM users WHERE email = ? LIMIT 1");
            $stmt->bind_param('s', $email);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($userId);
            $stmt->fetch();

            return $userId;
        }

        public function getUserId($hash){
            $stmt = $this->conn->prepare("SELECT user_id FROM sessions WHERE hash = ? LIMIT 1");
            $stmt->bind_param('s', $hash);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($userId);
            $stmt->fetch();

            return $userId;
        }

        public function getUsername($hash){
            $stmt = $this->conn->prepare("SELECT Username FROM users INNER JOIN sessions on users.user_id = sessions.user_id AND sessions.hash = ?;");
            $stmt->bind_param('s', $hash);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($Username);
            $stmt->fetch();

            return $Username;
        }

        public function getUserEmail($hash){
            $stmt = $this->conn->prepare("SELECT email FROM sessions WHERE hash = ? LIMIT 1");
            $stmt->bind_param('s', $hash);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($email);
            $stmt->fetch();

            return $email;
        }

        private function checkUserEmail($email){
            $stmt = $this->conn->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->bind_param('s', $email);
            $stmt->execute();
            $stmt->store_result();

            return $stmt->num_rows;
        }

        public function login($email, $password){
            $stmt = $this->conn->prepare("SELECT user_id, Username, password, is_active FROM users WHERE email = ? LIMIT 1");
            $stmt->bind_param('s', $email);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($userId, $Username, $dbPassword, $isActive);
            $stmt->fetch();
            $password = hash('sha512', $password);
            $brute = $this->checkBrute($userId, $email) ? 'true' : 'false';

            if ($stmt->num_rows == 1 && $isActive == 'Y' && $brute == 'false' && password_verify($password, $dbPassword)) {
                $userBrowser = $_SERVER['HTTP_USER_AGENT'];
                $userId = preg_replace('/[^0-9]+/', '', $userId);
                $Username = preg_replace("/[^a-zA-Z0-9_\-]+/", '', $Username);
                $_SESSION['Username'] = $Username;
                $_SESSION['loginString'] = hash('sha512', $dbPassword.$userBrowser);

                $ip = $this->getIpAddress();

                $fingerPrint = $this->getRandomKey(16);

                $_SESSION['fp'] = hash('sha256', $fingerPrint);

                $cookieParams = session_get_cookie_params();

                setcookie('fp', $fingerPrint, $cookieParams['lifetime'], $cookieParams['path'], $cookieParams['domain'], false, true);

                session_regenerate_id();

                $this->deleteSessions($_SESSION['loginString'], $userId);
                $this->deleteAttempts($userId);
                $this->addSession($userId, $_SESSION['loginString'], $ip);

                return true;
            } else {
                $this->addAttempt($userId);
                return false;
            }
            return false;
        }

        public function checkBrute($userId, $email){
            $currentDate = strtotime(date('Y-m-d H:i:s'));
            $stmt = $this->conn->prepare("SELECT expire_time FROM attempts WHERE user_id = ? AND expire_time > '$currentDate'");
            $stmt->bind_param('i', $userId);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows >= 5) {
                $this->addRequest($userId, 'R', $email);
                return true;
            }
            return false;
        }

        private function addAttempt($userId){
            $expireTime = strtotime(date('Y-m-d H:i:s', strtotime('+5 minutes')));
            $ip = $this->getIpAddress();
            $this->conn->query("INSERT INTO attempts(user_id, ip, expire_time) VALUES ('$userId', '$ip', '$expireTime')");
        }

        private function deleteAttempts($userId){
            $this->conn->query("DELETE FROM attempts WHERE user_id = '$userId';");
        }

        public function isAuthenticated(){
            if (isset($_SESSION['Username'], $_SESSION['loginString'], $_SESSION['fp'])) {
                $userId = $this->getUserId($_SESSION['loginString']);
                $loginString = $_SESSION['loginString'];
                $Username = $_SESSION['Username'];
                $userBrowser = $_SERVER['HTTP_USER_AGENT'];
                $ip = $this->getIpAddress();

                $stmt = $this->conn->prepare("SELECT password FROM users WHERE user_id = ? LIMIT 1");
                $stmt->bind_param('i', $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows == 1) {
                    $stmt->bind_result($password);
                    $stmt->fetch();
                    $login_check = hash('sha512', $password.$userBrowser);

                    if (hash_equals($login_check, $loginString) && $this->checkDbSession($loginString) && $this->checkFingerPrint()) {
                        return true;
                    }
                }
            }

            return false;
        }

        private function checkDbSession($hash){
            $ip = $this->getIpAddress();
            $currentDate = strtotime(date('Y-m-d H:i:s'));

            $stmt = $this->conn->prepare("SELECT user_id, ip, expire_date FROM sessions WHERE hash = ? LIMIT 1");
            $stmt->bind_param('s', $hash);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($userId, $ipDB, $expireDate);
            $stmt->fetch();

            $expireDate = strtotime($expireDate);

            if ($stmt->num_rows == 1) {
                if ($ip == $ipDB && $currentDate < $expireDate) {
                    return true;
                } else {
                    $this->deleteSessions($hash, $userId);
                }
            }

            return false;
        }

        public function logout(){
            $hash = $_SESSION['loginString'];
            $userId = $this->getUserId($hash);
            $this->deleteSessions($hash, $userId);
            $_SESSION = array();
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
            session_destroy();
        }

        private function addSession($userId, $hash, $ip){
            $sessExpire = date('Y-m-d H:i:s', strtotime('+5 minutes'));
            $insertSession = "INSERT INTO sessions (user_id, hash, expire_date, ip) VALUES ( '$userId','$hash','$sessExpire' , '$ip'); ";
            $this->conn->query($insertSession);
        }

        private function deleteSessions($hash, $userId){
            $currentDate = date('Y-m-d H:i:s');
            $deleteSess = "DELETE FROM sessions WHERE hash = '$hash'; ";
            $deleteSessExp = "DELETE FROM sessions WHERE expire_date < '$currentDate'; ";
            $this->conn->query($deleteSess);
            $this->conn->query($deleteSessExp);
        }

        public function addRequest($userId, $type, $email){
            $reqKey = $this->getRandomKey(10);
            $expireDate = date('Y-m-d H:i:s', strtotime('+120 minutes'));
            $this->deleteRequests($userId, $type);

            if ($this->conn->query("INSERT INTO requests(user_id, request_key, expire_date, type) VALUES ('$userId', '$reqKey', '$expireDate', '$type')")) {
                $this->sendActivation($reqKey, $email);
                return true;
            } else {
                return false;
            }
        }

        public function sendActivation($reqKey, $email){
            $url = 'http://yoururlhere.com/request='.$reqKey;

            $mail = new PHPMailer();
            $mail->IsSMTP();
            $mail->Host = $this->host;
            $mail->Port = 465;
            $mail->SMTPSecure = 'ssl';
            $mail->SMTPAuth = true;
            $mail->Username = $this->from;
            $mail->Password = $this->pwd;
            $mail->setFrom($this->from, 'PHP Simple Auth - Activate your account');
            $mail->addAddress($email);

            $mail->Subject = 'Angular Auth - Activate your account';
            $mail->msgHTML('<html><h1>Please click on the link below
            to activate your account</p>' ."<a href='{$url}'>{$url}</a></html>");
            $mail->WordWrap = 50;

            if ($mail->Send()) {
                return true;
            } else {
                return false;
            }
        }

        public function activateUser($reqKey){
            $stmt = $this->conn->prepare("SELECT user_id, expire_date FROM requests WHERE request_key = ? AND type = 'A'");
            $stmt->bind_param('s', $reqKey);
            if(!$stmt->execute()){
              echo $stmt-> error;
            }
            $stmt->store_result();
            $stmt->bind_result($userId, $expireDate);
            $stmt->fetch();

            $currTime = strtotime(date('Y-m-d H:i:s'));
            $expireTime = strtotime($expireDate);

            if ($stmt->num_rows == 1 && $currTime < $expireTime) {
                $this->setUserActive($userId);
                $this->deleteRequests($userId, 'A');

                return true;
            }

            return false;
        }

        private function setUserActive($userId){
            if ($this->conn->query("UPDATE users SET is_active = 'Y' WHERE user_id = '$userId'")) {
                return true;
            }
            return false;
        }

        public function deleteRequests($userId, $type){
            $this->conn->query("DELETE FROM requests WHERE user_id = '$userId' AND type = '$type'");
        }

        private function getIpAddress(){
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] != '') {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
            } else {
                return $_SERVER['REMOTE_ADDR'];
            }
        }

        /* Function Credit (Adapted): Devshed - Making PHP sessions secure: http://goo.gl/uaDMxp */
        private function getRandomKey($num_bytes){
            if (!is_int($num_bytes) || $num_bytes <= 0) {
                throw new Exception('Argument must be a positive integer.');
            }
            if (function_exists('openssl_random_pseudo_bytes')) {
                $raw_random = openssl_random_pseudo_bytes($num_bytes);
            } elseif (function_exists('mcrypt_create_iv')) {
                $raw_random = mcrypt_create_iv($num_bytes, MCRYPT_DEV_URANDOM);
            } else {
                throw new Exception('OpenSSL or Mcrypt extension required.');
            }

            return bin2hex($raw_random);
        }

        private function checkFingerPrint(){
            if (hash('sha256', $_COOKIE['fp']) == $_SESSION['fp']) {
                return true;
            } else {
                return false;
            }
        }
    }
