-- php-session-auth
-- https://github.com/Nucleus-Inc/php-session-auth
-- Copyright (c) Nucleus Inc (https://www.nucleus.eti.br)
-- Licensed under the MIT License (https://opensource.org/licenses/MIT)

CREATE TABLE `users` (
     `user_id` INT AUTO_INCREMENT PRIMARY KEY,
     `username` VARCHAR(255) NOT NULL,
     `email` VARCHAR(255) NOT NULL UNIQUE,
     `is_active` ENUM ('Y','N') DEFAULT 'N',
     `password` CHAR(128) NOT NULL
);
CREATE TABLE attempts (
    `attempt_id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `ip` VARCHAR(39) NOT NULL,
    `expire_time` VARCHAR(30) NOT NULL,
    FOREIGN KEY(`user_id`) REFERENCES users(`user_id`) ON DELETE CASCADE
);
CREATE TABLE sessions (
  `session_id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `hash` VARCHAR(255) NOT NULL,
  `expire_date` DATETIME,
  `ip` VARCHAR(39) NOT NULL,
  FOREIGN KEY(`user_id`) REFERENCES users(`user_id`) ON DELETE CASCADE
);
CREATE TABLE requests (
  `request_id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `request_key` VARCHAR(20) NOT NULL,
  `expire_date` DATETIME NOT NULL,
  `type` enum ('A','R') NOT NULL,
  FOREIGN KEY(`user_id`) REFERENCES users(`user_id`) ON DELETE CASCADE
);
