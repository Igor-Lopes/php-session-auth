-- php-simple-auth
-- https://github.com/igor-lopes/php-simple-auth
-- Copyright (c) Nucleus Inc (https://www.nucleus.eti.br)
-- Licensed under the MIT License (https://opensource.org/licenses/MIT)

CREATE TABLE IF NOT EXISTS `users` (
     `user_id` INT AUTO_INCREMENT PRIMARY KEY,
     `username` VARCHAR(255) NOT NULL,
     `email` VARCHAR(255) NOT NULL UNIQUE,
     `is_active` ENUM ('Y','N') DEFAULT 'N',
     `password` CHAR(128) NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
    `attempt_id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `ip` VARCHAR(39) NOT NULL,
    `expire_time` VARCHAR(30) NOT NULL,
    FOREIGN KEY(`user_id`) REFERENCES users(`user_id`) ON DELETE CASCADE
);
