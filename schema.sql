DROP DATABASE IF EXISTS user_system;
CREATE DATABASE user_system;
USE user_system;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_admin TINYINT(1) DEFAULT 0,
    read_only_token VARCHAR(255) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE appointments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    scheduled_date DATE NOT NULL,
    frequency ENUM('weekly', 'monthly', 'yearly', 'one-off') NOT NULL,
    status ENUM('scheduled', 'attended', 'missed', 'rescheduled') DEFAULT 'scheduled',
    parent_id INT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES appointments(id) ON DELETE SET NULL
);
UPDATE users 
SET role = 'admin' 
WHERE id = 1;
