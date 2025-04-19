<?php
// /var/www/schedule.permadomain.com/html/includes/db.php

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Load configuration
$configFile = __DIR__ . '/../../config.php';
if (!file_exists($configFile)) {
    error_log("Configuration file not found: $configFile");
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $_SESSION['error'] = 'System configuration error. Please try again later.';
    header('Location: /login.php');
    exit;
}
require_once $configFile;

try {
    error_log("Attempting database connection: host=" . DB_HOST . ", dbname=" . DB_NAME);
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    error_log("Database connection established successfully");
} catch (PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $_SESSION['error'] = 'Database connection failed. Please try again later.';
    header('Location: /login.php');
    exit;
}

// Include functions.php after $pdo is initialized
require_once __DIR__ . '/functions.php';

// Log successful connection using debug_log() now that functions.php is safe
debug_log("Database connection established successfully");
