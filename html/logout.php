<?php
// /var/www/schedule.permadomain.com/html/logout.php
session_start();
require 'includes/functions.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Basic rate-limiting for POST requests
$maxAttempts = 10;
$lockoutTime = 600; // 10 minutes
if (!isset($_SESSION['logout_attempts'])) {
    $_SESSION['logout_attempts'] = 0;
    $_SESSION['last_logout_attempt'] = time();
}

if ($_SESSION['logout_attempts'] >= $maxAttempts && (time() - $_SESSION['last_logout_attempt']) < $lockoutTime) {
    debug_log("Rate limit exceeded: attempts={$_SESSION['logout_attempts']}, user_id=" . (isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 'null'));
    $_SESSION['error'] = 'Too many logout attempts. Please try again in ' . ceil(($lockoutTime - (time() - $_SESSION['last_logout_attempt'])) / 60) . ' minutes.';
    header('Location: /login.php');
    exit;
}

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];

// Restrict to POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    debug_log("Invalid request method: method={$_SERVER['REQUEST_METHOD']}, user_id=" . ($userId ?: 'null') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false'));
    $_SESSION['error'] = 'Invalid request method. Please use the logout form.';
    header('Location: /login.php');
    exit;
}

// Validate CSRF token
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    debug_log("CSRF validation failed: user_id=" . ($userId ?: 'null') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false'));
    $_SESSION['error'] = 'Invalid request. Please try again.';
    $_SESSION['logout_attempts']++;
    $_SESSION['last_logout_attempt'] = time();
    header('Location: /login.php');
    exit;
}

debug_log("Logout successful: user_id=" . ($userId ?: 'null') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false') . ", session_data_cleared=true");
session_destroy();
$_SESSION = []; // Clear all session data
$_SESSION['success'] = 'You have been logged out successfully.';
header('Location: /login.php');
exit;
?>
