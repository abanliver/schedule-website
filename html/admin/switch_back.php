<?php
// /var/www/schedule.permadomain.com/html/admin/switch_back.php
session_start();
require '../includes/db.php';
require '../includes/functions.php';

ini_set('display_errors', 0);
error_reporting(E_ALL);

if (!isset($_SESSION['drop_in_user']) || !$_SESSION['drop_in_user'] || !isset($_SESSION['admin_session'])) {
    debug_log("Invalid switch back attempt", '/tmp/switch_back_debug.log');
    $_SESSION['error'] = 'Invalid request.';
    header('Location: /login.php');
    exit;
}

try {
    $adminId = $_SESSION['admin_session']['user_id'];
    $targetUserId = $_SESSION['user_id'];

    // Log the action
#    $stmt = $pdo->prepare('INSERT INTO audit_log (admin_id, action, target_user_id) VALUES (?, ?, ?)');
#    $stmt->execute([$adminId, 'switch_back', $targetUserId]);
    debug_log("Logged action: admin_id=$adminId, action=switch_back, target_user_id=$targetUserId", '/tmp/switch_back_debug.log');

    // Restore admin session
    $_SESSION['user_id'] = $_SESSION['admin_session']['user_id'];
    $_SESSION['is_admin'] = $_SESSION['admin_session']['is_admin'];
    $_SESSION['csrf_token'] = $_SESSION['admin_session']['csrf_token'];
    unset($_SESSION['drop_in_user'], $_SESSION['admin_session'], $_SESSION['original_admin_id'], $_SESSION['username'], $_SESSION['email']);

    debug_log("Restored admin session: admin_id=$adminId", '/tmp/switch_back_debug.log');
    $_SESSION['success'] = 'Switched back to admin account.';
    header('Location: /admin/index.php');
    exit;
} catch (PDOException $e) {
    debug_log("Database error: " . $e->getMessage(), '/tmp/switch_back_debug.log');
    $_SESSION['error'] = 'Failed to switch back. Please log in again.';
    header('Location: /login.php');
    exit;
}
?>
