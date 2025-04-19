<?php
// /var/www/schedule.permadomain.com/html/admin/login_as_user.php
session_start();
require '../includes/db.php';
require '../includes/functions.php';

ini_set('display_errors', 0);
error_reporting(E_ALL);

// Check admin access
$adminId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$isAdmin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'];
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];
if (!$adminId || !$isAdmin || $isReadOnly) {
    debug_log("Access denied: admin_id=" . ($adminId ?: 'null') . ", is_admin=" . ($isAdmin ? 'true' : 'false') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false'), '/tmp/login_as_user_debug.log');
    $_SESSION['error'] = 'Access denied. Admins only.';
    header('Location: /login.php');
    exit;
}

$targetUserId = isset($_GET['user_id']) ? (int)$_GET['user_id'] : null;
if (!$targetUserId) {
    debug_log("No target user ID provided: admin_id=$adminId", '/tmp/login_as_user_debug.log');
    $_SESSION['error'] = 'Invalid user ID.';
    header('Location: /admin/index.php');
    exit;
}

try {
    // Verify target user exists
    $stmt = $pdo->prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?');
    $stmt->execute([$targetUserId]);
    $targetUser = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$targetUser) {
        debug_log("Target user not found: target_user_id=$targetUserId, admin_id=$adminId", '/tmp/login_as_user_debug.log');
        $_SESSION['error'] = 'User not found.';
        header('Location: /admin/index.php');
        exit;
    }

    // Prevent admins from dropping into other admins
    if ($targetUser['is_admin']) {
        debug_log("Cannot drop into another admin: target_user_id=$targetUserId, admin_id=$adminId", '/tmp/login_as_user_debug.log');
        $_SESSION['error'] = 'Cannot drop into another admin account.';
        header('Location: /admin/index.php');
        exit;
    }

    // Log the action
#    $stmt = $pdo->prepare('INSERT INTO audit_log (admin_id, action, target_user_id) VALUES (?, ?, ?)');
#    $stmt->execute([$adminId, 'drop_in_user', $targetUserId]);
    debug_log("Logged action: admin_id=$adminId, action=drop_in_user, target_user_id=$targetUserId", '/tmp/login_as_user_debug.log');

    // Store admin session
    $_SESSION['admin_session'] = [
        'user_id' => $_SESSION['user_id'],
        'is_admin' => $_SESSION['is_admin'],
        'csrf_token' => $_SESSION['csrf_token'],
        'read_only' => $_SESSION['read_only']
    ];

    // Switch to target user session
    $_SESSION['user_id'] = $targetUser['id'];
    $_SESSION['is_admin'] = $targetUser['is_admin'];
    $_SESSION['username'] = $targetUser['username'];
    $_SESSION['email'] = $targetUser['email'];
    $_SESSION['read_only'] = false;
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $_SESSION['drop_in_user'] = true;
    $_SESSION['original_admin_id'] = $adminId;

    debug_log("Switched to user: admin_id=$adminId, target_user_id=$targetUserId, username=" . $targetUser['username'], '/tmp/login_as_user_debug.log');
    header('Location: /index.php');
    exit;
} catch (PDOException $e) {
    debug_log("Database error: " . $e->getMessage(), '/tmp/login_as_user_debug.log');
    $_SESSION['error'] = 'Failed to drop into user account. Please try again.';
    header('Location: /admin/index.php');
    exit;
} catch (Exception $e) {
    debug_log("Unexpected error: " . $e->getMessage(), '/tmp/login_as_user_debug.log');
    $_SESSION['error'] = 'Unexpected error. Please try again.';
    header('Location: /admin/index.php');
    exit;
}
?>
