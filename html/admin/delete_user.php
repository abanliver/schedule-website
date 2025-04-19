<?php
// /var/www/schedule.permadomain.com/html/admin/delete_user.php
session_start();
require '../includes/db.php';
require '../includes/functions.php';

// Disable display_errors in production
ini_set('display_errors', 1);
error_reporting(E_ALL);


$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];
$isAdmin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'];

if (!$userId || $isReadOnly || !$isAdmin) {
    debug_log("Access denied: user_id=" . ($userId ?: 'null') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false') . ", is_admin=" . ($isAdmin ? 'true' : 'false'));
    $_SESSION['error'] = 'Access denied. Admins only.';
    header('Location: /schedule.php' . ($isReadOnly && isset($_SESSION['read_only_schedule_id']) ? '?schedule_id=' . $_SESSION['read_only_schedule_id'] : ''));
    exit;
}

try {
    // Validate admin user
    $stmt = $pdo->prepare('SELECT username FROM users WHERE id = ? AND is_admin = 1');
    $stmt->execute([$userId]);
    $adminUser = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$adminUser) {
        debug_log("Admin user not found: user_id=$userId");
        session_destroy();
        $_SESSION = [];
        $_SESSION['error'] = 'Admin access denied.';
        header('Location: /login.php');
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_id'])) {
        // Validate CSRF token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            debug_log("CSRF validation failed: admin_user_id=$userId");
            $_SESSION['error'] = 'Invalid request. Please try again.';
            header('Location: /admin/index.php');
            exit;
        }

        $deleteUserId = (int)$_POST['user_id'];

        // Prevent self-deletion
        if ($deleteUserId === $userId) {
            debug_log("Self-deletion attempted: admin_user_id=$userId, delete_user_id=$deleteUserId");
            $_SESSION['error'] = 'You cannot delete your own account.';
            header('Location: /admin/index.php');
            exit;
        }

        // Verify user exists
        $stmt = $pdo->prepare('SELECT id FROM users WHERE id = ?');
        $stmt->execute([$deleteUserId]);
        if (!$stmt->fetch()) {
            debug_log("User not found: admin_user_id=$userId, delete_user_id=$deleteUserId");
            $_SESSION['error'] = 'User not found.';
            header('Location: /admin/index.php');
            exit;
        }

        // Delete related data (appointments, schedules, user)
        $pdo->beginTransaction();
        $stmt = $pdo->prepare('DELETE FROM appointments WHERE user_id = ?');
        $stmt->execute([$deleteUserId]);
        debug_log("Deleted appointments for delete_user_id=$deleteUserId");

        $stmt = $pdo->prepare('DELETE FROM schedules WHERE user_id = ?');
        $stmt->execute([$deleteUserId]);
        debug_log("Deleted schedules for delete_user_id=$deleteUserId");

        $stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
        $stmt->execute([$deleteUserId]);
        debug_log("Deleted user: admin_user_id=$userId, delete_user_id=$deleteUserId");

        $pdo->commit();
        $_SESSION['success'] = 'User and associated data deleted successfully!';
        header('Location: /admin/index.php');
        exit;
    } else {
        debug_log("Invalid request: no user_id provided, admin_user_id=$userId");
        $_SESSION['error'] = 'Invalid request.';
        header('Location: /admin/index.php');
        exit;
    }
} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    debug_log("Deletion error: " . $e->getMessage());
    $_SESSION['error'] = 'Error deleting user. Please try again.';
    header('Location: /admin/index.php');
    exit;
}
?>
