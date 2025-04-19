<?php
// /var/www/schedule.permadomain.com/html/check_session.php
session_start();
require __DIR__ . '/includes/functions.php';
require __DIR__ . '/includes/db.php';

// Fetch settings
$settings = get_setting();

// Check if session is active
$timeout = (int)$settings['session_timeout'];
$isActive = false;

if (isset($_SESSION['user_id']) && isset($_SESSION['last_activity'])) {
    if (!isset($_SESSION['stay_logged_in']) || !$_SESSION['stay_logged_in']) {
        if (time() - $_SESSION['last_activity'] <= $timeout) {
            $isActive = true;
        } else {
            debug_log("Session timeout detected in check_session: user_id=" . (int)$_SESSION['user_id']);
            session_destroy();
            $_SESSION = [];
            $_SESSION['error'] = 'Your session has expired. Please log in again.';
        }
    } else {
        $isActive = true; // Stay logged in is active
    }
}

header('Content-Type: application/json');
echo json_encode(['active' => $isActive]);
exit;
