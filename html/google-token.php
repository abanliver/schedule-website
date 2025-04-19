<?php
// /var/www/schedule.permadomain.com/html/google-token.php
session_start();
require_once 'includes/functions.php';
require_once 'includes/db.php';

// Set JSON content type
header('Content-Type: application/json');

try {
    // Validate CSRF token
    if (!isset($_SERVER['HTTP_X_CSRF_TOKEN']) || $_SERVER['HTTP_X_CSRF_TOKEN'] !== $_SESSION['csrf_token']) {
        debug_log("Google token: CSRF validation failed, received token: " . ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? 'none'));
        echo json_encode(['success' => false, 'error' => 'Invalid CSRF token']);
        exit;
    }

    // Check for access token
    $input = json_decode(file_get_contents('php://input'), true);
    if (!isset($input['access_token'])) {
        debug_log("Google token: No access token provided");
        echo json_encode(['success' => false, 'error' => 'No access token provided']);
        exit;
    }

    // Fetch user info
    $userinfo_url = 'https://www.googleapis.com/oauth2/v3/userinfo';
    $ch = curl_init($userinfo_url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $input['access_token']]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $userinfo_response = curl_exec($ch);
    if ($userinfo_response === false) {
        debug_log("Google token: cURL error fetching userinfo: " . curl_error($ch));
        curl_close($ch);
        throw new Exception('Failed to fetch user information');
    }
    curl_close($ch);

    $userinfo = json_decode($userinfo_response, true);
    if (!isset($userinfo['sub'])) {
        debug_log("Google token: Invalid userinfo response: " . json_encode($userinfo));
        throw new Exception('Failed to retrieve user information');
    }

    // Sanitize username: replace spaces with underscores, keep alphanumeric and underscores
    $raw_username = $userinfo['name'] ?? 'GoogleUser_' . substr($userinfo['sub'], 0, 8);
    $sanitized_username = preg_replace('/[^a-zA-Z0-9_]/', '_', $raw_username);
    $sanitized_username = preg_replace('/_+/', '_', $sanitized_username); // Replace multiple underscores with single
    $sanitized_username = substr($sanitized_username, 0, 255); // Truncate to 255 characters

    // Check if user exists or create new user
    $stmt = $pdo->prepare('SELECT id, is_admin FROM users WHERE google_id = ?');
    $stmt->execute([$userinfo['sub']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Create new user
        $stmt = $pdo->prepare('INSERT INTO users (google_id, username, email, is_admin, password) VALUES (?, ?, ?, 0, NULL)');
        $stmt->execute([
            $userinfo['sub'],
            $sanitized_username,
            $userinfo['email']
        ]);
        $user_id = $pdo->lastInsertId();
        $is_admin = 0;
        debug_log("Google token: Created new user: google_id={$userinfo['sub']}, username={$sanitized_username}, email={$userinfo['email']}");
    } else {
        $user_id = $user['id'];
        $is_admin = $user['is_admin'];
        debug_log("Google token: Existing user found: google_id={$userinfo['sub']}, user_id={$user_id}, username={$user['username']}");
    }

    // Set session
    $_SESSION['user_id'] = $user_id;
    $_SESSION['is_admin'] = $is_admin;
    unset($_SESSION['read_only'], $_SESSION['read_only_schedule_id'], $_SESSION['read_only_schedule_name']);
    $_SESSION['login_attempts'] = 0;

    debug_log("Google login successful: user_id={$user_id}, username={$sanitized_username}, email={$userinfo['email']}, is_admin=" . ($is_admin ? 'true' : 'false'));
    echo json_encode(['success' => true]);
    exit;

} catch (Exception $e) {
    debug_log("Google token error: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    exit;
}
?>
