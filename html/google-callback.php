<?php
// /var/www/schedule.permadomain.com/html/google-callback.php
session_start();
require_once 'includes/functions.php';
require_once 'includes/db.php';

// Configuration
require_once '../config.php';
$client_id = GOOGLE_CLIENT_ID;
$client_secret = GOOGLE_CLIENT_SECRET;
$redirect_uri =  GOOGLE_REDIRECT_URL;

try {
    // Log request details
    debug_log("Google callback: Request URL: " . $_SERVER['REQUEST_URI']);
    debug_log("Google callback: Query string: " . $_SERVER['QUERY_STRING']);
    debug_log("Google callback: GET params: " . json_encode($_GET));

    // Check for authorization code or error
    if (isset($_GET['error'])) {
        debug_log("Google callback: Error received: " . $_GET['error'] . (isset($_GET['error_description']) ? " - " . $_GET['error_description'] : ""));
        throw new Exception('Google authentication failed: ' . $_GET['error'] . (isset($_GET['error_description']) ? " - " . $_GET['error_description'] : ""));
    }
    if (!isset($_GET['code'])) {
        debug_log("Google callback: No authorization code received");
        throw new Exception('Google authentication failed: No authorization code received.');
    }

    // Exchange code for tokens
    $token_url = 'https://oauth2.googleapis.com/token';
    $params = [
        'code' => $_GET['code'],
        'client_id' => $client_id,
        'client_secret' => $client_secret,
        'redirect_uri' => $redirect_uri,
        'grant_type' => 'authorization_code'
    ];

    $ch = curl_init($token_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $response = curl_exec($ch);
    if ($response === false) {
        debug_log("Google callback: cURL error: " . curl_error($ch));
        curl_close($ch);
        throw new Exception('Failed to communicate with Google token endpoint.');
    }
    curl_close($ch);

    $token_data = json_decode($response, true);
    if (isset($token_data['error']) || !isset($token_data['access_token'])) {
        debug_log("Google callback: Token exchange failed: " . json_encode($token_data));
        throw new Exception('Failed to obtain access token: ' . ($token_data['error_description'] ?? 'Unknown error'));
    }

    // Fetch user info
    $userinfo_url = 'https://www.googleapis.com/oauth2/v3/userinfo';
    $ch = curl_init($userinfo_url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $token_data['access_token']]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $userinfo_response = curl_exec($ch);
    if ($userinfo_response === false) {
        debug_log("Google callback: cURL error fetching userinfo: " . curl_error($ch));
        curl_close($ch);
        throw new Exception('Failed to fetch user information.');
    }
    curl_close($ch);

    $userinfo = json_decode($userinfo_response, true);
    if (!isset($userinfo['sub'])) {
        debug_log("Google callback: Invalid userinfo response: " . json_encode($userinfo));
        throw new Exception('Failed to retrieve user information.');
    }

    // Check if user exists or create new user
    $stmt = $pdo->prepare('SELECT id, is_admin FROM users WHERE google_id = ?');
    $stmt->execute([$userinfo['sub']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Create new user
        $stmt = $pdo->prepare('INSERT INTO users (google_id, username, email, is_admin, password) VALUES (?, ?, ?, 0, NULL)');
        $stmt->execute([
            $userinfo['sub'],
            $userinfo['name'] ?? 'Google User ' . substr($userinfo['sub'], 0, 8),
            $userinfo['email']
        ]);
        $user_id = $pdo->lastInsertId();
        $is_admin = 0;
        debug_log("Google callback: Created new user: google_id={$userinfo['sub']}, email={$userinfo['email']}");
    } else {
        $user_id = $user['id'];
        $is_admin = $user['is_admin'];
        debug_log("Google callback: Existing user found: google_id={$userinfo['sub']}, user_id={$user_id}");
    }

    // Set session
    $_SESSION['user_id'] = $user_id;
    $_SESSION['is_admin'] = $is_admin;
    unset($_SESSION['read_only'], $_SESSION['read_only_schedule_id'], $_SESSION['read_only_schedule_name']);
    $_SESSION['login_attempts'] = 0;

    debug_log("Google login successful: user_id={$user_id}, email={$userinfo['email']}, is_admin=" . ($is_admin ? 'true' : 'false'));
    header('Location: /index.php');
    exit;

} catch (Exception $e) {
    debug_log("Google callback error: " . $e->getMessage());
    $_SESSION['error'] = 'Google authentication failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    header('Location: /login.php');
    exit;
}
?>
