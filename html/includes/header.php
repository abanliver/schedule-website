<?php
// /var/www/schedule.permadomain.com/html/includes/header.php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require __DIR__ . '/functions.php';
require __DIR__ . '/db.php';

// Debug session
debug_log("Header included: user_id=" . (isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 'null'));

// Fetch settings
try {
    if (!function_exists('get_setting')) {
        debug_log("Error: get_setting() function is undefined in includes/functions.php");
        throw new Exception("System configuration error: settings unavailable.");
    }
    $settings = get_setting();
} catch (Exception $e) {
    debug_log("Failed to fetch settings: " . $e->getMessage());
    $settings = [
        'session_timeout' => 1800,
        'session_regeneration_interval' => 600,
        'session_creation_max_attempts' => 5,
        'session_creation_lockout_time' => 900
    ]; // Fallback
}

// Generate a nonce for inline scripts
try {
    $nonce = base64_encode(random_bytes(16));
} catch (Exception $e) {
    debug_log("Failed to generate nonce: " . $e->getMessage());
    $nonce = base64_encode(uniqid());
}

// Content Security Policy (CSP)
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://accounts.google.com 'nonce-$nonce'; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net data:; connect-src 'self'; frame-src https://accounts.google.com;");

// Session timeout, skipped if stay_logged_in is true
$timeout = (int)($settings['session_timeout'] ?? 1800);
if (!isset($_SESSION['stay_logged_in']) || !$_SESSION['stay_logged_in']) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $timeout)) {
        debug_log("Session timed out: user_id=" . (isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 'null'));
        session_destroy();
        $_SESSION = [];
        $_SESSION['error'] = 'Your session has expired. Please log in again.';
        header('Location: /login.php');
        exit;
    }
}
$_SESSION['last_activity'] = time();

// Session regeneration
$regeneration_interval = (int)($settings['session_regeneration_interval'] ?? 600);
if (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
} elseif (time() - $_SESSION['created'] > $regeneration_interval) {
    // Preserve CSRF token
    $old_csrf_token = $_SESSION['csrf_token'] ?? null;
    session_regenerate_id(true);
    $_SESSION['created'] = time();
    if ($old_csrf_token) {
        $_SESSION['csrf_token'] = $old_csrf_token;
    }
    debug_log("Session ID regenerated: user_id=" . (isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 'null') . ", preserved_csrf_token=" . substr($_SESSION['csrf_token'] ?? 'none', 0, 8) . "...");
}

// Rate-limiting for session creation (only for non-logged-in users)
$maxSessions = (int)($settings['session_creation_max_attempts'] ?? 5);
$lockoutTime = (int)($settings['session_creation_lockout_time'] ?? 900);
if (!isset($_SESSION['session_attempts'])) {
    $_SESSION['session_attempts'] = 0;
    $_SESSION['last_session_attempt'] = time();
}
// Reset session attempts if lockout expired
if ($_SESSION['session_attempts'] >= $maxSessions && (time() - $_SESSION['last_session_attempt']) >= $lockoutTime) {
    $_SESSION['session_attempts'] = 0;
    $_SESSION['last_session_attempt'] = time();
    debug_log("Reset session attempts after lockout expiration");
}
// Apply rate-limiting only for non-logged-in users and specific pages
if (!isset($_SESSION['user_id']) && !isset($_SESSION['read_only']) && in_array(basename($_SERVER['SCRIPT_NAME']), ['login.php', 'register.php'])) {
    if ($_SESSION['session_attempts'] >= $maxSessions && (time() - $_SESSION['last_session_attempt']) < $lockoutTime) {
        debug_log("Session creation rate limit exceeded: attempts={$_SESSION['session_attempts']}");
        $_SESSION['error'] = 'Too many session creation attempts. Please try again in ' . ceil(($lockoutTime - (time() - $_SESSION['last_session_attempt'])) / 60) . ' minutes.';
        if (basename($_SERVER['SCRIPT_NAME']) !== 'login.php') {
            header('Location: /login.php');
            exit;
        }
    } else {
        $_SESSION['session_attempts']++;
        $_SESSION['last_session_attempt'] = time();
        debug_log("Incremented session attempts: attempts={$_SESSION['session_attempts']}");
    }
}

// Generate CSRF token if not set
if (!isset($_SESSION['csrf_token'])) {
    try {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        debug_log("CSRF token generated: token=" . substr($_SESSION['csrf_token'], 0, 8) . "...");
    } catch (Exception $e) {
        debug_log("Failed to generate CSRF token: " . $e->getMessage());
        $_SESSION['csrf_token'] = bin2hex(uniqid());
    }
}

// Validate user/admin status (skip for login.php)
$isLoggedIn = false;
$isAdmin = false;
if (isset($_SESSION['user_id']) && basename($_SERVER['SCRIPT_NAME']) !== 'login.php') {
    try {
        $stmt = $pdo->prepare('SELECT id, is_admin FROM users WHERE id = ?');
        $stmt->execute([(int)$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            $isLoggedIn = true;
            $isAdmin = $user['is_admin'];
            $_SESSION['is_admin'] = $isAdmin;
        } else {
            debug_log("Invalid user_id in session: user_id=" . (int)$_SESSION['user_id']);
            session_destroy();
            $_SESSION = [];
            $_SESSION['error'] = 'Invalid session. Please log in again.';
            header('Location: /login.php');
            exit;
        }
    } catch (PDOException $e) {
        debug_log("Database error during user validation: " . $e->getMessage());
        $_SESSION['error'] = 'Unable to validate session. Please try again.';
        header('Location: /login.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Appointment Tracker</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
          rel="stylesheet" 
          integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" 
          crossorigin="anonymous">
    <link rel="stylesheet" href="/css/style.css?v=<?php echo filemtime($_SERVER['DOCUMENT_ROOT'] . '/css/style.css'); ?>">
</head>
<body>

<?php if (isset($_SESSION['drop_in_user']) && $_SESSION['drop_in_user']): ?>
    <div class="alert alert-warning text-center mb-0">
        Logged in as <?php echo htmlspecialchars($_SESSION['username'] ?? 'User ID ' . $_SESSION['user_id'], ENT_QUOTES, 'UTF-8'); ?>. 
        <a href="/admin/switch_back.php" class="btn btn-danger btn-sm">Switch Back to Admin</a>
    </div>
<?php endif; ?>

<nav class="navbar navbar-expand-lg navbar-light bg-light shadow-sm">
    <div class="container-fluid">
        <a class="navbar-brand" href="/">Appointment Tracker</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <?php if ($isLoggedIn || isset($_SESSION['read_only'])): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="/index.php">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/schedule.php">Schedule</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/calendar.php">Calendar</a>
                    </li>
                    <?php if ($isLoggedIn): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="/report.php">Reports</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/profile.php">Profile</a>
                        </li>
                        <?php if ($isAdmin): ?>
                            <li class="nav-item">
                                <a class="nav-link" href="/admin/index.php">Admin</a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/admin/settings.php">Settings</a>
                            </li>
                        <?php endif; ?>
                        <li class="nav-item">
                            <form method="POST" action="/logout.php" class="d-inline" onsubmit="return confirm('Are you sure you want to log out?');">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <button type="submit" name="logout" class="nav-link btn btn-link">Logout</button>
                            </form>
                        </li>
                    <?php endif; ?>
                <?php else: ?>
                    <li class="nav-item">
                        <a class="nav-link" href="/login.php">Login</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/register.php">Register</a>
                    </li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>
<div class="container mt-4">
    <?php if (isset($_SESSION['success'])): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <?php echo htmlspecialchars($_SESSION['success']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
        <?php unset($_SESSION['success']); ?>
    <?php endif; ?>
    <?php if (isset($_SESSION['error'])): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <?php echo htmlspecialchars($_SESSION['error']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
        <?php unset($_SESSION['error']); ?>
    <?php endif; ?>
</div>

<?php if ($isLoggedIn && (!isset($_SESSION['stay_logged_in']) || !$_SESSION['stay_logged_in'])): ?>
<script nonce="<?php echo htmlspecialchars($nonce); ?>">
    function checkSession() {
        fetch('/check_session.php', {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            if (!data.active) {
                window.location.href = '/login.php';
            }
        })
        .catch(error => {
            console.error('Session check failed:', error);
        });
    }
    // Check every 30 seconds
    setInterval(checkSession, 30000);
    // Initial check after 5 seconds
    setTimeout(checkSession, 5000);
</script>
<?php endif; ?>
