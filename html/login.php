<?php
// /var/www/schedule.permadomain.com/html/login.php
session_start();
require_once 'includes/db.php'; // Moved before functions.php
require_once 'includes/functions.php';

// Enable error display temporarily for debugging
ini_set('display_errors', 0); // Set to 0 in production
error_reporting(E_ALL);

// Debug session
debug_log("Login page accessed: user_id=" . (isset($_SESSION['user_id']) ? $_SESSION['user_id'] : 'not set'));

// Check if already logged in
if (isset($_SESSION['user_id'])) {
    debug_log("User already logged in: user_id={$_SESSION['user_id']}, redirecting to index.php");
    header('Location: /index.php');
    exit;
}

try {
    // Fetch settings
    if (!function_exists('get_setting')) {
        debug_log("Error: get_setting() function is undefined in includes/functions.php");
        throw new Exception("System configuration error: settings unavailable.");
    }
    $settings = get_setting();
} catch (Exception $e) {
    debug_log("Failed to fetch settings: " . $e->getMessage());
    $_SESSION['error'] = 'System error: unable to load settings. Please try again later.';
    $settings = [
        'login_max_attempts' => 5,
        'login_lockout_time' => 900,
        'allow_stay_logged_in' => '1'
    ]; // Fallback
}

// Initialize rate-limiting
$maxAttempts = (int)($settings['login_max_attempts'] ?? 5);
$lockoutTime = (int)($settings['login_lockout_time'] ?? 900);
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt'] = time();
    debug_log("Initialized login attempts");
}

// Reset login attempts if lockout expired
if ($_SESSION['login_attempts'] >= $maxAttempts && (time() - $_SESSION['last_attempt']) >= $lockoutTime) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt'] = time();
    debug_log("Reset login attempts after lockout expiration");
}

// Check for lockout
if ($_SESSION['login_attempts'] >= $maxAttempts) {
    $_SESSION['error'] = 'Too many login attempts. Please try again in ' . ceil(($lockoutTime - (time() - $_SESSION['last_attempt'])) / 60) . ' minutes.';
} else {
    // Verify PDO is initialized
    if (!isset($pdo)) {
        debug_log("Error: PDO object not initialized in db.php");
        $_SESSION['error'] = 'System error: database unavailable. Please try again later.';
    } else {
        // Process POST request if not locked out
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_SESSION['error'])) {
            // Validate CSRF token
            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                debug_log("CSRF validation failed, POST token: " . ($_POST['csrf_token'] ?? 'none') . ", Session token: " . ($_SESSION['csrf_token'] ?? 'none'));
                $_SESSION['error'] = 'Invalid request. Please try again.';
                $_SESSION['login_attempts']++;
                $_SESSION['last_attempt'] = time();
            } else {
                $username = trim($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                $token = trim($_POST['token'] ?? '');
                $stayLoggedIn = isset($_POST['stay_logged_in']) && $_POST['stay_logged_in'] === '1' && ($settings['allow_stay_logged_in'] ?? '0') === '1';

                try {
                    if ($username && $password) {
                        // Username/password login
                        if (strlen($username) < 1 || strlen($username) > 255) {
                            debug_log("User login failed: invalid username length, username=" . substr($username, 0, 50));
                            $_SESSION['error'] = 'Username must be between 1 and 255 characters.';
                            $_SESSION['login_attempts']++;
                            $_SESSION['last_attempt'] = time();
                        } else {
                            $stmt = $pdo->prepare('SELECT id, username, password, is_admin FROM users WHERE username = ?');
                            $stmt->execute([$username]);
                            $user = $stmt->fetch(PDO::FETCH_ASSOC);

                            if ($user && password_verify($password, $user['password'])) {
                                $_SESSION['user_id'] = $user['id'];
                                $_SESSION['username'] = $user['username'];
                                $_SESSION['is_admin'] = $user['is_admin'];
                                $_SESSION['stay_logged_in'] = $stayLoggedIn;
                                unset($_SESSION['read_only'], $_SESSION['read_only_schedule_id'], $_SESSION['read_only_schedule_name']);
                                $_SESSION['login_attempts'] = 0;
                                debug_log("User login successful: user_id={$user['id']}, username=" . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . ", is_admin=" . ($user['is_admin'] ? 'true' : 'false') . ", stay_logged_in=" . ($stayLoggedIn ? 'true' : 'false'));
                                header('Location: /index.php');
                                exit;
                            } else {
                                debug_log("User login failed: username=" . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . ", invalid credentials");
                                $_SESSION['error'] = 'Incorrect username or password.';
                                $_SESSION['login_attempts']++;
                                $_SESSION['last_attempt'] = time();
                            }
                        }
                    } elseif ($token) {
                        // Read-only token login
                        if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
                            debug_log("Read-only login failed: invalid token format, token=" . substr($token, 0, 32));
                            $_SESSION['error'] = 'Invalid read-only token format. It must be a 32-character hexadecimal string.';
                            $_SESSION['login_attempts']++;
                            $_SESSION['last_attempt'] = time();
                        } else {
                            $stmt = $pdo->prepare('SELECT s.id, s.name, u.id as user_id FROM schedules s JOIN users u ON s.user_id = u.id WHERE s.read_only_token = ?');
                            $stmt->execute([$token]);
                            $schedule = $stmt->fetch(PDO::FETCH_ASSOC);

                            if ($schedule) {
                                $_SESSION['read_only'] = true;
                                $_SESSION['read_only_schedule_id'] = $schedule['id'];
                                $_SESSION['read_only_schedule_name'] = $schedule['name'];
                                unset($_SESSION['user_id'], $_SESSION['is_admin']);
                                $_SESSION['login_attempts'] = 0;
                                debug_log("Read-only login successful: schedule_id={$schedule['id']}, user_id={$schedule['user_id']}, token=" . substr($token, 0, 8) . "...");
                                header('Location: /schedule.php?schedule_id=' . $schedule['id']);
                                exit;
                            } else {
                                debug_log("Read-only login failed: invalid token=" . substr($token, 0, 8) . "...");
                                $_SESSION['error'] = 'Invalid or expired read-only token.';
                                $_SESSION['login_attempts']++;
                                $_SESSION['last_attempt'] = time();
                            }
                        }
                    } else {
                        debug_log("Login attempt with empty credentials");
                        $_SESSION['error'] = 'Please provide a username and password or a read-only token.';
                        $_SESSION['login_attempts']++;
                        $_SESSION['last_attempt'] = time();
                    }
                } catch (PDOException $e) {
                    debug_log("Database error in login processing: " . $e->getMessage());
                    $_SESSION['error'] = 'Unable to process login. Please try again later.';
                    $_SESSION['login_attempts']++;
                    $_SESSION['last_attempt'] = time();
                }
            }
            // Regenerate CSRF token after POST
            try {
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                debug_log("Regenerated CSRF token: " . substr($_SESSION['csrf_token'], 0, 8) . "...");
            } catch (Exception $e) {
                debug_log("Failed to regenerate CSRF token: " . $e->getMessage());
                $_SESSION['error'] = 'System error: unable to generate secure token.';
            }
        }
    }
}

// Generate CSRF token if not set
if (!isset($_SESSION['csrf_token'])) {
    try {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        debug_log("Generated CSRF token: " . substr($_SESSION['csrf_token'], 0, 8) . "...");
    } catch (Exception $e) {
        debug_log("Failed to generate CSRF token: " . $e->getMessage());
        $_SESSION['error'] = 'System error: unable to generate secure token.';
    }
}
?>

<?php include 'includes/header.php'; ?>
<style>
    .login-container {
        max-width: 400px;
        margin: 2rem auto;
        padding: 2rem;
        background: #ffffff;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .login-container h1 {
        font-size: 1.8rem;
        color: #333;
        text-align: center;
        margin-bottom: 1.5rem;
    }
    .form-control {
        border-radius: 5px;
        border: 1px solid #ced4da;
        padding: 0.75rem;
        transition: border-color 0.3s ease;
    }
    .form-control:focus {
        border-color: #007bff;
        box-shadow: 0 0 5px rgba(0, 123, 255, 0.3);
    }
    .form-label {
        font-weight: 500;
        color: #555;
    }
    .btn-primary {
        width: 100;
        padding: 0.75rem;
        border-radius: 5px;
        background-color: #007bff;
        border: none;
        font-weight: 500;
        transition: background-color 0.3s ease;
    }
    .btn-primary:hover {
        background-color: #0056b3;
    }
    .btn-google {
        width: 100%;
        padding: 0.75rem;
        border-radius: 5px;
        background-color: #ffffff;
        border: 1px solid #ccc;
        color: #333;
        font-weight: 500;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        transition: background-color 0.3s ease, box-shadow 0.3s ease;
    }
    .btn-google:hover {
        background-color: #f8f8f8;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    .btn-google:disabled {
        background-color: #e0e0e0;
        cursor: not-allowed;
        opacity: 0.6;
    }
    .btn-google img {
        height: 20px;
    }
    .alert {
        border-radius: 5px;
        padding: 0.75rem;
        margin-bottom: 1rem;
    }
    .divider {
        display: flex;
        align-items: center;
        text-align: center;
        margin: 1.5rem 0;
        color: #666;
    }
    .divider::before,
    .divider::after {
        content: '';
        flex: 1;
        border-bottom: 1px solid #ddd;
    }
    .divider span {
        padding: 0 0.5rem;
        font-size: 0.9rem;
    }
    @media (max-width: 768px) {
        .login-container {
            margin: 1rem;
            padding: 1.5rem;
        }
        .login-container h1 {
            font-size: 1.6rem;
        }
    }
</style>

<div class="container my-5">
    <div class="login-container">
        <h1>Login</h1>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <div id="google-signin-error" class="alert alert-warning" style="display: none;">
            Google Sign-In failed. Please try again or contact support.
        </div>

        <form method="POST" action="/login.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" placeholder="Enter username" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" placeholder="Enter password" required>
            </div>
            <?php if (($settings['allow_stay_logged_in'] ?? '0') === '1'): ?>
            <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="stay_logged_in" name="stay_logged_in" value="1">
                <label class="form-check-label" for="stay_logged_in">Stay logged in</label>
            </div>
            <?php endif; ?>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>

        <div class="divider"><span>OR</span></div>

        <button class="btn btn-google" id="google-signin-btn" disabled>
            <img src="/assets/google-logo.png" alt="Google Logo"> Loading...
        </button>

        <div class="divider"><span>OR</span></div>

        <form method="POST" action="/login.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="mb-3">
                <label for="token" class="form-label">Read-Only Token</label>
                <input type="text" class="form-control" id="token" name="token" placeholder="Enter read-only token">
            </div>
            <button type="submit" class="btn btn-primary">Login with Token</button>
        </form>
    </div>
</div>

<script nonce="<?php echo htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8'); ?>">
function loadGoogleScript(callback) {
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => {
        console.log('Google Identity Services loaded');
        callback();
    };
    script.onerror = () => {
        console.error('Failed to load Google Identity Services');
        document.getElementById('google-signin-error').style.display = 'block';
    };
    document.head.appendChild(script);
}

function googleSignIn() {
    if (typeof google === 'undefined' || !google.accounts) {
        console.error('Google Identity Services not loaded');
        document.getElementById('google-signin-error').style.display = 'block';
        return;
    }
    const client = google.accounts.oauth2.initTokenClient({
        client_id: '883594600749-oueqjep5vn6h6q1b7ihs2a2psu37ma57.apps.googleusercontent.com',
        scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email openid',
        ux_mode: 'popup',
        callback: (response) => {
            if (response.error) {
                console.error('Google Sign-In error:', response.error, response.error_description);
                document.getElementById('google-signin-error').innerText = 'Google Sign-In failed: ' + (response.error_description || response.error);
                document.getElementById('google-signin-error').style.display = 'block';
                return;
            }
            // Send access token to server
            fetch('/google-token.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': '<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>'
                },
                body: JSON.stringify({ access_token: response.access_token })
            })
            .then(response => {
                if (!response.ok) throw new Error('Server responded with status ' + response.status);
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    console.log('Google login successful:', data);
                    window.location.href = '/index.php';
                } else {
                    console.error('Server error:', data.error);
                    document.getElementById('google-signin-error').innerText = 'Google Sign-In failed: ' + data.error;
                    document.getElementById('google-signin-error').style.display = 'block';
                }
            })
            .catch(error => {
                console.error('Fetch error:', error);
                document.getElementById('google-signin-error').innerText = 'Google Sign-In failed: ' + error.message;
                document.getElementById('google-signin-error').style.display = 'block';
            });
        }
    });
    client.requestAccessToken();
}

document.addEventListener('DOMContentLoaded', function() {
    loadGoogleScript(function() {
        const button = document.getElementById('google-signin-btn');
        button.disabled = false;
        button.innerHTML = '<img src="/assets/google-logo.png" alt="Google Logo"> Sign in with Google';
        button.title = 'Sign in with Google';
        button.addEventListener('click', googleSignIn);
    });
});
</script>

<?php include 'includes/footer.php'; ?>
