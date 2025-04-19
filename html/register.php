<?php
// /var/www/schedule.permadomain.com/html/register.php
session_start();
require 'includes/db.php';
require 'includes/functions.php';

ini_set('display_errors', 0);
error_reporting(E_ALL);

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: /index.php');
    exit;
}

// Basic rate-limiting
$maxAttempts = 10;
$lockoutTime = 600; // 10 minutes
if (!isset($_SESSION['register_attempts'])) {
    $_SESSION['register_attempts'] = 0;
    $_SESSION['last_register_attempt'] = time();
}

if ($_SESSION['register_attempts'] >= $maxAttempts && (time() - $_SESSION['last_register_attempt']) < $lockoutTime) {
    $_SESSION['error'] = 'Too many registration attempts. Please try again in ' . ceil(($lockoutTime - (time() - $_SESSION['last_register_attempt'])) / 60) . ' minutes.';
    header('Location: /register.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed during registration");
        $_SESSION['error'] = 'Invalid request. Please try again.';
        $_SESSION['register_attempts']++;
        $_SESSION['last_register_attempt'] = time();
        header('Location: /register.php');
        exit;
    }

    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    try {
        // Validate inputs
        if (strlen($username) < 1 || strlen($username) > 255 || !preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            debug_log("Registration failed: invalid username, username=" . htmlspecialchars(substr($username, 0, 50), ENT_QUOTES, 'UTF-8'));
            $_SESSION['error'] = 'Username must be 1-255 characters and alphanumeric (letters, numbers, underscores).';
            $_SESSION['register_attempts']++;
            $_SESSION['last_register_attempt'] = time();
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
            debug_log("Registration failed: invalid email, email=" . htmlspecialchars(substr($email, 0, 50), ENT_QUOTES, 'UTF-8'));
            $_SESSION['error'] = 'Please enter a valid email address (max 255 characters).';
            $_SESSION['register_attempts']++;
            $_SESSION['last_register_attempt'] = time();
        } elseif (strlen($password) < 8) {
            debug_log("Registration failed: password too short");
            $_SESSION['error'] = 'Password must be at least 8 characters long.';
            $_SESSION['register_attempts']++;
            $_SESSION['last_register_attempt'] = time();
        } else {
            // Check username and email uniqueness
            $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ?');
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                debug_log("Registration failed: username taken, username=" . htmlspecialchars($username, ENT_QUOTES, 'UTF-8'));
                $_SESSION['error'] = 'This username is already taken.';
                $_SESSION['register_attempts']++;
                $_SESSION['last_register_attempt'] = time();
            } else {
                $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ?');
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    debug_log("Registration failed: email taken, email=" . htmlspecialchars($email, ENT_QUOTES, 'UTF-8'));
                    $_SESSION['error'] = 'This email is already in use.';
                    $_SESSION['register_attempts']++;
                    $_SESSION['last_register_attempt'] = time();
                } else {
                    // Insert new user
                    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare('INSERT INTO users (username, email, password, is_admin, created_at) VALUES (?, ?, ?, 0, NOW())');
                    $stmt->execute([$username, $email, $hashedPassword]);
                    $userId = $pdo->lastInsertId();
                    debug_log("User registered: user_id=$userId, username=" . htmlspecialchars($username, ENT_QUOTES, 'UTF-8'));

                    // Log in the user
                    $_SESSION['user_id'] = $userId;
                    $_SESSION['username'] = $username;
                    $_SESSION['email'] = $email;
                    $_SESSION['is_admin'] = 0;
                    $_SESSION['read_only'] = false;
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    $_SESSION['register_attempts'] = 0;

                    $_SESSION['success'] = 'Registration successful! Welcome!';
                    header('Location: /index.php');
                    exit;
                }
            }
        }
    } catch (PDOException $e) {
        debug_log("Registration error: " . $e->getMessage());
        $_SESSION['error'] = 'Unable to register due to a database error. Please try again.';
        $_SESSION['register_attempts']++;
        $_SESSION['last_register_attempt'] = time();
        header('Location: /register.php');
        exit;
    }
}

$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

<?php include 'includes/header.php'; ?>
<style>
    .register-container {
        max-width: 900px;
        margin: 3rem auto;
        padding: 2.5rem;
        background: linear-gradient(135deg, #ffffff, #f8f9fa);
        border-radius: 15px;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
        transition: transform 0.3s ease;
    }
    .register-container:hover {
        transform: translateY(-5px);
    }
    .register-container h1 {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1a3c66;
        text-align: center;
        margin-bottom: 2rem;
    }
    .form-control {
        border-radius: 8px;
        border: 1px solid #d1d5db;
        padding: 0.75rem 1rem;
        font-size: 1rem;
        transition: all 0.3s ease;
    }
    .form-control:focus {
        border-color: #3b82f6;
        box-shadow: 0 0 8px rgba(59, 130, 246, 0.3);
        outline: none;
    }
    .form-label {
        font-weight: 600;
        color: #374151;
        margin-bottom: 0.5rem;
    }
    .btn-primary, .btn-secondary {
        padding: 0.75rem 1.5rem;
        border-radius: 8px;
        font-size: 1rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    .btn-primary {
        background-color: #3b82f6;
        border: none;
    }
    .btn-primary:hover {
        background-color: #1d4ed8;
        transform: translateY(-2px);
    }
    .btn-secondary {
        background-color: #6b7280;
        border: none;
    }
    .btn-secondary:hover {
        background-color: #4b5563;
        transform: translateY(-2px);
    }
    .alert {
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1.5rem;
        font-size: 0.95rem;
    }
    @media (max-width: 768px) {
        .register-container {
            margin: 1.5rem;
            padding: 1.5rem;
        }
        .register-container h1 {
            font-size: 1.8rem;
        }
    }
</style>

<div class="container my-5">
    <div class="register-container">
        <h1>Register</h1>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
        <?php endif; ?>
        <?php if (isset($_SESSION['success'])): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
        <?php endif; ?>

        <form method="POST" action="/register.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="mb-4">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
            </div>
            <div class="mb-4">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" required>
            </div>
            <div class="mb-4">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" name="register" class="btn btn-primary">Register</button>
        </form>

        <div class="mt-4">
            <a href="/login.php" class="btn btn-secondary">Back to Login</a>
        </div>
    </div>
</div>
<?php include 'includes/footer.php'; ?>
