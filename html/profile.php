<?php
// /var/www/schedule.permadomain.com/html/profile.php
session_start();
require 'includes/db.php';
require 'includes/functions.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Basic rate-limiting for POST requests
$maxAttempts = 10;
$lockoutTime = 600; // 10 minutes
if (!isset($_SESSION['profile_attempts'])) {
    $_SESSION['profile_attempts'] = 0;
    $_SESSION['last_profile_attempt'] = time();
}

if ($_SESSION['profile_attempts'] >= $maxAttempts && (time() - $_SESSION['last_profile_attempt']) < $lockoutTime) {
    $_SESSION['error'] = 'Too many profile update attempts. Please try again in ' . ceil(($lockoutTime - (time() - $_SESSION['last_profile_attempt'])) / 60) . ' minutes.';
    header('Location: /profile.php');
    exit;
}

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];

if (!$userId || $isReadOnly) {
    debug_log("Access denied: user_id=" . ($userId ?: 'null') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false'));
    $_SESSION['error'] = 'Please log in to access your profile.';
    header('Location: /schedule.php' . ($isReadOnly && isset($_SESSION['read_only_schedule_id']) ? '?schedule_id=' . (int)$_SESSION['read_only_schedule_id'] : ''));
    exit;
}

try {
    $stmt = $pdo->prepare('SELECT username, email FROM users WHERE id = ?');
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        debug_log("User not found: user_id=$userId");
        session_destroy();
        $_SESSION = [];
        $_SESSION['error'] = 'Your account was not found. Please log in again.';
        header('Location: /login.php');
        exit;
    }
    $username = $user['username'];
    $email = $user['email'];

    // Fetch schedules for read-only token display
    $stmt = $pdo->prepare('SELECT id, name, read_only_token FROM schedules WHERE user_id = ? ORDER BY created_at');
    $stmt->execute([$userId]);
    $schedules = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    debug_log("Database error: " . $e->getMessage());
    $_SESSION['error'] = 'Unable to process request due to a database error. Please try again.';
    header('Location: /login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed: user_id=$userId");
        $_SESSION['error'] = 'Invalid request. Please try again.';
        $_SESSION['profile_attempts']++;
        $_SESSION['last_profile_attempt'] = time();
        header('Location: /profile.php');
        exit;
    }

    $newUsername = trim($_POST['username'] ?? '');
    $newEmail = trim($_POST['email'] ?? '');
    $newPassword = $_POST['password'] ?? '';

    try {
        if ($newUsername || $newEmail || $newPassword) {
            if ($newUsername) {
                if (strlen($newUsername) < 1 || strlen($newUsername) > 255 || !preg_match('/^[a-zA-Z0-9_]+$/', $newUsername)) {
                    debug_log("Profile update failed: invalid username, user_id=$userId, username=" . htmlspecialchars(substr($newUsername, 0, 50), ENT_QUOTES, 'UTF-8'));
                    $_SESSION['error'] = 'Username must be 1-255 characters and alphanumeric (letters, numbers, underscores).';
                    $_SESSION['profile_attempts']++;
                    $_SESSION['last_profile_attempt'] = time();
                } else {
                    // Check username uniqueness
                    $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ? AND id != ?');
                    $stmt->execute([$newUsername, $userId]);
                    if ($stmt->fetch()) {
                        debug_log("Profile update failed: username taken, user_id=$userId, username=" . htmlspecialchars($newUsername, ENT_QUOTES, 'UTF-8'));
                        $_SESSION['error'] = 'This username is already taken.';
                        $_SESSION['profile_attempts']++;
                        $_SESSION['last_profile_attempt'] = time();
                    }
                }
            }
            if ($newEmail) {
                if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL) || strlen($newEmail) > 255) {
                    debug_log("Profile update failed: invalid email, user_id=$userId, email=" . htmlspecialchars(substr($newEmail, 0, 50), ENT_QUOTES, 'UTF-8'));
                    $_SESSION['error'] = 'Please enter a valid email address (max 255 characters).';
                    $_SESSION['profile_attempts']++;
                    $_SESSION['last_profile_attempt'] = time();
                } else {
                    // Check email uniqueness
                    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? AND id != ?');
                    $stmt->execute([$newEmail, $userId]);
                    if ($stmt->fetch()) {
                        debug_log("Profile update failed: email taken, user_id=$userId, email=" . htmlspecialchars($newEmail, ENT_QUOTES, 'UTF-8'));
                        $_SESSION['error'] = 'This email is already in use.';
                        $_SESSION['profile_attempts']++;
                        $_SESSION['last_profile_attempt'] = time();
                    }
                }
            }
            if ($newPassword) {
                if (strlen($newPassword) < 8) {
                    debug_log("Profile update failed: password too short, user_id=$userId");
                    $_SESSION['error'] = 'Password must be at least 8 characters long.';
                    $_SESSION['profile_attempts']++;
                    $_SESSION['last_profile_attempt'] = time();
                }
            }
            if (!isset($_SESSION['error'])) {
                // Apply updates
                $updates = [];
                $params = [];
                if ($newUsername) {
                    $updates[] = 'username = ?';
                    $params[] = $newUsername;
                }
                if ($newEmail) {
                    $updates[] = 'email = ?';
                    $params[] = $newEmail;
                }
                if ($newPassword) {
                    $updates[] = 'password = ?';
                    $params[] = password_hash($newPassword, PASSWORD_DEFAULT);
                }
                if ($updates) {
                    $params[] = $userId;
                    $stmt = $pdo->prepare('UPDATE users SET ' . implode(', ', $updates) . ' WHERE id = ?');
                    $stmt->execute($params);
                    debug_log("Profile updated: user_id=$userId" . ($newUsername ? ", new_username=" . htmlspecialchars($newUsername, ENT_QUOTES, 'UTF-8') : '') . ($newEmail ? ", new_email=" . htmlspecialchars($newEmail, ENT_QUOTES, 'UTF-8') : '') . ($newPassword ? ", password_updated" : ''));
                    $_SESSION['success'] = 'Profile updated successfully!';
                    $_SESSION['profile_attempts'] = 0;
                }
            }
        } else {
            debug_log("Profile update failed: no changes provided, user_id=$userId");
            $_SESSION['error'] = 'Please provide a new username, email, or password to update.';
            $_SESSION['profile_attempts']++;
            $_SESSION['last_profile_attempt'] = time();
        }
    } catch (PDOException $e) {
        debug_log("Profile update error: " . $e->getMessage());
        $_SESSION['error'] = 'Unable to update profile due to a database error. Please try again.';
        $_SESSION['profile_attempts']++;
        $_SESSION['last_profile_attempt'] = time();
    }
    header('Location: /profile.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['regenerate_token'])) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed for token regeneration: user_id=$userId");
        $_SESSION['error'] = 'Invalid request. Please try again.';
        $_SESSION['profile_attempts']++;
        $_SESSION['last_profile_attempt'] = time();
        header('Location: /profile.php');
        exit;
    }

    $regenScheduleId = (int)$_POST['schedule_id'];
    try {
        $stmt = $pdo->prepare('SELECT id, read_only_token FROM schedules WHERE id = ? AND user_id = ?');
        $stmt->execute([$regenScheduleId, $userId]);
        $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($schedule) {
            $oldToken = $schedule['read_only_token'];
            $newToken = bin2hex(random_bytes(16));
            $stmt = $pdo->prepare('UPDATE schedules SET read_only_token = ? WHERE id = ? AND user_id = ?');
            $stmt->execute([$newToken, $regenScheduleId, $userId]);
            debug_log("Token regenerated: schedule_id=$regenScheduleId, user_id=$userId, old_token=" . substr(htmlspecialchars($oldToken, ENT_QUOTES, 'UTF-8'), 0, 8) . "..., new_token=" . substr(htmlspecialchars($newToken, ENT_QUOTES, 'UTF-8'), 0, 8) . "...");
            $_SESSION['success'] = 'Read-only token regenerated successfully!';
            $_SESSION['profile_attempts'] = 0;
        } else {
            debug_log("Invalid schedule for token regeneration: schedule_id=$regenScheduleId, user_id=$userId");
            $_SESSION['error'] = 'The selected schedule does not exist or you lack permission.';
            $_SESSION['profile_attempts']++;
            $_SESSION['last_profile_attempt'] = time();
        }
    } catch (PDOException $e) {
        debug_log("Token regeneration error: " . $e->getMessage());
        $_SESSION['error'] = 'Unable to regenerate token due to a database error. Please try again.';
        $_SESSION['profile_attempts']++;
        $_SESSION['last_profile_attempt'] = time();
    }
    header('Location: /profile.php');
    exit;
}
?>

<?php include 'includes/header.php'; ?>
<div class="container">
    <h1>Profile</h1>

    <?php if (isset($_SESSION['success'])): ?>
        <div class="alert alert-success"><?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
    <?php endif; ?>
    <?php if (isset($_SESSION['error'])): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
    <?php endif; ?>

    <form method="POST" action="/profile.php" onsubmit="return confirm('Are you sure you want to update your profile?');">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <div class="mb-3">
            <label for="username" class="form-label">Username</label>
            <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>">
        </div>
        <div class="mb-3">
            <label for="email" class="form-label">Email</label>
            <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>">
        </div>
        <div class="mb-3">
            <label for="password" class="form-label">New Password (leave blank to keep current)</label>
            <input type="password" class="form-control" id="password" name="password" placeholder="Enter new password">
        </div>
        <button type="submit" name="update_profile" class="btn btn-primary">Update Profile</button>
    </form>

    <h2 class="mt-4">Your Schedules</h2>
    <?php if (empty($schedules)): ?>
        <div class="alert alert-info">No schedules found. <a href="/generate.php">Create one</a>.</div>
    <?php else: ?>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Read-Only Token</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($schedules as $schedule): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($schedule['name']); ?></td>
                        <td><?php echo htmlspecialchars($schedule['read_only_token']); ?></td>
                        <td>
                            <a href="/schedule.php?schedule_id=<?php echo $schedule['id']; ?>" class="btn btn-primary btn-sm">View</a>
                            <form method="POST" class="d-inline" onsubmit="return confirm('Are you sure you want to regenerate the read-only token for this schedule? This will invalidate the current token.');">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="schedule_id" value="<?php echo $schedule['id']; ?>">
                                <button type="submit" name="regenerate_token" class="btn btn-warning btn-sm">Regenerate Token</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <div class="mt-4">
        <a href="/index.php" class="btn btn-secondary">Back to Schedules</a>
        <form method="POST" action="/logout.php" class="d-inline">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <button type="submit" name="logout" class="btn btn-danger">Logout</button>
        </form>
    </div>
</div>
<?php include 'includes/footer.php'; ?>
