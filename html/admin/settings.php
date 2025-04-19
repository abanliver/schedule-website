<?php
// /var/www/schedule.permadomain.com/html/admin/settings.php
session_start();
require_once '../includes/db.php';
require_once '../includes/functions.php';

// Restrict to admins
if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
    $_SESSION['error'] = 'Access denied. Admins only.';
    header('Location: /login.php');
    exit;
}

// Fetch current settings
$settings = get_setting();

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed on settings update: user_id=" . (int)$_SESSION['user_id']);
        $_SESSION['error'] = 'Invalid request. Please try again.';
    } else {
        try {
            $updates = [
                'session_timeout' => max(60, min(86400, (int)($_POST['session_timeout'] ?? 1800))),
                'allow_stay_logged_in' => isset($_POST['allow_stay_logged_in']) ? '1' : '0',
                'session_regeneration_interval' => max(300, min(86400, (int)($_POST['session_regeneration_interval'] ?? 3600))),
                'session_creation_max_attempts' => max(5, min(50, (int)($_POST['session_creation_max_attempts'] ?? 15))),
                'session_creation_lockout_time' => max(60, min(3600, (int)($_POST['session_creation_lockout_time'] ?? 600))),
                'login_max_attempts' => max(3, min(20, (int)($_POST['login_max_attempts'] ?? 5))),
                'login_lockout_time' => max(60, min(3600, (int)($_POST['login_lockout_time'] ?? 300))),
                'debug_logging_enabled' => isset($_POST['debug_logging_enabled']) ? '1' : '0'
            ];

            foreach ($updates as $key => $value) {
                $stmt = $pdo->prepare('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?');
                $stmt->execute([$key, $value, $value]);
            }

            debug_log("Settings updated by user_id=" . (int)$_SESSION['user_id']);
            $_SESSION['success'] = 'Settings updated successfully.';
            header('Location: /admin/settings.php');
            exit;
        } catch (PDOException $e) {
            debug_log("Database error updating settings: " . $e->getMessage());
            $_SESSION['error'] = 'Failed to update settings. Please try again.';
        }
    }
    // Regenerate CSRF token
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<?php include '../includes/header.php'; ?>
<div class="container mt-4">
    <h1>System Settings</h1>

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

    <form method="POST" action="/admin/settings.php">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        
        <div class="mb-3">
            <label for="session_timeout" class="form-label">Session Timeout (seconds)</label>
            <input type="number" class="form-control" id="session_timeout" name="session_timeout" value="<?php echo htmlspecialchars($settings['session_timeout']); ?>" min="60" max="86400" required>
            <small class="form-text text-muted">Duration before inactive sessions expire (60 to 86400 seconds).</small>
        </div>

        <div class="mb-3 form-check">
            <input type="checkbox" class="form-check-input" id="allow_stay_logged_in" name="allow_stay_logged_in" value="1" <?php echo $settings['allow_stay_logged_in'] === '1' ? 'checked' : ''; ?>>
            <label class="form-check-label" for="allow_stay_logged_in">Allow "Stay Logged In"</label>
            <small class="form-text text-muted">Enable the "Stay logged in" option on login form.</small>
        </div>

        <div class="mb-3">
            <label for="session_regeneration_interval" class="form-label">Session Regeneration Interval (seconds)</label>
            <input type="number" class="form-control" id="session_regeneration_interval" name="session_regeneration_interval" value="<?php echo htmlspecialchars($settings['session_regeneration_interval']); ?>" min="300" max="86400" required>
            <small class="form-text text-muted">How often to regenerate session IDs (300 to 86400 seconds).</small>
        </div>

        <div class="mb-3">
            <label for="session_creation_max_attempts" class="form-label">Session Creation Max Attempts</label>
            <input type="number" class="form-control" id="session_creation_max_attempts" name="session_creation_max_attempts" value="<?php echo htmlspecialchars($settings['session_creation_max_attempts']); ?>" min="5" max="50" required>
            <small class="form-text text-muted">Max session creation attempts before lockout (5 to 50).</small>
        </div>

        <div class="mb-3">
            <label for="session_creation_lockout_time" class="form-label">Session Creation Lockout Time (seconds)</label>
            <input type="number" class="form-control" id="session_creation_lockout_time" name="session_creation_lockout_time" value="<?php echo htmlspecialchars($settings['session_creation_lockout_time']); ?>" min="60" max="3600" required>
            <small class="form-text text-muted">Lockout duration after max session attempts (60 to 3600 seconds).</small>
        </div>

        <div class="mb-3">
            <label for="login_max_attempts" class="form-label">Login Max Attempts</label>
            <input type="number" class="form-control" id="login_max_attempts" name="login_max_attempts" value="<?php echo htmlspecialchars($settings['login_max_attempts']); ?>" min="3" max="20" required>
            <small class="form-text text-muted">Max login attempts before lockout (3 to 20).</small>
        </div>

        <div class="mb-3">
            <label for="login_lockout_time" class="form-label">Login Lockout Time (seconds)</label>
            <input type="number" class="form-control" id="login_lockout_time" name="login_lockout_time" value="<?php echo htmlspecialchars($settings['login_lockout_time']); ?>" min="60" max="3600" required>
            <small class="form-text text-muted">Lockout duration after max login attempts (60 to 3600 seconds).</small>
        </div>

        <div class="mb-3 form-check">
            <input type="checkbox" class="form-check-input" id="debug_logging_enabled" name="debug_logging_enabled" value="1" <?php echo $settings['debug_logging_enabled'] === '1' ? 'checked' : ''; ?>>
            <label class="form-check-label" for="debug_logging_enabled">Enable Debug Logging</label>
            <small class="form-text text-muted">Log debug information to /logs/debug.log.</small>
        </div>

        <button type="submit" class="btn btn-primary">Save Settings</button>
    </form>
</div>
<?php include '../includes/footer.php'; ?>
