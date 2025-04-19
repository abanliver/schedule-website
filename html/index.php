<?php
// /var/www/schedule.permadomain.com/html/index.php
session_start();
require 'includes/db.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];

if (!$userId || $isReadOnly) {
    debug_log("Access denied: user_id=" . ($userId ?: 'null') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false'));
    $_SESSION['error'] = 'Please log in to view your schedules.';
    header('Location: /schedule.php' . ($isReadOnly && isset($_SESSION['read_only_schedule_id']) ? '?schedule_id=' . $_SESSION['read_only_schedule_id'] : ''));
    exit;
}

try {
    $stmt = $pdo->prepare('SELECT username, is_admin FROM users WHERE id = ?');
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        debug_log("User not found: user_id=$userId");
        session_destroy();
        $_SESSION = [];
        $_SESSION['error'] = 'User not found.';
        header('Location: /login.php');
        exit;
    }
    $username = $user['username'];
    $isAdmin = $user['is_admin'];

    $stmt = $pdo->prepare('SELECT id, name FROM schedules WHERE user_id = ? ORDER BY created_at');
    $stmt->execute([$userId]);
    $schedules = $stmt->fetchAll(PDO::FETCH_ASSOC);
    debug_log("Fetched " . count($schedules) . " schedules for user_id=$userId");
} catch (PDOException $e) {
    debug_log("Database error: " . $e->getMessage());
    $_SESSION['error'] = 'Database error. Please try again.';
    header('Location: /login.php');
    exit;
}
?>

<?php include 'includes/header.php'; ?>
<div class="container">
    <h1>Your Schedules</h1>

    <?php if (isset($_SESSION['success'])): ?>
        <div class="alert alert-success"><?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
    <?php endif; ?>
    <?php if (isset($_SESSION['error'])): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
    <?php endif; ?>

    <?php if (empty($schedules)): ?>
        <div class="alert alert-info">No schedules found. Create one to get started.</div>
        <a href="/generate.php" class="btn btn-primary">Create Schedule</a>
    <?php else: ?>
        <ul class="list-group mb-4">
            <?php foreach ($schedules as $schedule): ?>
                <li class="list-group-item">
                    <a href="/schedule.php?schedule_id=<?php echo $schedule['id']; ?>"><?php echo htmlspecialchars($schedule['name']); ?></a>
                </li>
            <?php endforeach; ?>
        </ul>
        <a href="/generate.php" class="btn btn-primary">Create New Schedule</a>
    <?php endif; ?>

    <div class="mt-4">
        <a href="/profile.php" class="btn btn-secondary">Profile</a>
        <?php if ($isAdmin): ?>
            <a href="/admin/index.php" class="btn btn-primary">Admin Panel</a>
        <?php endif; ?>
        <form method="POST" action="/logout.php" class="d-inline">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <button type="submit" name="logout" class="btn btn-danger">Logout</button>
        </form>
    </div>
</div>
<?php include 'includes/footer.php'; ?>
