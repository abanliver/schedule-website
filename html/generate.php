<?php
// /var/www/schedule.permadomain.com/html/generate.php
session_start();
require 'includes/db.php';
require 'includes/functions.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];

if (!$userId || $isReadOnly) {
    debug_log("Access denied: user_id=" . ($userId ?: 'null') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false'));
    $_SESSION['error'] = 'Please log in to create or edit a schedule.';
    header('Location: /schedule.php' . ($isReadOnly && isset($_SESSION['read_only_schedule_id']) ? '?schedule_id=' . (int)$_SESSION['read_only_schedule_id'] : ''));
    exit;
}

$scheduleId = isset($_GET['schedule_id']) ? (int)$_GET['schedule_id'] : null;

function calculateDates($startDate, $frequency, $sessions) {
    $dates = [];
    try {
        $date = DateTime::createFromFormat('Y-m-d', $startDate);
        if (!$date || $date->format('Y-m-d') !== $startDate) {
            throw new Exception("Invalid start date format: $startDate");
        }
        while ($date->format('N') != 2) { // Start on Tuesday
            $date->modify('+1 day');
        }
        for ($i = 0; $i < $sessions; $i++) {
            $dates[] = $date->format('Y-m-d');
            switch ($frequency) {
                case 'weekly': $date->modify('+1 week'); break;
                case 'monthly': $date->modify('+1 month'); break;
                case 'yearly': $date->modify('+1 year'); break;
            }
        }
    } catch (Exception $e) {
        debug_log("Error in calculateDates: " . $e->getMessage());
        return [];
    }
    return $dates;
}

// Validate schedule_id if provided
if ($scheduleId) {
    try {
        $stmt = $pdo->prepare('SELECT id, name FROM schedules WHERE id = ? AND user_id = ?');
        $stmt->execute([$scheduleId, $userId]);
        $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$schedule) {
            debug_log("Invalid schedule: schedule_id=$scheduleId, user_id=$userId");
            $_SESSION['error'] = 'Invalid schedule selected.';
            header('Location: /index.php');
            exit;
        }
        $scheduleName = $schedule['name'];
    } catch (PDOException $e) {
        debug_log("Error validating schedule: " . $e->getMessage());
        $_SESSION['error'] = 'Error accessing schedule.';
        header('Location: /index.php');
        exit;
    }
} else {
    $scheduleName = '';
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed: user_id=$userId, action=" . ($_POST['create'] ?? $_POST['generate'] ?? $_POST['add_date'] ?? 'unknown'));
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: /generate.php' . ($scheduleId ? '?schedule_id=' . $scheduleId : ''));
        exit;
    }

    if (isset($_POST['create']) || isset($_POST['generate'])) {
        $name = trim($_POST['schedule_name'] ?? '');
        $startDate = trim($_POST['start_date'] ?? '');
        $frequency = trim($_POST['frequency'] ?? '');
        $sessions = (int)($_POST['sessions'] ?? 0);

        // Sanitize schedule name
        $name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');

        // Validate inputs
        $dateObj = DateTime::createFromFormat('Y-m-d', $startDate);
        if (empty($name)) {
            $_SESSION['error'] = 'Schedule name is required.';
        } elseif (!$dateObj || $dateObj->format('Y-m-d') !== $startDate || !in_array($frequency, ['weekly', 'monthly', 'yearly']) || $sessions <= 0) {
            $_SESSION['error'] = 'Please provide a valid start date (YYYY-MM-DD), frequency, and number of sessions.';
        } else {
            try {
                if (isset($_POST['create']) && !$scheduleId) {
                    $token = bin2hex(random_bytes(16));
                    $stmt = $pdo->prepare('INSERT INTO schedules (user_id, name, read_only_token) VALUES (?, ?, ?)');
                    $stmt->execute([$userId, $name, $token]);
                    $scheduleId = $pdo->lastInsertId();
                    debug_log("Created new schedule: schedule_id=$scheduleId, user_id=$userId, name=$name, token=$token");
                } elseif (isset($_POST['generate']) && $scheduleId) {
                    $stmt = $pdo->prepare('UPDATE schedules SET name = ? WHERE id = ? AND user_id = ?');
                    $stmt->execute([$name, $scheduleId, $userId]);
                    debug_log("Updated schedule: schedule_id=$scheduleId, user_id=$userId, name=$name");
                }

                $dates = calculateDates($startDate, $frequency, $sessions);
                if (empty($dates)) {
                    $_SESSION['error'] = 'Unable to calculate appointment dates. Please check your inputs.';
                } else {
                    $pdo->beginTransaction();
                    $pdo->prepare('DELETE FROM appointments WHERE user_id = ? AND schedule_id = ?')->execute([$userId, $scheduleId]);
                    $stmt = $pdo->prepare('
                        INSERT INTO appointments (user_id, schedule_id, scheduled_date, frequency, status)
                        VALUES (?, ?, ?, ?, "scheduled")
                    ');
                    foreach ($dates as $date) {
                        $stmt->execute([$userId, $scheduleId, $date, $frequency]);
                    }
                    $pdo->commit();
                    debug_log("Generated " . count($dates) . " appointments for schedule_id=$scheduleId, user_id=$userId");
                    $_SESSION['success'] = "Schedule " . ($scheduleId ? 'updated' : 'created') . " successfully! View it <a href='/schedule.php?schedule_id=$scheduleId'>here</a>.";
                    header('Location: /index.php');
                    exit;
                }
            } catch (Exception $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                debug_log("Error processing schedule: " . $e->getMessage());
                $_SESSION['error'] = 'Error processing schedule. Please try again.';
            }
        }
    }
    if (isset($_POST['add_date']) && $scheduleId) {
        try {
            $specificDate = trim($_POST['specific_date'] ?? '');
            $dateObj = DateTime::createFromFormat('Y-m-d', $specificDate);
            if (!$dateObj || $dateObj->format('Y-m-d') !== $specificDate) {
                throw new Exception("Invalid date format: $specificDate");
            }
            $stmt = $pdo->prepare('
                INSERT INTO appointments (user_id, schedule_id, scheduled_date, frequency, status)
                VALUES (?, ?, ?, ?, ?)
            ');
            $stmt->execute([$userId, $scheduleId, $specificDate, 'one-off', 'scheduled']);
            debug_log("Added specific date: schedule_id=$scheduleId, user_id=$userId, date=$specificDate");
            $_SESSION['success'] = "Appointment added successfully! View it <a href='/schedule.php?schedule_id=$scheduleId'>here</a>.";
            header('Location: /index.php');
            exit;
        } catch (Exception $e) {
            debug_log("Error adding specific date: " . $e->getMessage());
            $_SESSION['error'] = 'Failed to add appointment. Please check the date format.';
        }
    }
    // Redirect to preserve error/success messages
    header('Location: /generate.php' . ($scheduleId ? '?schedule_id=' . $scheduleId : ''));
    exit;
}

$isAdmin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'];
?>

<?php include 'includes/header.php'; ?>
<div class="container">
    <h1><?php echo $scheduleId ? 'Edit Schedule' : 'Create Schedule'; ?></h1>

    <?php if (isset($_SESSION['success'])): ?>
        <div class="alert alert-success"><?php echo $_SESSION['success']; unset($_SESSION['success']); ?></div>
    <?php endif; ?>
    <?php if (isset($_SESSION['error'])): ?>
        <div class="alert alert-danger"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
    <?php endif; ?>

    <div class="card shadow-sm p-4 mb-4">
        <h4><?php echo $scheduleId ? 'Update Schedule' : 'New Schedule'; ?></h4>
        <form method="POST" class="row g-3">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="col-md-6">
                <label class="form-label">Schedule Name</label>
                <input type="text" name="schedule_name" class="form-control" value="<?php echo htmlspecialchars($scheduleName); ?>" required>
            </div>
            <div class="col-md-3">
                <label class="form-label">Start Date</label>
                <input type="date" name="start_date" class="form-control" required>
            </div>
            <div class="col-md-3">
                <label class="form-label">Frequency</label>
                <select name="frequency" class="form-select" required>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                    <option value="yearly">Yearly</option>
                </select>
            </div>
            <div class="col-md-3">
                <label class="form-label">Number of Sessions</label>
                <input type="number" name="sessions" class="form-control" min="1" required>
            </div>
            <div class="col-md-3">
                <label class="form-label">&nbsp;</label>
                <button type="submit" name="<?php echo $scheduleId ? 'generate' : 'create'; ?>" class="btn btn-primary w-100">
                    <?php echo $scheduleId ? 'Update Schedule' : 'Create Schedule'; ?>
                </button>
            </div>
        </form>
        <?php if ($scheduleId): ?>
            <form method="POST" class="row g-3 mt-3">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="col-md-3">
                    <label class="form-label">Add Specific Date</label>
                    <input type="date" name="specific_date" class="form-control" required>
                </div>
                <div class="col-md-3">
                    <label class="form-label">&nbsp;</label>
                    <button type="submit" name="add_date" class="btn btn-success w-100">Add Date</button>
                </div>
            </form>
        <?php endif; ?>
    </div>

    <div class="mb-4">
        <a href="/index.php" class="btn btn-secondary">Back to Schedules</a>
        <form method="POST" action="/logout.php" class="d-inline">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <button type="submit" name="logout" class="btn btn-danger">Logout</button>
        </form>
        <?php if ($isAdmin): ?>
            <a href="/admin/index.php" class="btn btn-primary">Admin Panel</a>
        <?php endif; ?>
    </div>
</div>
<?php include 'includes/footer.php'; ?>
