<?php
// /var/www/schedule.permadomain.com/html/schedule.php

// Prevent caching
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Only start session if not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Initialize CSRF token if not set
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    debug_log("CSRF token initialized: " . $_SESSION['csrf_token']);
}

require_once 'includes/db.php';
require_once 'includes/summary.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$readOnlyToken = isset($_GET['token']) ? trim($_GET['token']) : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];
$displayUserId = null;
$displayUsername = null;
$scheduleId = null;
$schedules = [];

if (!$userId && !$isReadOnly && !$readOnlyToken) {
    debug_log("Access denied: no user_id, read_only session, or token provided");
    $_SESSION['error'] = 'Please log in or provide a valid read-only token.';
    header('Location: /login.php');
    exit;
}

function calculateDates($startDate, $frequency, $sessions) {
    $dates = [];
    try {
        $date = new DateTime($startDate);
        while ($date->format('N') != 2) {
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
        debug_log('calculateDates error: ' . $e->getMessage());
        return [];
    }
    return $dates;
}

function reschedulePastDue($pdo, $userId, $scheduleId) {
    try {
        $today = date('Y-m-d');
        $stmt = $pdo->prepare('SELECT * FROM appointments WHERE user_id = ? AND schedule_id = ? AND status = "scheduled" AND scheduled_date < ? AND parent_id IS NULL');
        $stmt->execute([$userId, $scheduleId, $today]);
        $pastDue = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($pastDue as $appt) {
            $checkStmt = $pdo->prepare('SELECT COUNT(*) FROM appointments WHERE parent_id = ? AND user_id = ? AND schedule_id = ?');
            $checkStmt->execute([$appt['id'], $userId, $scheduleId]);
            if ($checkStmt->fetchColumn() == 0) {
                $pdo->prepare('UPDATE appointments SET status = "missed" WHERE id = ?')->execute([$appt['id']]);
                $latestStmt = $pdo->prepare('SELECT MAX(scheduled_date) as latest_date FROM appointments WHERE user_id = ? AND schedule_id = ? AND status = "scheduled"');
                $latestStmt->execute([$userId, $scheduleId]);
                $latestDate = $latestStmt->fetchColumn();
                $baseDate = $latestDate ? new DateTime($latestDate) : new DateTime($appt['scheduled_date']);
                switch ($appt['frequency']) {
                    case 'weekly': $baseDate->modify('+1 week'); break;
                    case 'monthly': $baseDate->modify('+1 month'); break;
                    case 'yearly': $baseDate->modify('+1 year'); break;
                }
                $newDateStr = $baseDate->format('Y-m-d');
                $pdo->prepare('INSERT INTO appointments (user_id, schedule_id, scheduled_date, frequency, status, parent_id) VALUES (?, ?, ?, ?, "scheduled", ?)')
                    ->execute([$userId, $scheduleId, $newDateStr, $appt['frequency'], $appt['id']]);
            }
        }
    } catch (Exception $e) {
        debug_log('reschedulePastDue error: ' . $e->getMessage());
    }
}

try {
    if ($userId && !$isReadOnly) {
        // Authenticated user
        $stmt = $pdo->prepare('SELECT username FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            $displayUserId = $userId;
            $displayUsername = $user['username'];
            $stmt = $pdo->prepare('SELECT id, name, read_only_token FROM schedules WHERE user_id = ? ORDER BY created_at');
            $stmt->execute([$userId]);
            $schedules = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (empty($schedules)) {
                debug_log("No schedules found for user_id=$userId");
                $_SESSION['error'] = 'No schedules found. Please create one.';
                header('Location: /index.php');
                exit;
            } else {
                $requestedScheduleId = isset($_GET['schedule_id']) ? (int)$_GET['schedule_id'] : $schedules[0]['id'];
                $validScheduleIds = array_column($schedules, 'id');
                $scheduleId = in_array($requestedScheduleId, $validScheduleIds) ? $requestedScheduleId : $schedules[0]['id'];
            }
        } else {
            debug_log("User not found: user_id=$userId");
            session_destroy();
            $_SESSION = [];
            $_SESSION['error'] = 'User not found.';
            header('Location: /login.php');
            exit;
        }
    } elseif ($isReadOnly || $readOnlyToken) {
        // Read-only access
        if ($isReadOnly && isset($_SESSION['read_only_schedule_id'])) {
            $scheduleId = (int)$_SESSION['read_only_schedule_id'];
        } elseif ($readOnlyToken) {
            $stmt = $pdo->prepare('SELECT s.id, s.name, u.id as user_id, u.username FROM schedules s JOIN users u ON s.user_id = u.id WHERE s.read_only_token = ?');
            $stmt->execute([$readOnlyToken]);
            $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($schedule) {
                $scheduleId = $schedule['id'];
                $_SESSION['read_only'] = true;
                $_SESSION['read_only_schedule_id'] = $schedule['id'];
                $_SESSION['read_only_schedule_name'] = $schedule['name'];
                debug_log("Read-only access granted via token: schedule_id=$scheduleId, token=$readOnlyToken");
            } else {
                debug_log("Invalid read-only token: token=$readOnlyToken");
                $_SESSION['error'] = 'Invalid or expired read-only token.';
                header('Location: /login.php');
                exit;
            }
        }

        if ($scheduleId) {
            $stmt = $pdo->prepare('SELECT s.id, s.name, u.id as user_id, u.username FROM schedules s JOIN users u ON s.user_id = u.id WHERE s.id = ?');
            $stmt->execute([$scheduleId]);
            $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($schedule) {
                $displayUserId = $schedule['user_id'];
                $displayUsername = $schedule['username'];
                unset($_SESSION['user_id']);
                unset($_SESSION['is_admin']);
            } else {
                debug_log("Schedule not found: schedule_id=$scheduleId");
                unset($_SESSION['read_only'], $_SESSION['read_only_schedule_id'], $_SESSION['read_only_schedule_name']);
                $_SESSION['error'] = 'Schedule not found.';
                header('Location: /login.php');
                exit;
            }
        } else {
            debug_log("No schedule_id for read-only access");
            $_SESSION['error'] = 'Invalid schedule access.';
            header('Location: /login.php');
            exit;
        }
    }
} catch (PDOException $e) {
    debug_log('Database error in user/schedule fetch: ' . $e->getMessage());
    $_SESSION['error'] = 'Database error. Please try again.';
    header('Location: /login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_schedule']) && $userId && !$isReadOnly) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed: user_id=$userId, action=delete_schedule");
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: /schedule.php?schedule_id=' . (int)$_POST['schedule_id']);
        exit;
    }

    $deleteScheduleId = (int)$_POST['schedule_id'];
    if ($deleteScheduleId && in_array($deleteScheduleId, array_column($schedules, 'id'))) {
        try {
            $stmt = $pdo->prepare('DELETE FROM schedules WHERE id = ? AND user_id = ?');
            $stmt->execute([$deleteScheduleId, $userId]);
            debug_log("Schedule deleted: schedule_id=$deleteScheduleId, user_id=$userId");
            $_SESSION['success'] = 'Schedule deleted successfully!';
            header('Location: /index.php');
            exit;
        } catch (Exception $e) {
            debug_log('Delete schedule error: ' . $e->getMessage());
            $_SESSION['error'] = 'Error deleting schedule.';
            header('Location: /schedule.php?schedule_id=' . $deleteScheduleId);
            exit;
        }
    } else {
        debug_log("Invalid schedule ID for deletion: schedule_id=$deleteScheduleId, user_id=$userId");
        $_SESSION['error'] = 'Invalid schedule ID.';
        header('Location: /schedule.php?schedule_id=' . $deleteScheduleId);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['regenerate_token']) && $userId && !$isReadOnly) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed: user_id=$userId, action=regenerate_token");
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: /schedule.php?schedule_id=' . (int)$_POST['schedule_id']);
        exit;
    }

    $regenScheduleId = (int)$_POST['schedule_id'];
    if ($regenScheduleId && in_array($regenScheduleId, array_column($schedules, 'id'))) {
        try {
            $newToken = bin2hex(random_bytes(16));
            $stmt = $pdo->prepare('UPDATE schedules SET read_only_token = ? WHERE id = ? AND user_id = ?');
            $stmt->execute([$newToken, $regenScheduleId, $userId]);
            debug_log("Token regenerated: schedule_id=$regenScheduleId, user_id=$userId, new_token=$newToken");
            $_SESSION['success'] = 'Read-only token regenerated!';
            header('Location: /schedule.php?schedule_id=' . $regenScheduleId);
            exit;
        } catch (PDOException $e) {
            debug_log('Token regeneration error: ' . $e->getMessage());
            $_SESSION['error'] = 'Error regenerating token.';
            header('Location: /schedule.php?schedule_id=' . $regenScheduleId);
            exit;
        }
    } else {
        debug_log("Invalid schedule ID for token regeneration: schedule_id=$regenScheduleId, user_id=$userId");
        $_SESSION['error'] = 'Invalid schedule ID.';
        header('Location: /schedule.php?schedule_id=' . $regenScheduleId);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax']) && $displayUserId && $scheduleId && !$isReadOnly) {
    header('Content-Type: application/json');
    debug_log("AJAX POST request received: user_id=$userId, display_user_id=$displayUserId, schedule_id=$scheduleId, action=" . ($_POST['update_status'] ?? ($_POST['delete'] ?? 'unknown')) . ", session_id=" . session_id() . ", post_data=" . json_encode($_POST));

    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed: user_id=$userId, session_id=" . session_id() . ", received_token=" . ($_POST['csrf_token'] ?? 'none') . ", expected_token=" . ($_SESSION['csrf_token'] ?? 'none'));
        echo json_encode(['success' => false, 'error' => 'Invalid CSRF token']);
        exit;
    }

    try {
        if (isset($_POST['update_status'])) {
            $id = (int)$_POST['id'];
            $status = $_POST['status'] === 'reschedule' ? 'rescheduled' : $_POST['status'];
            debug_log("Updating status: appointment_id=$id, status=$status, user_id=$displayUserId, schedule_id=$scheduleId");

            $stmt = $pdo->prepare('SELECT scheduled_date, frequency FROM appointments WHERE id = ? AND user_id = ? AND schedule_id = ?');
            $stmt->execute([$id, $displayUserId, $scheduleId]);
            $appt = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$appt) {
                debug_log("Appointment not found: id=$id, user_id=$displayUserId, schedule_id=$scheduleId");
                echo json_encode(['success' => false, 'error' => 'Appointment not found']);
                exit;
            }

            $stmt = $pdo->prepare('UPDATE appointments SET status = ? WHERE id = ? AND user_id = ? AND schedule_id = ?');
            $stmt->execute([$status, $id, $displayUserId, $scheduleId]);
            debug_log("Status updated: appointment_id=$id, new_status=$status");

            $checkStmt = $pdo->prepare('SELECT COUNT(*) FROM appointments WHERE parent_id = ? AND user_id = ? AND schedule_id = ?');
            $checkStmt->execute([$id, $displayUserId, $scheduleId]);
            $hasChild = $checkStmt->fetchColumn() > 0;
            debug_log("Child check: appointment_id=$id, has_child=" . ($hasChild ? 'yes' : 'no'));

            if (in_array($status, ['missed', 'rescheduled']) && !$hasChild) {
                $latestStmt = $pdo->prepare('SELECT MAX(scheduled_date) as latest_date FROM appointments WHERE user_id = ? AND schedule_id = ? AND status = "scheduled"');
                $latestStmt->execute([$displayUserId, $scheduleId]);
                $latestDate = $latestStmt->fetchColumn();
                $baseDate = $latestDate ? new DateTime($latestDate) : new DateTime($appt['scheduled_date']);
                switch ($appt['frequency']) {
                    case 'weekly': $baseDate->modify('+1 week'); break;
                    case 'monthly': $baseDate->modify('+1 month'); break;
                    case 'yearly': $baseDate->modify('+1 year'); break;
                    default:
                        debug_log("Invalid frequency: appointment_id=$id, frequency=" . ($appt['frequency'] ?? 'none'));
                        echo json_encode(['success' => false, 'error' => 'Invalid frequency']);
                        exit;
                }
                $newDateStr = $baseDate->format('Y-m-d');
                $pdo->prepare('INSERT INTO appointments (user_id, schedule_id, scheduled_date, frequency, status, parent_id) VALUES (?, ?, ?, ?, "scheduled", ?)')
                    ->execute([$displayUserId, $scheduleId, $newDateStr, $appt['frequency'], $id]);
                debug_log("New appointment created: parent_id=$id, new_date=$newDateStr, frequency=" . $appt['frequency']);
            } elseif ($status === 'scheduled' || (!in_array($status, ['missed', 'rescheduled']) && $hasChild)) {
                $pdo->prepare('DELETE FROM appointments WHERE parent_id = ? AND user_id = ? AND schedule_id = ? AND status = "scheduled"')
                    ->execute([$id, $displayUserId, $scheduleId]);
                debug_log("Child appointments deleted: parent_id=$id");
            }

            reschedulePastDue($pdo, $displayUserId, $scheduleId);
            $appointments = fetchAppointments($pdo, $displayUserId, $scheduleId);
            $summary = getAppointmentSummary($pdo, $displayUserId, $displayUsername, $scheduleId);
            debug_log("AJAX POST response prepared: appointments_count=" . count($appointments));
            echo json_encode(['success' => true, 'appointments' => $appointments, 'summary' => $summary, 'userId' => $userId, 'scheduleId' => $scheduleId]);
            exit;
        }
        if (isset($_POST['delete'])) {
            $id = (int)$_POST['id'];
            debug_log("Deleting appointment: id=$id, user_id=$displayUserId, schedule_id=$scheduleId");
            $pdo->prepare('DELETE FROM appointments WHERE id = ? AND user_id = ? AND schedule_id = ?')->execute([$id, $displayUserId, $scheduleId]);
            $pdo->prepare('DELETE FROM appointments WHERE parent_id = ? AND user_id = ? AND schedule_id = ?')->execute([$id, $displayUserId, $scheduleId]);

            reschedulePastDue($pdo, $displayUserId, $scheduleId);
            $appointments = fetchAppointments($pdo, $displayUserId, $scheduleId);
            $summary = getAppointmentSummary($pdo, $displayUserId, $displayUsername, $scheduleId);
            debug_log("Delete response prepared: appointments_count=" . count($appointments));
            echo json_encode(['success' => true, 'appointments' => $appointments, 'summary' => $summary, 'userId' => $userId, 'scheduleId' => $scheduleId]);
            exit;
        }
    } catch (Exception $e) {
        debug_log('AJAX POST error: ' . $e->getMessage() . ', trace: ' . $e->getTraceAsString());
        echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage()]);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['ajax']) && $displayUserId && $scheduleId) {
    header('Content-Type: application/json');
    debug_log("AJAX GET request received: user_id=$userId, display_user_id=$displayUserId, schedule_id=$scheduleId, session_id=" . session_id());
    try {
        $appointments = fetchAppointments($pdo, $displayUserId, $scheduleId);
        $summary = getAppointmentSummary($pdo, $displayUserId, $displayUsername, $scheduleId);
        echo json_encode(['success' => true, 'appointments' => $appointments, 'summary' => $summary, 'userId' => $userId, 'scheduleId' => $scheduleId]);
    } catch (Exception $e) {
        debug_log('AJAX GET error: ' . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Server error']);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clear_schedule']) && $userId && !$isReadOnly) {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed: user_id=$userId, action=clear_schedule");
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: /schedule.php?schedule_id=' . (int)$_POST['schedule_id']);
        exit;
    }

    try {
        $clearScheduleId = (int)$_POST['schedule_id'];
        $pdo->prepare('DELETE FROM appointments WHERE user_id = ? AND schedule_id = ?')->execute([$userId, $clearScheduleId]);
        debug_log("Appointments cleared: schedule_id=$clearScheduleId, user_id=$userId");
        $_SESSION['success'] = 'Appointments cleared successfully!';
        header('Location: /schedule.php?schedule_id=' . $clearScheduleId);
        exit;
    } catch (PDOException $e) {
        debug_log('Clear schedule error: ' . $e->getMessage());
        $_SESSION['error'] = 'Error clearing appointments.';
        header('Location: /schedule.php?schedule_id=' . $clearScheduleId);
        exit;
    }
}

function fetchAppointments($pdo, $userId, $scheduleId) {
    try {
        $stmt = $pdo->prepare('
            SELECT a.*, p.scheduled_date as parent_date 
            FROM appointments a 
            LEFT JOIN appointments p ON a.parent_id = p.id 
            WHERE a.user_id = ? AND a.schedule_id = ? 
            ORDER BY a.scheduled_date
        ');
        $stmt->execute([$userId, $scheduleId]);
        $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $childStmt = $pdo->prepare('
            SELECT parent_id, scheduled_date 
            FROM appointments 
            WHERE parent_id IN (
                SELECT id 
                FROM appointments 
                WHERE user_id = ? AND schedule_id = ? AND status IN ("rescheduled", "missed")
            ) AND user_id = ? AND schedule_id = ?
        ');
        $childStmt->execute([$userId, $scheduleId, $userId, $scheduleId]);
        $childDates = $childStmt->fetchAll(PDO::FETCH_KEY_PAIR);

        foreach ($appointments as &$appt) {
            $appt['display_date'] = DateTime::createFromFormat('Y-m-d', $appt['scheduled_date'])->format('m/d/Y');
            $appt['parent_display_date'] = $appt['parent_date'] ? 
                DateTime::createFromFormat('Y-m-d', $appt['parent_date'])->format('m/d/Y') : null;
            $appt['child_display_date'] = isset($childDates[$appt['id']]) ? 
                DateTime::createFromFormat('Y-m-d', $childDates[$appt['id']])->format('m/d/Y') : null;
        }
        unset($appt);
        return $appointments;
    } catch (PDOException $e) {
        debug_log('fetchAppointments error: ' . $e->getMessage());
        return [];
    }
}

if ($displayUserId && $scheduleId) {
    reschedulePastDue($pdo, $displayUserId, $scheduleId);
    $appointments = fetchAppointments($pdo, $displayUserId, $scheduleId);
    $summary = getAppointmentSummary($pdo, $displayUserId, $displayUsername, $scheduleId);
    debug_log("Rendering schedule: schedule_id=$scheduleId, user_id=$displayUserId, appointments_count=" . count($appointments));
} else {
    $appointments = [];
    $summary = null;
}

$isAdmin = $userId && isset($_SESSION['is_admin']) && $_SESSION['is_admin'] && !$isReadOnly;
?>

<?php include 'includes/header.php'; ?>
<div class="container">
    <h1>View Schedule</h1>

    <?php if (isset($_SESSION['success'])): ?>
        <div class="alert alert-success"><?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
    <?php endif; ?>
    <?php if (isset($_SESSION['error'])): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
    <?php endif; ?>

    <?php if (!$displayUserId || !$scheduleId): ?>
        <div class="alert alert-warning">Unable to load schedule. Please try again or contact support.</div>
    <?php else: ?>
        <div class="mb-4 d-flex flex-wrap gap-2" role="group">
            <?php if ($userId && !$isReadOnly): ?>
                <a href="/index.php" class="btn btn-secondary btn-uniform">Back to Schedules</a>
                <a href="/generate.php?schedule_id=<?php echo $scheduleId; ?>" class="btn btn-primary btn-uniform">Edit Schedule</a>
                <a href="/report.php?schedule_id=<?php echo $scheduleId; ?>" class="btn btn-info btn-uniform">Generate Report</a>
                <form method="POST" class="d-inline-block">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="schedule_id" value="<?php echo $scheduleId; ?>">
                    <button type="submit" name="clear_schedule" class="btn btn-danger btn-uniform">Clear Appointments</button>
                </form>
                <form method="POST" action="/logout.php" class="d-inline-block">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <button type="submit" name="logout" class="btn btn-danger btn-uniform">Logout</button>
                </form>
                <?php if ($isAdmin): ?>
                    <a href="/admin/index.php" class="btn btn-primary btn-uniform">Admin Panel</a>
                <?php endif; ?>
                <a href="/calendar.php?schedule_id=<?php echo $scheduleId; ?>" class="btn btn-info btn-uniform">Calendar View</a>
            <?php else: ?>
                <a href="/calendar.php?schedule_id=<?php echo $scheduleId; ?>" class="btn btn-info btn-uniform">Calendar View</a>
            <?php endif; ?>
        </div>

        <?php if ($userId && !$isReadOnly): ?>
            <div class="card shadow-sm p-3 mb-4">
                <div class="d-flex align-items-center">
                    <label for="scheduleSelect" class="form-label me-3 mb-0">Select Schedule:</label>
                    <select id="scheduleSelect" class="form-select w-auto">
                        <?php foreach ($schedules as $schedule): ?>
                            <option value="<?php echo $schedule['id']; ?>" <?php echo $schedule['id'] == $scheduleId ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($schedule['name']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <?php if (count($schedules) > 1): ?>
                        <form method="POST" class="ms-3">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <input type="hidden" name="schedule_id" value="<?php echo $scheduleId; ?>">
                            <button type="submit" name="delete_schedule" class="btn btn-danger btn-sm delete-schedule-btn">Delete Schedule</button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

        <div id="scheduleSection">
            <?php if ($summary && $summary['start_date']): ?>
                <div class="card shadow-sm p-4 mb-4 summary-card">
                    <h5>Appointment Summary for <?php echo htmlspecialchars($summary['username']); ?><?php echo $isReadOnly ? ' (Public View)' : ''; ?></h5>
                    <div class="row summary-row g-3">
                        <div class="col col-summary">
                            <div class="summary-box">
                                <strong>Start Date</strong>
                                <span><?php echo htmlspecialchars($summary['display_start_date']); ?></span>
                            </div>
                        </div>
                        <div class="col col-summary">
                            <div class="summary-box">
                                <strong>End Date</strong>
                                <span><?php echo htmlspecialchars($summary['display_end_date']); ?></span>
                            </div>
                        </div>
                        <div class="col col-summary">
                            <div class="summary-box">
                                <strong>Total</strong>
                                <span><?php echo (int)$summary['total']; ?></span>
                            </div>
                        </div>
                        <div class="col col-summary">
                            <div class="summary-box">
                                <strong>Remaining</strong>
                                <span><?php echo (int)$summary['remaining']; ?></span>
                            </div>
                        </div>
                        <div class="col col-summary">
                            <div class="summary-box">
                                <strong>Attended</strong>
                                <span><?php echo (int)$summary['attended']; ?></span>
                            </div>
                        </div>
                        <div class="col col-summary">
                            <div class="summary-box">
                                <strong>Missed</strong>
                                <span><?php echo (int)$summary['missed']; ?></span>
                            </div>
                        </div>
                        <div class="col col-summary">
                            <div class="summary-box">
                                <strong>Rescheduled</strong>
                                <span><?php echo (int)$summary['rescheduled']; ?></span>
                            </div>
                        </div>
                    </div>
                    <?php if ($userId && !$isReadOnly): ?>
                        <div class="token-section">
                            <div class="token-left">
                                <strong>Read-Only Token:</strong>
                                <?php
                                    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                                    $host = $_SERVER['HTTP_HOST'];
                                    $baseUrl = $protocol . '://' . $host . '/schedule.php';
                                    $fullUrl = $baseUrl . '?token=' . urlencode($summary['read_only_token']);
                                ?>
                                <a href="<?php echo htmlspecialchars($fullUrl); ?>" id="publicUrl"><?php echo htmlspecialchars($summary['read_only_token']); ?></a>
                            </div>
                            <div class="token-right">
                                <form method="POST" class="d-inline">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="schedule_id" value="<?php echo $scheduleId; ?>">
                                    <button type="submit" name="regenerate_token" class="btn btn-primary btn-sm">Regenerate</button>
                                </form>
                                <button id="copyUrlBtn" class="btn btn-warning btn-sm" data-url="<?php echo htmlspecialchars($fullUrl); ?>">Copy URL</button>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            <?php if ($appointments && $scheduleId): ?>
                <div class="card shadow-sm mb-4">
                    <div class="card-body p-0">
                        <table class="table table-bordered appointment-table">
                            <thead>
                                <tr>
                                    <th>Date</th>
                                    <th>Status</th>
                                    <?php if ($userId && !$isReadOnly): ?>
                                        <th>Actions</th>
                                    <?php endif; ?>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($appointments as $appt): ?>
                                    <tr data-id="<?php echo $appt['id']; ?>" 
                                        class="appointment-row status-<?php echo htmlspecialchars($appt['status']); ?>"
                                        style="background-color: <?php
                                            $bgColor = '#ffffff';
                                            switch (strtolower(trim($appt['status']))) {
                                                case 'scheduled': $bgColor = '#e7f3ff'; break;
                                                case 'attended': $bgColor = '#e6ffed'; break;
                                                case 'missed': $bgColor = '#ffe6e6'; break;
                                                case 'rescheduled': $bgColor = '#fffde7'; break;
                                            }
                                            echo $bgColor;
                                        ?>;">
                                        <td><?php echo htmlspecialchars($appt['display_date']); ?></td>
                                        <td><?php 
                                            echo htmlspecialchars(ucfirst($appt['status'])); 
                                            if (in_array(strtolower($appt['status']), ['rescheduled', 'missed']) && $appt['child_display_date']) {
                                                echo '<br>' . htmlspecialchars($appt['display_date']) . ' -> ' . htmlspecialchars($appt['child_display_date']);
                                            } elseif ($appt['parent_display_date']) {
                                                echo '<br>' . htmlspecialchars($appt['parent_display_date']) . ' -> ' . htmlspecialchars($appt['display_date']);
                                            }
                                        ?></td>
                                        <?php if ($userId && !$isReadOnly): ?>
                                            <td>
                                                <button class="btn btn-primary btn-sm status-btn" data-status="reschedule">Reschedule</button>
                                                <button class="btn btn-success btn-sm status-btn" data-status="attended">Attended</button>
                                                <button class="btn btn-danger btn-sm status-btn" data-status="missed">Missed</button>
                                                <button class="btn btn-secondary btn-sm status-btn" data-status="scheduled">Reset</button>
                                                <button class="btn btn-warning btn-sm delete-btn">Delete</button>
                                            </td>
                                        <?php endif; ?>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php else: ?>
                <div class="alert alert-info">
                    <?php if ($userId && !$isReadOnly): ?>
                        No appointments scheduled yet. <a href="/generate.php?schedule_id=<?php echo $scheduleId; ?>">Generate appointments</a> to get started.
                    <?php else: ?>
                        No appointments found for this schedule.
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

<style>
.container .appointment-table, 
.container .appointment-table tbody, 
.container .appointment-table tr, 
.container .appointment-table td {
    background: transparent !important;
}
.container .appointment-table tbody tr.appointment-row.status-scheduled {
    background-color: #e7f3ff !important;
}
.container .appointment-table tbody tr.appointment-row.status-attended {
    background-color: #e6ffed !important;
}
.container .appointment-table tbody tr.appointment-row.status-missed {
    background-color: #ffe6e6 !important;
}
.container .appointment-table tbody tr.appointment-row.status-rescheduled {
    background-color: #fffde7 !important;
}
.container .appointment-table tbody tr.appointment-row:hover {
    filter: brightness(95%);
}
.btn-uniform {
    min-width: 120px;
    padding: 8px 16px;
    text-align: center;
}
.d-flex.gap-2 form { margin: 0; }
.d-flex.gap-2 form button { width: 100%; }
.summary-card .summary-row { display: flex; flex-wrap: wrap; }
.summary-card .col-summary { 
    flex: 0 0 calc(100% / 7); 
    max-width: calc(100% / 7); 
    padding: 0 4px; 
}
.summary-card .summary-box { 
    background-color: #f9fafb; 
    border-radius: 6px; 
    padding: 10px; 
    text-align: center; 
}
.summary-card .summary-box strong { 
    font-size: 0.85rem; 
    font-weight: 500; 
    color: #555; 
    display: block; 
    margin-bottom: 4px; 
}
.summary-card .summary-box span { 
    font-size: 0.95rem; 
    font-weight: 600; 
    color: #222; 
}
.summary-card .token-section { 
    margin-top: 20px; 
    padding: 10px; 
    background-color: #f1f3f5; 
    border-radius: 6px; 
    display: flex; 
    justify-content: space-between; 
    align-items: center; 
    gap: 12px; 
    font-size: 0.9rem; 
}
.summary-card .token-section a { 
    color: #007bff; 
    text-decoration: none; 
}
.summary-card .token-section a:hover { 
    text-decoration: underline; 
}
@media (max-width: 992px) {
    .summary-card .col-summary { 
        flex: 0 0 50%; 
        max-width: 50%; 
    }
}
@media (max-width: 576px) {
    .summary-card .col-summary { 
        flex: 0 0 100%; 
        max-width: 100%; 
    }
    .summary-card .summary-box { 
        padding: 8px; 
    }
    .summary-card .summary-box strong { 
        font-size: 0.8rem; 
    }
    .summary-card .summary-box span { 
        font-size: 0.9rem; 
    }
}
</style>

<script nonce="<?php echo htmlspecialchars($nonce); ?>">
    window.scheduleCsrfToken = '<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? ''); ?>';
    window.scheduleId = <?php echo (int)$scheduleId; ?>;
    window.scheduleIsReadOnly = <?php echo json_encode($isReadOnly); ?>;
    console.log('schedule.php: CSRF token set in window: ' + window.scheduleCsrfToken);
    console.log('schedule.php: Session ID: ' + '<?php echo session_id(); ?>');
    console.log('schedule.php: Schedule ID: ' + window.scheduleId);
    console.log('schedule.php: Is Read Only: ' + window.scheduleIsReadOnly);
    document.addEventListener('DOMContentLoaded', () => {
        const statusButtons = document.querySelectorAll('.status-btn');
        console.log('schedule.php: Found status buttons on load: ' + statusButtons.length);
        statusButtons.forEach(btn => console.log('schedule.php: Status button', btn.dataset.status, btn.closest('tr')?.dataset.id));
        // Attach dropdown listener
        const scheduleSelect = document.getElementById('scheduleSelect');
        if (scheduleSelect) {
            scheduleSelect.addEventListener('change', function() {
                const newScheduleId = this.value;
                if (newScheduleId) {
                    window.location.href = '?schedule_id=' + encodeURIComponent(newScheduleId) + '&t=' + Date.now();
                }
            });
        }
    });
</script>
<script src="/js/schedule.js?t=<?php echo time(); ?>" nonce="<?php echo htmlspecialchars($nonce); ?>"></script>
<?php
debug_log("Page load: user_id=" . ($userId ?? 'none') . ", session_id=" . session_id() . ", csrf_token=" . ($_SESSION['csrf_token'] ?? 'none'));
?>
<?php include 'includes/footer.php'; ?>
