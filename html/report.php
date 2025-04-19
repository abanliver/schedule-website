<?php
// /var/www/schedule.permadomain.com/html/report.php
session_start();
require 'includes/db.php';
require 'includes/summary.php';
require 'includes/functions.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Basic rate-limiting for report generation
$maxAttempts = 10;
$lockoutTime = 600; // 10 minutes
if (!isset($_SESSION['report_attempts'])) {
    $_SESSION['report_attempts'] = 0;
    $_SESSION['last_report_attempt'] = time();
}

if ($_SESSION['report_attempts'] >= $maxAttempts && (time() - $_SESSION['last_report_attempt']) < $lockoutTime) {
    $_SESSION['error'] = 'Too many report generation attempts. Please try again in ' . ceil(($lockoutTime - (time() - $_SESSION['last_report_attempt'])) / 60) . ' minutes.';
    header('Location: /schedule.php?schedule_id=' . (isset($_GET['schedule_id']) ? (int)$_GET['schedule_id'] : 0));
    exit;
}

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$readOnlyToken = isset($_GET['token']) ? trim($_GET['token']) : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];
$displayUserId = null;
$displayUsername = null;
$scheduleId = isset($_GET['schedule_id']) ? (int)$_GET['schedule_id'] : null;

if (!$userId && !$isReadOnly && !$readOnlyToken) {
    debug_log("Access denied: no user_id, read_only session, or token provided");
    $_SESSION['error'] = 'Please log in or provide a valid token to generate the report.';
    header('Location: /login.php');
    exit;
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
        } else {
            debug_log("User not found: user_id=$userId");
            session_destroy();
            $_SESSION = [];
            $_SESSION['error'] = 'Your account was not found. Please log in again.';
            header('Location: /login.php');
            exit;
        }

        // Validate schedule for authenticated user
        if ($scheduleId) {
            $stmt = $pdo->prepare('SELECT id, name FROM schedules WHERE user_id = ? AND id = ?');
            $stmt->execute([$userId, $scheduleId]);
            $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$schedule) {
                debug_log("Invalid schedule: user_id=$userId, schedule_id=$scheduleId");
                $_SESSION['error'] = 'The requested schedule does not exist or you lack permission.';
                header('Location: /index.php');
                exit;
            }
            $scheduleName = $schedule['name'];
        } else {
            debug_log("Missing schedule_id: user_id=$userId");
            $_SESSION['error'] = 'No schedule specified for the report.';
            header('Location: /index.php');
            exit;
        }
        debug_log("Authenticated access: user_id=$displayUserId, schedule_id=$scheduleId");
    } elseif ($isReadOnly || $readOnlyToken) {
        // Read-only access
        if ($readOnlyToken && !preg_match('/^[a-f0-9]{32}$/', $readOnlyToken)) {
            debug_log("Invalid read-only token format: token=" . substr(htmlspecialchars($readOnlyToken, ENT_QUOTES, 'UTF-8'), 0, 8) . "...");
            http_response_code(403);
            $_SESSION['error'] = 'The read-only token format is invalid. It must be a 32-character hexadecimal string.';
            header('Location: /login.php');
            exit;
        }
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
                debug_log("Read-only access granted via token: schedule_id=$scheduleId, token=" . substr(htmlspecialchars($readOnlyToken, ENT_QUOTES, 'UTF-8'), 0, 8) . "...");
            } else {
                debug_log("Invalid read-only token: token=" . substr(htmlspecialchars($readOnlyToken, ENT_QUOTES, 'UTF-8'), 0, 8) . "...");
                http_response_code(403);
                $_SESSION['error'] = 'The read-only token is invalid or has expired.';
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
                $scheduleName = $schedule['name'];
                unset($_SESSION['user_id'], $_SESSION['is_admin']);
                debug_log("Read-only access confirmed: schedule_id=$scheduleId, user_id=$displayUserId");
            } else {
                debug_log("Schedule not found: schedule_id=$scheduleId");
                unset($_SESSION['read_only'], $_SESSION['read_only_schedule_id'], $_SESSION['read_only_schedule_name']);
                $_SESSION['error'] = 'The requested schedule was not found.';
                header('Location: /login.php');
                exit;
            }
        } else {
            debug_log("No schedule_id for read-only access");
            $_SESSION['error'] = 'Invalid schedule access. Please provide a valid token.';
            header('Location: /login.php');
            exit;
        }
    }
} catch (PDOException $e) {
    debug_log("Database error: " . $e->getMessage());
    $_SESSION['error'] = 'Unable to process request due to a database error. Please try again.';
    header('Location: /login.php');
    exit;
}

// Fetch appointments
function fetchAppointments($pdo, $userId, $scheduleId) {
    try {
        $stmt = $pdo->prepare('
            SELECT a.*, p.scheduled_date as parent_date 
            FROM appointments a 
            LEFT JOIN appointments p ON a.parent_id = p.id 
            WHERE a.user_id = ? AND a.schedule_id = ? 
            AND a.scheduled_date BETWEEN DATE_SUB(CURDATE(), INTERVAL 1 YEAR) AND DATE_ADD(CURDATE(), INTERVAL 5 YEAR)
            ORDER BY a.scheduled_date
        ');
        $stmt->execute([$userId, $scheduleId]);
        $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($appointments as &$appt) {
            if (!empty($appt['scheduled_date']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $appt['scheduled_date'])) {
                $appt['display_date'] = DateTime::createFromFormat('Y-m-d', $appt['scheduled_date'])->format('m/d/Y');
            } else {
                debug_log("Invalid scheduled_date for appointment ID {$appt['id']}: " . ($appt['scheduled_date'] ?? 'null'));
                $appt['display_date'] = 'Invalid';
            }
            if ($appt['parent_date'] && preg_match('/^\d{4}-\d{2}-\d{2}$/', $appt['parent_date'])) {
                $appt['parent_display_date'] = DateTime::createFromFormat('Y-m-d', $appt['parent_date'])->format('m/d/Y');
            } else {
                $appt['parent_display_date'] = 'N/A';
            }
            $appt['frequency'] = $appt['frequency'] ?? 'N/A';
        }
        unset($appt);
        debug_log("Fetched " . count($appointments) . " appointments for user=$userId, schedule=$scheduleId");
        return $appointments;
    } catch (Exception $e) {
        debug_log("fetchAppointments error: " . $e->getMessage());
        return [];
    }
}

$_SESSION['report_attempts']++;
$_SESSION['last_report_attempt'] = time();

$appointments = fetchAppointments($pdo, $displayUserId, $scheduleId);
$summary = getAppointmentSummary($pdo, $displayUserId, $displayUsername, $scheduleId);

if (!$appointments || !$summary) {
    debug_log("No data: appointments=" . count($appointments) . ", summary=" . ($summary ? 'set' : 'unset'));
    $_SESSION['error'] = 'No data available to generate the report.';
    header('Location: /schedule.php?schedule_id=' . $scheduleId);
    exit;
}

// Generate text file
try {
    // Build content
    $content = "Appointment Report\n";
    $content .= "=================\n\n";
    $content .= "User: " . htmlspecialchars($displayUsername, ENT_QUOTES, 'UTF-8') . "\n";
    $content .= "Schedule: " . htmlspecialchars($scheduleName, ENT_QUOTES, 'UTF-8') . "\n\n";
    $content .= "Summary:\n";
    $content .= "  Start Date: " . htmlspecialchars($summary['display_start_date'], ENT_QUOTES, 'UTF-8') . "\n";
    $content .= "  End Date: " . htmlspecialchars($summary['display_end_date'], ENT_QUOTES, 'UTF-8') . "\n";
    $content .= "  Total: " . (int)$summary['total'] . "\n";
    $content .= "  Remaining: " . (int)$summary['remaining'] . "\n";
    $content .= "  Attended: " . (int)$summary['attended'] . "\n";
    $content .= "  Missed: " . (int)$summary['missed'] . "\n";
    $content .= "  Rescheduled: " . (int)$summary['rescheduled'] . "\n\n";
    $content .= "Appointments:\n";
    $content .= str_pad("Date", 12) . str_pad("Status", 12) . str_pad("Frequency", 12) . "Parent Date\n";
    $content .= str_repeat("-", 48) . "\n";

    foreach ($appointments as $appt) {
        $content .= str_pad($appt['display_date'], 12) . 
                    str_pad(ucfirst($appt['status']), 12) . 
                    str_pad(ucfirst($appt['frequency']), 12) . 
                    $appt['parent_display_date'] . "\n";
    }

    // Sanitize filename
    $filename = 'report_schedule_' . $scheduleId . '_' . date('YmdHis') . '.txt';
    $filename = preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $filename);
    if (strlen($filename) > 255) {
        $filename = substr($filename, 0, 255);
    }

    // Set headers
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($content));
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');

    debug_log("Generating text file: $filename");
    $_SESSION['report_attempts'] = 0; // Reset on success
    echo $content;
    exit;

} catch (Exception $e) {
    debug_log("Text file generation error: " . $e->getMessage());
    $_SESSION['error'] = 'Failed to generate the report. Please try again.';
    header('Location: /schedule.php?schedule_id=' . $scheduleId);
    exit;
}
