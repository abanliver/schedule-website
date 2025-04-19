<?php
// /var/www/schedule.permadomain.com/html/calendar.php
session_start();
require 'includes/db.php';
require 'includes/summary.php';
require 'includes/functions.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Debug session
debug_log("Raw session user_id: " . (isset($_SESSION['user_id']) ? $_SESSION['user_id'] : 'not set'));

// Basic rate-limiting for AJAX
$maxAjaxRequests = 100;
$ajaxLockoutTime = 3600; // 1 hour
if (!isset($_SESSION['ajax_requests'])) {
    $_SESSION['ajax_requests'] = 0;
    $_SESSION['last_ajax_request'] = time();
}

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$readOnlyToken = isset($_GET['token']) ? trim($_GET['token']) : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];
$displayUserId = null;
$displayUsername = null;
$scheduleId = null;

if (!$userId && !$isReadOnly && !$readOnlyToken) {
    debug_log("Access denied: no user_id, read_only session, or token provided");
    $_SESSION['error'] = "Please log in or provide a valid token to view the calendar.";
    header("Location: /login.php");
    exit;
}

try {
    if ($userId && !$isReadOnly) {
        // Authenticated user
        $stmt = $pdo->prepare("SELECT username, is_admin FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            $displayUserId = $userId;
            $displayUsername = $user['username'];
            $isAdmin = $user['is_admin'];
            $requestedScheduleId = isset($_GET['schedule_id']) ? (int)$_GET['schedule_id'] : null;
            if ($requestedScheduleId) {
                $stmt = $pdo->prepare("SELECT id FROM schedules WHERE user_id = ? AND id = ?");
                $stmt->execute([$userId, $requestedScheduleId]);
                $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($schedule) {
                    $scheduleId = $schedule['id'];
                } else {
                    debug_log("Invalid schedule ID: schedule_id=$requestedScheduleId, user_id=$userId");
                    $_SESSION['error'] = "The requested schedule does not exist or you lack permission.";
                    header("Location: /index.php");
                    exit;
                }
            } else {
                $stmt = $pdo->prepare("SELECT id FROM schedules WHERE user_id = ? ORDER BY created_at LIMIT 1");
                $stmt->execute([$userId]);
                $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($schedule) {
                    $scheduleId = $schedule['id'];
                } else {
                    debug_log("No schedules found for user_id=$userId");
                    $_SESSION['error'] = "You have no schedules to display.";
                    header("Location: /index.php");
                    exit;
                }
            }
            debug_log("Authenticated access: user_id=$displayUserId, schedule_id=$scheduleId, is_admin=" . ($isAdmin ? 'true' : 'false'));
        } else {
            debug_log("User not found: user_id=$userId");
            session_destroy();
            $_SESSION = [];
            $_SESSION['error'] = "Your account was not found. Please log in again.";
            header("Location: /login.php");
            exit;
        }
    } elseif ($isReadOnly || $readOnlyToken) {
        // Read-only access
        if ($readOnlyToken && !preg_match('/^[a-f0-9]{32}$/', $readOnlyToken)) {
            debug_log("Invalid read-only token format: token=" . substr(htmlspecialchars($readOnlyToken, ENT_QUOTES, 'UTF-8'), 0, 8) . "...");
            http_response_code(403);
            $_SESSION['error'] = "The read-only token format is invalid. It must be a 32-character hexadecimal string.";
            header("Location: /login.php");
            exit;
        }
        if ($isReadOnly && isset($_SESSION['read_only_schedule_id'])) {
            $scheduleId = (int)$_SESSION['read_only_schedule_id'];
        } elseif ($readOnlyToken) {
            $stmt = $pdo->prepare("SELECT s.id, s.name, u.id as user_id, u.username FROM schedules s JOIN users u ON s.user_id = u.id WHERE s.read_only_token = ?");
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
                $_SESSION['error'] = "The read-only token is invalid or has expired.";
                header("Location: /login.php");
                exit;
            }
        }

        if ($scheduleId) {
            $stmt = $pdo->prepare("SELECT s.id, s.name, u.id as user_id, u.username FROM schedules s JOIN users u ON s.user_id = u.id WHERE s.id = ?");
            $stmt->execute([$scheduleId]);
            $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($schedule) {
                $displayUserId = $schedule['user_id'];
                $displayUsername = $schedule['username'];
                unset($_SESSION['user_id']);
                unset($_SESSION['is_admin']);
                debug_log("Read-only access confirmed: schedule_id=$scheduleId, user_id=$displayUserId");
            } else {
                debug_log("Schedule not found: schedule_id=$scheduleId");
                unset($_SESSION['read_only'], $_SESSION['read_only_schedule_id'], $_SESSION['read_only_schedule_name']);
                $_SESSION['error'] = "The requested schedule was not found.";
                header("Location: /login.php");
                exit;
            }
        } else {
            debug_log("No schedule_id for read-only access");
            $_SESSION['error'] = "Invalid schedule access. Please provide a valid token.";
            header("Location: /login.php");
            exit;
        }
    }
} catch (PDOException $e) {
    debug_log("Database error: " . $e->getMessage());
    $_SESSION['error'] = "Unable to process request due to a database error. Please try again.";
    header("Location: /login.php");
    exit;
}

if ($_SERVER["REQUEST_METHOD"] === "GET" && isset($_GET["ajax"]) && $_GET["ajax"] === "calendar" && $displayUserId && $scheduleId) {
    // Rate-limiting check
    if ($_SESSION['ajax_requests'] >= $maxAjaxRequests && (time() - $_SESSION['last_ajax_request']) < $ajaxLockoutTime) {
        debug_log("AJAX rate limit exceeded: user_id=" . ($userId ?? 'null') . ", schedule_id=$scheduleId");
        http_response_code(429);
        header("Content-Type: application/json");
        echo json_encode(["error" => "Too many requests. Please try again later."]);
        exit;
    }
    $_SESSION['ajax_requests']++;
    $_SESSION['last_ajax_request'] = time();

    header("Content-Type: application/json");
    try {
        if ($isReadOnly && $_SESSION['read_only_schedule_id'] != $scheduleId) {
            debug_log("Read-only access denied: schedule_id=$scheduleId does not match read_only_schedule_id=" . ($_SESSION['read_only_schedule_id'] ?? 'null'));
            http_response_code(403);
            echo json_encode(["error" => "Unauthorized schedule access."]);
            exit;
        }
        // Fetch appointments within a reasonable date range
        $stmt = $pdo->prepare("
            SELECT id, scheduled_date, status, frequency 
            FROM appointments 
            WHERE user_id = ? AND schedule_id = ? 
            AND scheduled_date BETWEEN DATE_SUB(CURDATE(), INTERVAL 1 YEAR) AND DATE_ADD(CURDATE(), INTERVAL 5 YEAR)
        ");
        $stmt->execute([$displayUserId, $scheduleId]);
        $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);

        debug_log("Fetched " . count($appointments) . " appointments for user $displayUserId, schedule $scheduleId");

        $events = [];
        foreach ($appointments as $appt) {
            if (!empty($appt["scheduled_date"]) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $appt["scheduled_date"])) {
                $events[] = [
                    "id" => $appt["id"],
                    "title" => ucfirst($appt["status"]) . " Appointment",
                    "start" => $appt["scheduled_date"],
                    "classNames" => ["status-" . strtolower(trim($appt["status"]))],
                    "extendedProps" => [
                        "status" => $appt["status"],
                        "frequency" => $appt["frequency"]
                    ]
                ];
            } else {
                debug_log("Skipping appointment ID {$appt['id']} due to invalid or empty scheduled_date: " . ($appt["scheduled_date"] ?? 'null'));
            }
        }
        $_SESSION['ajax_requests'] = 0; // Reset on successful fetch
        echo json_encode($events);
        exit;
    } catch (Exception $e) {
        debug_log("Error in calendar AJAX: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(["error" => "Failed to load calendar events. Please try again."]);
        exit;
    }
}

$isAdmin = $userId && isset($_SESSION["is_admin"]) && $_SESSION["is_admin"] && !$isReadOnly;
?>

<?php include 'includes/header.php'; ?>
<style>
    .calendar-container {
        max-width: 1100px;
        margin: 3rem auto;
        padding: 2.5rem;
        background: linear-gradient(135deg, #ffffff, #f8f9fa);
        border-radius: 15px;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
        transition: transform 0.3s ease;
    }
    .calendar-container:hover {
        transform: translateY(-5px);
    }
    .calendar-container h1 {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1a3c66;
        text-align: center;
        margin-bottom: 2rem;
    }
    #calendar {
        padding: 20px;
    }
    .fc-event, .fc-event-title, .fc-daygrid-event {
        color: #000000 !important;
        cursor: pointer;
        padding: 2px 5px;
        font-size: 0.9em;
    }
    .fc-event.status-scheduled {
        background-color: #e7f3ff !important;
        border-color: #b3d7ff !important;
    }
    .fc-event.status-attended {
        background-color: #e6ffed !important;
        border-color: #b3ffcc !important;
    }
    .fc-event.status-missed {
        background-color: #ffe6e6 !important;
        border-color: #ffb3b3 !important;
    }
    .fc-event.status-rescheduled {
        background-color: #fffde7 !important;
        border-color: #fff9b3 !important;
    }
    .btn-uniform {
        min-width: 120px;
        padding: 8px 16px;
        text-align: center;
    }
    .btn-primary, .btn-secondary, .btn-success, .btn-info, .btn-danger {
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
    .btn-success {
        background-color: #28a745;
        border: none;
    }
    .btn-success:hover {
        background-color: #218838;
        transform: translateY(-2px);
    }
    .btn-info {
        background-color: #17a2b8;
        border: none;
    }
    .btn-info:hover {
        background-color: #138496;
        transform: translateY(-2px);
    }
    .btn-danger {
        background-color: #dc3545;
        border: none;
    }
    .btn-danger:hover {
        background-color: #c82333;
        transform: translateY(-2px);
    }
    .d-flex.gap-2 form { margin: 0; }
    .d-flex.gap-2 form button { width: 100%; }
    .alert {
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1.5rem;
        font-size: 0.95rem;
    }
    @media (max-width: 768px) {
        .calendar-container {
            margin: 1.5rem;
            padding: 1.5rem;
        }
        .calendar-container h1 {
            font-size: 1.8rem;
        }
        .btn-uniform {
            min-width: 100px;
            font-size: 0.9rem;
        }
    }
    /* Improved Print-specific styles */
    @media print {
        @page {
            size: A4;
            margin: 15mm 10mm;
        }
        body {
            margin: 0;
            padding: 0;
            background: #fff;
            color: #000;
            font-family: Arial, sans-serif;
            font-size: 10pt;
        }
        .calendar-container, .container {
            margin: 0;
            padding: 0;
            box-shadow: none;
            background: none;
            transform: none;
            width: 100%;
            max-width: none;
        }
        #calendar {
            position: static;
            width: 100%;
            margin: 0;
            padding: 5mm;
        }
        .fc, .fc-media-screen, .fc-direction-ltr, .fc-theme-standard {
            width: 100% !important;
            height: auto !important;
        }
        .fc-daygrid-day {
            width: 14.28% !important; /* 7 days */
            height: 25mm !important;
            box-sizing: border-box;
            page-break-inside: avoid;
        }
        .fc-daygrid-day-frame {
            height: 100% !important;
            overflow: hidden;
        }
        .fc-daygrid-day-top {
            font-size: 8pt !important;
            font-weight: bold;
        }
        .fc-daygrid-day-events {
            font-size: 7pt !important;
        }
        .fc-event, .fc-event-main, .fc-event-title {
            background: none !important;
            border: 0.5pt solid #000 !important;
            color: #000 !important;
            padding: 1mm !important;
            margin: 0.5mm !important;
            font-size: 7pt !important;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: normal;
        }
        .fc-header-toolbar {
            display: none !important;
        }
        .fc-daygrid-day-bg, .fc-scroller {
            background: none !important;
        }
        .fc-daygrid-day-number {
            color: #000 !important;
        }
        /* Hide non-essential elements */
        .navbar, .btn, .alert, h1, footer, .no-print, .fc-button-group {
            display: none !important;
        }
        /* Ensure no page breaks within days */
        .fc-daygrid-day {
            break-inside: avoid;
        }
        /* Add calendar title */
        #calendar::before {
            content: "<?php echo htmlspecialchars($_SESSION['read_only_schedule_name'] ?? 'Calendar for ' . $displayUsername, ENT_QUOTES, 'UTF-8'); ?>";
            display: block;
            font-size: 12pt;
            font-weight: bold;
            text-align: center;
            margin-bottom: 5mm;
        }
    }
</style>

<div class="container my-5">
    <div class="calendar-container">
        <h1>Calendar View</h1>

        <?php if (isset($_SESSION['success'])): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
        <?php endif; ?>
        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <?php if ($displayUserId && $scheduleId): ?>
            <div class="mb-4 d-flex flex-wrap gap-2" role="group">
                <a href="/schedule.php?schedule_id=<?php echo $scheduleId; ?>" 
                   class="btn btn-secondary btn-uniform">Table View</a>
                <?php if ($userId && !$isReadOnly): ?>
                    <a href="/index.php" class="btn btn-info btn-uniform">Back to Schedules</a>
                    <a href="/generate.php?schedule_id=<?php echo $scheduleId; ?>" class="btn btn-primary btn-uniform">Edit Schedule</a>
                    <a href="/report.php?schedule_id=<?php echo $scheduleId; ?>" class="btn btn-info btn-uniform">Generate Report</a>
                    <form method="POST" action="/logout.php" class="d-inline-block">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <button type="submit" name="logout" class="btn btn-danger btn-uniform">Logout</button>
                    </form>
                    <?php if ($isAdmin): ?>
                        <a href="/admin/index.php" class="btn btn-primary btn-uniform">Admin Panel</a>
                    <?php endif; ?>
                <?php endif; ?>
                <button id="printCalendar" class="btn btn-success btn-uniform no-print">Print Calendar</button>
            </div>

            <div id="calendar"></div>
        <?php else: ?>
            <div class="alert alert-info">No appointments available.</div>
        <?php endif; ?>
    </div>
</div>

<script src="/assets/main.min.js"></script>
<script nonce="<?php echo htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8'); ?>">
document.addEventListener('DOMContentLoaded', function() {
    if (typeof FullCalendar === 'undefined') {
        console.error('FullCalendar is not defined.');
        document.getElementById('calendar').innerHTML = '<div class="alert alert-danger">Error: Calendar library failed to load. Please try refreshing or contact support.</div>';
        return;
    }

    var calendarEl = document.getElementById('calendar');
    if (!calendarEl) {
        console.error('Calendar element not found');
        document.body.insertAdjacentHTML('beforeend', '<div class="alert alert-danger">Error: Calendar container not found.</div>');
        return;
    }

    var calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,timeGridWeek,timeGridDay'
        },
        events: function(fetchInfo, successCallback, failureCallback) {
            fetch('/calendar.php?ajax=calendar&schedule_id=<?php echo $scheduleId; ?>')
                .then(response => {
                    if (!response.ok) throw new Error('HTTP error ' + response.status);
                    return response.json();
                })
                .then(data => {
                    if (data.length === 0) {
                        document.getElementById('calendar').insertAdjacentHTML('afterend', '<div class="alert alert-info">No appointments found.</div>');
                    }
                    successCallback(data);
                })
                .catch(error => {
                    console.error('Error fetching events:', error);
                    failureCallback(error);
                    document.getElementById('calendar').innerHTML = '<div class="alert alert-warning">Failed to load events. Please try again.</div>';
                });
        },
        eventClick: function(info) {
            alert('Event: ' + info.event.title + '\nDate: ' + info.event.start.toLocaleDateString() + '\nStatus: ' + info.event.extendedProps.status);
        },
        eventClassNames: function(arg) {
            return ['status-' + arg.event.extendedProps.status.toLowerCase()];
        }
    });

    try {
        calendar.render();
    } catch (e) {
        console.error('Error rendering calendar:', e);
        document.getElementById('calendar').innerHTML = '<div class="alert alert-danger">Error rendering calendar: ' + e.message + '</div>';
    }

    // Add event listener for print button
    var printButton = document.getElementById('printCalendar');
    if (printButton) {
        printButton.addEventListener('click', function() {
            window.print();
        });
    }
});
</script>

<?php include 'includes/footer.php'; ?>
