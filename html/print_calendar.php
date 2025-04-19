<?php
// /var/www/schedule.permadomain.com/html/print_calendar.php
session_start();
require 'includes/db.php';
require 'includes/functions.php';

ini_set('display_errors', 0);
error_reporting(E_ALL);

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$scheduleId = isset($_GET['schedule_id']) ? (int)$_GET['schedule_id'] : null;
$month = isset($_GET['month']) ? (int)$_GET['month'] : (int)date('m');
$year = isset($_GET['year']) ? (int)$_GET['year'] : (int)date('Y');

if (!$userId || !$scheduleId) {
    $_SESSION['error'] = 'Please log in and select a schedule.';
    header('Location: /login.php');
    exit;
}

// Validate month/year
if ($month < 1 || $month > 12) $month = (int)date('m');
if ($year < 1970 || $year > 9999) $year = (int)date('Y');

// Fetch schedule and appointments
try {
    $stmt = $pdo->prepare('SELECT name FROM schedules WHERE id = ? AND user_id = ?');
    $stmt->execute([$scheduleId, $userId]);
    $schedule = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$schedule) {
        $_SESSION['error'] = 'Invalid schedule.';
        header('Location: /index.php');
        exit;
    }
    $startDate = "$year-$month-01";
    $endDate = date('Y-m-t', strtotime($startDate));
    $stmt = $pdo->prepare('SELECT scheduled_date, status FROM appointments WHERE user_id = ? AND schedule_id = ? AND scheduled_date BETWEEN ? AND ?');
    $stmt->execute([$userId, $scheduleId, "$startDate 00:00:00", "$endDate 23:59:59"]);
    $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $eventsByDay = [];
    foreach ($appointments as $appt) {
        $day = (int)date('j', strtotime($appt['scheduled_date']));
        $eventsByDay[$day][] = $appt;
    }
} catch (PDOException $e) {
    debug_log("Print calendar error: " . $e->getMessage());
    $_SESSION['error'] = 'Unable to generate calendar.';
    header('Location: /calendar.php?schedule_id=' . $scheduleId);
    exit;
}

// Calendar data
$firstDay = new DateTime("$year-$month-01");
$daysInMonth = (int)$firstDay->format('t');
$firstDayOfWeek = (int)$firstDay->format('N') - 1; // 0 (Mon) to 6 (Sun)
$weeks = ceil(($daysInMonth + $firstDayOfWeek) / 7);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Print Calendar - <?php echo htmlspecialchars($schedule['name']); ?></title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
            font-size: 10pt;
            color: #000;
        }
        .print-container {
            width: 190mm;
            margin: 15mm auto;
            padding: 0;
        }
        h1 {
            font-size: 14pt;
            text-align: center;
            margin-bottom: 10mm;
        }
        .calendar-table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }
        .calendar-table th, .calendar-table td {
            border: 0.5pt solid #000;
            padding: 2mm;
            text-align: left;
            vertical-align: top;
            height: 25mm;
            box-sizing: border-box;
        }
        .calendar-table th {
            background: #eee;
            font-weight: bold;
            text-align: center;
        }
        .calendar-table td.empty {
            background: #f5f5f5;
        }
        .event {
            font-size: 7pt;
            margin: 1mm;
            padding: 1mm;
            border-left: 2pt solid #000;
        }
        @page {
            size: A4;
            margin: 15mm 10mm;
        }
        @media print {
            body {
                margin: 0;
                padding: 0;
            }
            .print-container {
                margin: 0 auto;
            }
            .no-print {
                display: none !important;
            }
        }
    </style>
</head>
<body onload="window.print()">
    <div class="print-container">
        <h1><?php echo htmlspecialchars($schedule['name']); ?> - <?php echo date('F Y', strtotime("$year-$month-01")); ?></h1>
        <table class="calendar-table">
            <thead>
                <tr>
                    <th>Mon</th><th>Tue</th><th>Wed</th><th>Thu</th><th>Fri</th><th>Sat</th><th>Sun</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $day = 1;
                for ($week = 0; $week < $weeks; $week++): ?>
                    <tr>
                        <?php for ($dow = 0; $dow < 7; $dow++): ?>
                            <?php
                            $cellDay = $week * 7 + $dow - $firstDayOfWeek + 1;
                            $isEmpty = $cellDay < 1 || $cellDay > $daysInMonth;
                            ?>
                            <td class="<?php echo $isEmpty ? 'empty' : ''; ?>">
                                <?php if (!$isEmpty): ?>
                                    <div><?php echo $cellDay; ?></div>
                                    <?php if (isset($eventsByDay[$cellDay])): ?>
                                        <?php foreach ($eventsByDay[$cellDay] as $event): ?>
                                            <div class="event"><?php echo htmlspecialchars(ucfirst($event['status']) . ' Appointment'); ?></div>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </td>
                        <?php endfor; ?>
                    </tr>
                <?php endfor; ?>
            </tbody>
        </table>
        <button class="no-print" onclick="window.print()">Print</button>
    </div>
</body>
</html>
