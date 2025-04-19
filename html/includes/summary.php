<?php
// /var/www/schedule.permadomain.com/html/includes/summary.php

// Only start session if not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'db.php'; // Includes functions.php and provides $pdo

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

function getAppointmentSummary($pdo, $userId, $username, $scheduleId) {
    // Validate inputs
    if (!is_int($userId) || $userId <= 0 || !is_int($scheduleId) || $scheduleId <= 0) {
        debug_log("Invalid input: user_id=$userId, schedule_id=$scheduleId, username=" . ($username ?: 'null'));
        return [
            'username' => $username ?: '',
            'start_date' => null,
            'end_date' => null,
            'display_start_date' => 'N/A',
            'display_end_date' => 'N/A',
            'total' => 0,
            'remaining' => 0,
            'attended' => 0,
            'missed' => 0,
            'rescheduled' => 0,
            'read_only_token' => ''
        ];
    }

    try {
        debug_log("Fetching appointment summary: user_id=$userId, schedule_id=$scheduleId, username=$username");
        $stmt = $pdo->prepare('
            SELECT 
                MIN(scheduled_date) as start_date,
                MAX(scheduled_date) as end_date,
                COUNT(*) as total,
                SUM(CASE WHEN status = "scheduled" AND scheduled_date >= CURDATE() THEN 1 ELSE 0 END) as remaining,
                SUM(CASE WHEN status = "attended" THEN 1 ELSE 0 END) as attended,
                SUM(CASE WHEN status = "missed" THEN 1 ELSE 0 END) as missed,
                SUM(CASE WHEN status = "rescheduled" THEN 1 ELSE 0 END) as rescheduled
            FROM appointments 
            WHERE user_id = ? AND schedule_id = ?
        ');
        $stmt->execute([$userId, $scheduleId]);
        $summary = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($summary['start_date']) {
            $summary['display_start_date'] = DateTime::createFromFormat('Y-m-d', $summary['start_date'])->format('m/d/Y');
            $summary['display_end_date'] = DateTime::createFromFormat('Y-m-d', $summary['end_date'])->format('m/d/Y');
        } else {
            $summary['display_start_date'] = 'N/A';
            $summary['display_end_date'] = 'N/A';
        }

        $summary['username'] = $username ?: '';

        $stmt = $pdo->prepare('SELECT read_only_token FROM schedules WHERE id = ? AND user_id = ?');
        $stmt->execute([$scheduleId, $userId]);
        $tokenResult = $stmt->fetch(PDO::FETCH_ASSOC);
        $summary['read_only_token'] = $tokenResult['read_only_token'] ?? '';

        debug_log("Appointment summary fetched: user_id=$userId, schedule_id=$scheduleId, total={$summary['total']}, remaining={$summary['remaining']}");
        return $summary;
    } catch (PDOException $e) {
        debug_log("Error fetching appointment summary: user_id=$userId, schedule_id=$scheduleId, error=" . $e->getMessage());
        error_log("Error fetching appointment summary: user_id=$userId, schedule_id=$scheduleId, error=" . $e->getMessage());
        return [
            'username' => $username ?: '',
            'start_date' => null,
            'end_date' => null,
            'display_start_date' => 'N/A',
            'display_end_date' => 'N/A',
            'total' => 0,
            'remaining' => 0,
            'attended' => 0,
            'missed' => 0,
            'rescheduled' => 0,
            'read_only_token' => ''
        ];
    }
}
