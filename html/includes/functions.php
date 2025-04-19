<?php
// /var/www/schedule.permadomain.com/html/includes/functions.php

// Prevent redefinition of functions
if (!function_exists('debug_log')) {
    function debug_log($message) {
        $logFile = '/var/www/schedule.permadomain.com/logs/debug.log';
        $timestamp = date('Y-m-d H:i:s');
        $logMessage = "[$timestamp] $message\n";
        
        try {
            // Check if debug logging is enabled
            $debugEnabled = get_setting('debug_logging_enabled');
            if ($debugEnabled !== '1') {
                return;
            }
            
            // Ensure the log directory exists
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                mkdir($logDir, 0755, true);
            }
            
            // Write to log file with error handling
            if (is_writable($logDir)) {
                file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
            } else {
                error_log("Debug log not writable: $logFile");
            }
        } catch (Exception $e) {
            error_log("Error writing to debug log: " . $e->getMessage());
        }
    }
}

if (!function_exists('get_setting')) {
    function get_setting($key = null) {
        static $cache = null;
        global $pdo;
        
        if ($cache === null) {
            // Check if $pdo is initialized
            if (!$pdo) {
                error_log("PDO connection is null in get_setting()");
                // Fallback defaults
                $cache = [
                    'session_timeout' => '1800',
                    'allow_stay_logged_in' => '1',
                    'session_regeneration_interval' => '3600',
                    'session_creation_max_attempts' => '15',
                    'session_creation_lockout_time' => '600',
                    'login_max_attempts' => '5',
                    'login_lockout_time' => '300',
                    'debug_logging_enabled' => '1'
                ];
                return $key ? ($cache[$key] ?? null) : $cache;
            }
            
            try {
                $stmt = $pdo->query('SELECT setting_key, setting_value FROM settings');
                $cache = [];
                while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                    $cache[$row['setting_key']] = $row['setting_value'];
                }
            } catch (PDOException $e) {
                error_log("Error fetching settings: " . $e->getMessage());
                // Fallback defaults
                $cache = [
                    'session_timeout' => '1800',
                    'allow_stay_logged_in' => '1',
                    'session_regeneration_interval' => '3600',
                    'session_creation_max_attempts' => '15',
                    'session_creation_lockout_time' => '600',
                    'login_max_attempts' => '5',
                    'login_lockout_time' => '300',
                    'debug_logging_enabled' => '1'
                ];
            }
        }
        
        return $key ? ($cache[$key] ?? null) : $cache;
    }
}
