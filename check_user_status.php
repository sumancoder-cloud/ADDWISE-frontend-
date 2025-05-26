<?php
require_once 'config.php';

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

// Get email from command line argument
$email = isset($argv[1]) ? $argv[1] : null;

if ($email) {
    echo "Checking status for email: " . htmlspecialchars($email) . "\n\n";
    
    // Query user status
    $sql = "SELECT id, email, status, email_verified, created_at FROM users WHERE email = ?";
    $stmt = mysqli_prepare($conn, $sql);
    if (!$stmt) {
        echo "Error preparing user query: " . mysqli_error($conn) . "\n";
        exit;
    }
    
    mysqli_stmt_bind_param($stmt, "s", $email);
    if (!mysqli_stmt_execute($stmt)) {
        echo "Error executing user query: " . mysqli_stmt_error($stmt) . "\n";
        exit;
    }
    
    $result = mysqli_stmt_get_result($stmt);
    if (!$result) {
        echo "Error getting user result: " . mysqli_error($conn) . "\n";
        exit;
    }
    
    if ($user = mysqli_fetch_assoc($result)) {
        echo "User Status:\n";
        echo "ID: " . htmlspecialchars($user['id']) . "\n";
        echo "Email: " . htmlspecialchars($user['email']) . "\n";
        echo "Status: " . (isset($user['status']) ? htmlspecialchars($user['status']) : 'Not set') . "\n";
        echo "Email Verified: " . (isset($user['email_verified']) ? ($user['email_verified'] ? 'Yes' : 'No') : 'Not set') . "\n";
        echo "Created At: " . htmlspecialchars($user['created_at']) . "\n";
        
        // Check OTP verification status
        $sql = "SELECT purpose, created_at, is_used FROM otp_verification 
                WHERE email = ? AND purpose = 'registration' 
                ORDER BY created_at DESC LIMIT 1";
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            echo "\nError preparing OTP query: " . mysqli_error($conn) . "\n";
            exit;
        }
        
        mysqli_stmt_bind_param($stmt, "s", $email);
        if (!mysqli_stmt_execute($stmt)) {
            echo "\nError executing OTP query: " . mysqli_stmt_error($stmt) . "\n";
            exit;
        }
        
        $otp_result = mysqli_stmt_get_result($stmt);
        if (!$otp_result) {
            echo "\nError getting OTP result: " . mysqli_error($conn) . "\n";
            exit;
        }
        
        if ($otp = mysqli_fetch_assoc($otp_result)) {
            echo "\nLast OTP Verification:\n";
            echo "Purpose: " . htmlspecialchars($otp['purpose']) . "\n";
            echo "Created At: " . htmlspecialchars($otp['created_at']) . "\n";
            echo "Used: " . ($otp['is_used'] ? 'Yes' : 'No') . "\n";
        } else {
            echo "\nNo OTP verification records found.\n";
        }
        
        // If status is not active but OTP is verified, try to fix the status
        if ((!isset($user['status']) || $user['status'] !== 'active') && $otp['is_used']) {
            echo "\nAttempting to fix account status...\n";
            $update_sql = "UPDATE users SET status = 'active', email_verified = TRUE WHERE email = ?";
            $update_stmt = mysqli_prepare($conn, $update_sql);
            if ($update_stmt) {
                mysqli_stmt_bind_param($update_stmt, "s", $email);
                if (mysqli_stmt_execute($update_stmt)) {
                    echo "Account status updated to active.\n";
                } else {
                    echo "Failed to update account status: " . mysqli_stmt_error($update_stmt) . "\n";
                }
                mysqli_stmt_close($update_stmt);
            } else {
                echo "Error preparing status update: " . mysqli_error($conn) . "\n";
            }
        }
    } else {
        echo "No user found with email: " . htmlspecialchars($email) . "\n";
    }
} else {
    echo "Please provide an email address as a command-line argument.\n";
    echo "Usage: php check_user_status.php <email>\n";
}

mysqli_close($conn);
?> 