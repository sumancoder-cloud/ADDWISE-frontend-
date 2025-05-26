<?php
require_once 'config.php';

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

// Get email from command line argument
$email = isset($argv[1]) ? $argv[1] : null;

if ($email) {
    echo "Checking and fixing status for email: " . htmlspecialchars($email) . "\n\n";
    
    // Begin transaction
    mysqli_begin_transaction($conn);
    
    try {
        // First, check if user exists and get current status
        $sql = "SELECT id, status, email_verified FROM users WHERE email = ? FOR UPDATE";
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            throw new Exception("Error preparing user query: " . mysqli_error($conn));
        }
        
        mysqli_stmt_bind_param($stmt, "s", $email);
        if (!mysqli_stmt_execute($stmt)) {
            throw new Exception("Error executing user query: " . mysqli_stmt_error($stmt));
        }
        
        $result = mysqli_stmt_get_result($stmt);
        if (!$result) {
            throw new Exception("Error getting user result: " . mysqli_error($conn));
        }
        
        $user = mysqli_fetch_assoc($result);
        if (!$user) {
            throw new Exception("No user found with email: " . htmlspecialchars($email));
        }
        
        echo "Current User Status:\n";
        echo "ID: " . $user['id'] . "\n";
        echo "Status: " . ($user['status'] ?? 'Not set') . "\n";
        echo "Email Verified: " . ($user['email_verified'] ? 'Yes' : 'No') . "\n";
        
        // Check OTP verification
        $sql = "SELECT purpose, created_at, is_used FROM otp_verification 
                WHERE email = ? AND purpose = 'registration' 
                ORDER BY created_at DESC LIMIT 1";
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            throw new Exception("Error preparing OTP query: " . mysqli_error($conn));
        }
        
        mysqli_stmt_bind_param($stmt, "s", $email);
        if (!mysqli_stmt_execute($stmt)) {
            throw new Exception("Error executing OTP query: " . mysqli_stmt_error($stmt));
        }
        
        $otp_result = mysqli_stmt_get_result($stmt);
        if (!$otp_result) {
            throw new Exception("Error getting OTP result: " . mysqli_error($conn));
        }
        
        $otp = mysqli_fetch_assoc($otp_result);
        if ($otp) {
            echo "\nOTP Verification Status:\n";
            echo "Purpose: " . $otp['purpose'] . "\n";
            echo "Created At: " . $otp['created_at'] . "\n";
            echo "Used: " . ($otp['is_used'] ? 'Yes' : 'No') . "\n";
            
            // If OTP is verified but account is not active, update the status
            if ($otp['is_used'] && (!isset($user['status']) || $user['status'] !== 'active')) {
                echo "\nUpdating account status to active...\n";
                
                $update_sql = "UPDATE users SET status = 'active', email_verified = TRUE WHERE id = ?";
                $update_stmt = mysqli_prepare($conn, $update_sql);
                if (!$update_stmt) {
                    throw new Exception("Error preparing status update: " . mysqli_error($conn));
                }
                
                mysqli_stmt_bind_param($update_stmt, "i", $user['id']);
                if (!mysqli_stmt_execute($update_stmt)) {
                    throw new Exception("Error updating status: " . mysqli_stmt_error($update_stmt));
                }
                
                echo "Account status successfully updated to active.\n";
            } else {
                echo "\nAccount status is already correct or OTP not verified.\n";
            }
        } else {
            echo "\nNo OTP verification records found.\n";
        }
        
        // Commit transaction
        mysqli_commit($conn);
        echo "\nTransaction completed successfully.\n";
        
    } catch (Exception $e) {
        // Rollback transaction on error
        mysqli_rollback($conn);
        echo "\nError: " . $e->getMessage() . "\n";
    }
    
} else {
    echo "Please provide an email address as a command-line argument.\n";
    echo "Usage: php fix_user_status.php <email>\n";
}

mysqli_close($conn);
?>