<?php
require_once 'config.php';

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

echo "Starting security check for all user accounts...\n\n";

// Begin transaction
mysqli_begin_transaction($conn);

try {
    // Get all users and their OTP verification status
    $sql = "SELECT u.id, u.email, u.status, u.email_verified,
            (SELECT COUNT(*) FROM otp_verification o 
             WHERE o.email = u.email 
             AND o.purpose = 'registration' 
             AND o.is_used = TRUE) as has_verified_otp
            FROM users u
            ORDER BY u.id";
    
    $result = mysqli_query($conn, $sql);
    
    if ($result) {
        echo "Checking all user accounts:\n";
        echo "----------------------------------------\n";
        $accounts_to_deactivate = [];
        $accounts_to_activate = [];
        
        while ($user = mysqli_fetch_assoc($result)) {
            echo "ID: " . $user['id'] . "\n";
            echo "Email: " . $user['email'] . "\n";
            echo "Current Status: " . $user['status'] . "\n";
            echo "Email Verified: " . ($user['email_verified'] ? 'Yes' : 'No') . "\n";
            echo "OTP Verified: " . ($user['has_verified_otp'] > 0 ? 'Yes' : 'No') . "\n";
            echo "----------------------------------------\n";
            
            // If account is active but OTP not verified, mark for deactivation
            if ($user['status'] === 'active' && $user['has_verified_otp'] == 0) {
                $accounts_to_deactivate[] = $user['id'];
            }
            // If account has verified OTP but is not active, mark for activation
            elseif ($user['has_verified_otp'] > 0 && $user['status'] !== 'active') {
                $accounts_to_activate[] = $user['id'];
            }
        }
        
        // Deactivate accounts without OTP verification
        if (!empty($accounts_to_deactivate)) {
            $ids = implode(',', $accounts_to_deactivate);
            $update_sql = "UPDATE users SET status = 'pending', email_verified = FALSE 
                          WHERE id IN ($ids)";
            
            if (mysqli_query($conn, $update_sql)) {
                $affected_rows = mysqli_affected_rows($conn);
                echo "\nDeactivated $affected_rows accounts that had not completed OTP verification.\n";
            } else {
                throw new Exception("Error deactivating accounts: " . mysqli_error($conn));
            }
        }
        
        // Activate accounts with verified OTP
        if (!empty($accounts_to_activate)) {
            $ids = implode(',', $accounts_to_activate);
            $update_sql = "UPDATE users SET status = 'active', email_verified = TRUE 
                          WHERE id IN ($ids)";
            
            if (mysqli_query($conn, $update_sql)) {
                $affected_rows = mysqli_affected_rows($conn);
                echo "\nActivated $affected_rows accounts that had completed OTP verification.\n";
            } else {
                throw new Exception("Error activating accounts: " . mysqli_error($conn));
            }
        }
        
        // Show final status
        $sql = "SELECT u.id, u.email, u.status, u.email_verified,
                (SELECT COUNT(*) FROM otp_verification o 
                 WHERE o.email = u.email 
                 AND o.purpose = 'registration' 
                 AND o.is_used = TRUE) as has_verified_otp
                FROM users u
                ORDER BY u.id";
        
        $result = mysqli_query($conn, $sql);
        if ($result) {
            echo "\nFinal Account Status:\n";
            echo "----------------------------------------\n";
            while ($user = mysqli_fetch_assoc($result)) {
                echo "ID: " . $user['id'] . "\n";
                echo "Email: " . $user['email'] . "\n";
                echo "Status: " . $user['status'] . "\n";
                echo "Email Verified: " . ($user['email_verified'] ? 'Yes' : 'No') . "\n";
                echo "OTP Verified: " . ($user['has_verified_otp'] > 0 ? 'Yes' : 'No') . "\n";
                echo "----------------------------------------\n";
            }
        }
        
        // Commit the transaction
        mysqli_commit($conn);
        echo "\nAccount security check completed!\n";
        
    } else {
        throw new Exception("Error checking user accounts: " . mysqli_error($conn));
    }
    
} catch (Exception $e) {
    // Rollback transaction on error
    mysqli_rollback($conn);
    echo "\nError: " . $e->getMessage() . "\n";
}

mysqli_close($conn);
?> 