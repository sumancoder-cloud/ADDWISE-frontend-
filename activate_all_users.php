<?php
require_once 'config.php';

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

echo "Starting to check and activate verified user accounts...\n\n";

// Begin transaction
mysqli_begin_transaction($conn);

try {
    // First, get all users and their OTP verification status
    $sql = "SELECT u.id, u.email, u.status, u.email_verified, 
            (SELECT COUNT(*) FROM otp_verification o 
             WHERE o.email = u.email 
             AND o.purpose = 'registration' 
             AND o.is_used = TRUE) as has_verified_otp
            FROM users u
            ORDER BY u.id";
    
    $result = mysqli_query($conn, $sql);
    
    if ($result) {
        echo "Current User Status:\n";
        echo "----------------------------------------\n";
        $users_to_activate = [];
        
        while ($user = mysqli_fetch_assoc($result)) {
            echo "ID: " . $user['id'] . "\n";
            echo "Email: " . $user['email'] . "\n";
            echo "Current Status: " . $user['status'] . "\n";
            echo "Email Verified: " . ($user['email_verified'] ? 'Yes' : 'No') . "\n";
            echo "OTP Verified: " . ($user['has_verified_otp'] > 0 ? 'Yes' : 'No') . "\n";
            echo "----------------------------------------\n";
            
            // Only activate accounts that have verified OTP
            if ($user['has_verified_otp'] > 0 && $user['status'] !== 'active') {
                $users_to_activate[] = $user['id'];
            }
        }
        
        // Update only verified accounts
        if (!empty($users_to_activate)) {
            $ids = implode(',', $users_to_activate);
            $update_sql = "UPDATE users SET status = 'active', email_verified = TRUE 
                          WHERE id IN ($ids) AND status != 'active'";
            
            if (mysqli_query($conn, $update_sql)) {
                $affected_rows = mysqli_affected_rows($conn);
                echo "\nSuccessfully activated $affected_rows verified user accounts.\n";
                
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
                    echo "\nFinal User Status:\n";
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
            } else {
                throw new Exception("Error updating verified accounts: " . mysqli_error($conn));
            }
        } else {
            echo "\nNo accounts need to be activated. All accounts are either already active or not verified.\n";
        }
        
        // Commit the transaction
        mysqli_commit($conn);
        echo "\nAccount status update completed!\n";
        
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