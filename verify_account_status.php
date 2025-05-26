<?php
require_once 'config.php';

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

echo "Verifying all account statuses...\n\n";

// Begin transaction
mysqli_begin_transaction($conn);

try {
    // Get all users with their OTP verification status
    $sql = "SELECT u.id, u.email, u.status, u.email_verified,
            (SELECT o.is_used 
             FROM otp_verification o 
             WHERE o.email = u.email 
             AND o.purpose = 'registration' 
             ORDER BY o.created_at DESC 
             LIMIT 1) as last_otp_used
            FROM users u
            ORDER BY u.id";
    
    $result = mysqli_query($conn, $sql);
    
    if ($result) {
        echo "Current Account Status:\n";
        echo "----------------------------------------\n";
        $fixes_needed = false;
        
        while ($user = mysqli_fetch_assoc($result)) {
            echo "ID: " . $user['id'] . "\n";
            echo "Email: " . $user['email'] . "\n";
            echo "Current Status: " . $user['status'] . "\n";
            echo "Email Verified: " . ($user['email_verified'] ? 'Yes' : 'No') . "\n";
            echo "Last OTP Used: " . ($user['last_otp_used'] ? 'Yes' : 'No') . "\n";
            
            // Check if status matches OTP verification
            $should_be_active = $user['last_otp_used'] == 1;
            $is_active = $user['status'] === 'active';
            
            if ($should_be_active !== $is_active) {
                echo "*** Status mismatch! Should be " . ($should_be_active ? 'active' : 'pending') . " ***\n";
                $fixes_needed = true;
                
                // Update status to match OTP verification
                $new_status = $should_be_active ? 'active' : 'pending';
                $update_sql = "UPDATE users SET 
                              status = ?, 
                              email_verified = ? 
                              WHERE id = ?";
                
                $stmt = mysqli_prepare($conn, $update_sql);
                $email_verified = $should_be_active ? 1 : 0;
                mysqli_stmt_bind_param($stmt, "sii", $new_status, $email_verified, $user['id']);
                
                if (mysqli_stmt_execute($stmt)) {
                    echo "Fixed: Status updated to " . $new_status . "\n";
                } else {
                    echo "Error updating status: " . mysqli_error($conn) . "\n";
                }
            }
            echo "----------------------------------------\n";
        }
        
        if (!$fixes_needed) {
            echo "\nAll account statuses are correct!\n";
        } else {
            echo "\nAccount statuses have been fixed.\n";
            
            // Show final status
            $result = mysqli_query($conn, $sql);
            if ($result) {
                echo "\nFinal Account Status:\n";
                echo "----------------------------------------\n";
                while ($user = mysqli_fetch_assoc($result)) {
                    echo "ID: " . $user['id'] . "\n";
                    echo "Email: " . $user['email'] . "\n";
                    echo "Status: " . $user['status'] . "\n";
                    echo "Email Verified: " . ($user['email_verified'] ? 'Yes' : 'No') . "\n";
                    echo "Last OTP Used: " . ($user['last_otp_used'] ? 'Yes' : 'No') . "\n";
                    echo "----------------------------------------\n";
                }
            }
        }
        
        // Commit the transaction
        mysqli_commit($conn);
        
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