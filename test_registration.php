<?php
require_once 'config.php';

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', 'registration_test.log');

// Clear the log file
file_put_contents('registration_test.log', '');

function log_message($message) {
    error_log($message . "\n", 3, 'registration_test.log');
}

// Test user data
$test_user = [
    'name' => 'Test User',
    'email' => 'test@example.com',
    'password' => 'Test123!@#'
];

log_message("=== Testing Registration Process ===\n");

// 1. Check if user already exists
$sql = "SELECT id FROM users WHERE email = ?";
if ($stmt = mysqli_prepare($conn, $sql)) {
    mysqli_stmt_bind_param($stmt, "s", $test_user['email']);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    
    if (mysqli_stmt_num_rows($stmt) > 0) {
        log_message("Test user already exists, deleting...");
        $sql = "DELETE FROM users WHERE email = ?";
        if ($stmt = mysqli_prepare($conn, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $test_user['email']);
            mysqli_stmt_execute($stmt);
        }
    }
    mysqli_stmt_close($stmt);
}

// 2. Try to insert test user
$hashed_password = password_hash($test_user['password'], PASSWORD_DEFAULT);
$sql = "INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, NOW())";

if ($stmt = mysqli_prepare($conn, $sql)) {
    mysqli_stmt_bind_param($stmt, "sss", $test_user['name'], $test_user['email'], $hashed_password);
    
    if (mysqli_stmt_execute($stmt)) {
        log_message("Test user created successfully");
        
        // 3. Verify user was created
        $sql = "SELECT id, name, email, created_at FROM users WHERE email = ?";
        if ($stmt = mysqli_prepare($conn, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $test_user['email']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if ($row = mysqli_fetch_assoc($result)) {
                log_message("\nUser details:");
                log_message("ID: " . $row['id']);
                log_message("Name: " . $row['name']);
                log_message("Email: " . $row['email']);
                log_message("Created: " . $row['created_at']);
            }
        }
    } else {
        log_message("Error creating test user: " . mysqli_error($conn));
    }
    mysqli_stmt_close($stmt);
}

// 4. Clean up
$sql = "DELETE FROM users WHERE email = ?";
if ($stmt = mysqli_prepare($conn, $sql)) {
    mysqli_stmt_bind_param($stmt, "s", $test_user['email']);
    mysqli_stmt_execute($stmt);
    log_message("\nTest user cleaned up");
}

mysqli_close($conn);

// Display the log file contents
echo "Test completed. Check registration_test.log for details.\n";
?> 