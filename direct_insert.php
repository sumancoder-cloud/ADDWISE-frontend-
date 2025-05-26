<?php
require_once 'config.php';

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Test data
$name = "Test User";
$email = "test@example.com";
$password = password_hash("Test123!@#", PASSWORD_DEFAULT);

// Direct insert
$sql = "INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, NOW())";
$stmt = mysqli_prepare($conn, $sql);

if ($stmt) {
    mysqli_stmt_bind_param($stmt, "sss", $name, $email, $password);
    
    if (mysqli_stmt_execute($stmt)) {
        echo "User inserted successfully!<br>";
        
        // Verify insertion
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if ($row = mysqli_fetch_assoc($result)) {
            echo "<pre>";
            print_r($row);
            echo "</pre>";
        }
    } else {
        echo "Error inserting user: " . mysqli_error($conn) . "<br>";
    }
    
    mysqli_stmt_close($stmt);
} else {
    echo "Error preparing statement: " . mysqli_error($conn) . "<br>";
}

mysqli_close($conn);
?> 