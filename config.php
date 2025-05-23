<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root'); 
define('DB_PASSWORD', '');      
define('DB_NAME', 'addwise_db');


$conn = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD);

if (!$conn) {
    error_log("Database connection failed: " . mysqli_connect_error());
    die("Connection failed: " . mysqli_connect_error());
}
error_log("Initial database connection successful");


$sql = "CREATE DATABASE IF NOT EXISTS " . DB_NAME;
if (!mysqli_query($conn, $sql)) {
    error_log("Error creating database: " . mysqli_error($conn));
    die("Error creating database: " . mysqli_error($conn));
}
error_log("Database creation/verification successful");


if (!mysqli_select_db($conn, DB_NAME)) {
    error_log("Error selecting database: " . mysqli_error($conn));
    die("Error selecting database: " . mysqli_error($conn));
}
error_log("Database selection successful");


$result = mysqli_query($conn, "SHOW DATABASES LIKE '" . DB_NAME . "'");
if (mysqli_num_rows($result) == 0) {
    error_log("Database verification failed - database does not exist");
    die("Database verification failed");
}
error_log("Database verification successful");


$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

if (!mysqli_query($conn, $sql)) {
    error_log("Error creating users table: " . mysqli_error($conn));
    die("Error creating users table: " . mysqli_error($conn));
}
error_log("Users table creation/verification successful");

$result = mysqli_query($conn, "SHOW TABLES LIKE 'users'");
if (mysqli_num_rows($result) == 0) {
    error_log("Users table verification failed - table does not exist");
    die("Users table verification failed");
}

$result = mysqli_query($conn, "DESCRIBE users");
$required_columns = ['id', 'name', 'email', 'password', 'created_at'];
$found_columns = [];
while ($row = mysqli_fetch_assoc($result)) {
    $found_columns[] = $row['Field'];
}
$missing_columns = array_diff($required_columns, $found_columns);
if (!empty($missing_columns)) {
    error_log("Users table structure verification failed - missing columns: " . implode(', ', $missing_columns));
    die("Users table structure verification failed");
}
error_log("Users table structure verification successful");

// Create OTP verification table if not exists
$sql = "CREATE TABLE IF NOT EXISTS otp_verification (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(100) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

if (!mysqli_query($conn, $sql)) {
    error_log("Error creating OTP table: " . mysqli_error($conn));
    die("Error creating OTP table: " . mysqli_error($conn));
}
error_log("OTP table creation/verification successful");

// Verify OTP table exists and has correct structure
$result = mysqli_query($conn, "SHOW TABLES LIKE 'otp_verification'");
if (mysqli_num_rows($result) == 0) {
    error_log("OTP table verification failed - table does not exist");
    die("OTP table verification failed");
}

$result = mysqli_query($conn, "DESCRIBE otp_verification");
$required_columns = ['id', 'email', 'otp', 'created_at'];
$found_columns = [];
while ($row = mysqli_fetch_assoc($result)) {
    $found_columns[] = $row['Field'];
}
$missing_columns = array_diff($required_columns, $found_columns);
if (!empty($missing_columns)) {
    error_log("OTP table structure verification failed - missing columns: " . implode(', ', $missing_columns));
    die("OTP table structure verification failed");
}
error_log("OTP table structure verification successful");

error_log("Database and tables setup completed successfully");
?> 