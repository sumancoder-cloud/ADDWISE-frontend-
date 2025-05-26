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

// Verify database exists
$sql = "CREATE DATABASE IF NOT EXISTS " . DB_NAME;
if (!mysqli_query($conn, $sql)) {
    error_log("Error creating database: " . mysqli_error($conn));
    die("Error creating database: " . mysqli_error($conn));
}
error_log("Database creation/verification successful");

// Select database
if (!mysqli_select_db($conn, DB_NAME)) {
    error_log("Error selecting database: " . mysqli_error($conn));
    die("Error selecting database: " . mysqli_error($conn));
}
error_log("Database selection successful");

// Verify database exists
$result = mysqli_query($conn, "SHOW DATABASES LIKE '" . DB_NAME . "'");
if (mysqli_num_rows($result) == 0) {
    error_log("Database verification failed - database does not exist");
    die("Database verification failed");
}
error_log("Database verification successful");

// Create and verify users table with enhanced security features
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    status ENUM('active', 'inactive', 'suspended') NOT NULL DEFAULT 'active',
    last_login DATETIME,
    login_attempts INT DEFAULT 0,
    password_reset_token VARCHAR(100),
    password_reset_expires DATETIME,
    email_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(100),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX (email),
    INDEX (status),
    INDEX (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

if (!mysqli_query($conn, $sql)) {
    error_log("Error creating users table: " . mysqli_error($conn));
    die("Error creating users table: " . mysqli_error($conn));
}
error_log("Users table creation/verification successful");

// Verify users table exists and has correct structure
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

// Create user_sessions table for better session management
$sql = "CREATE TABLE IF NOT EXISTS user_sessions (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    session_token VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    last_activity DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX (session_token),
    INDEX (user_id),
    INDEX (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

if (!mysqli_query($conn, $sql)) {
    error_log("Error creating user_sessions table: " . mysqli_error($conn));
    die("Error creating user_sessions table: " . mysqli_error($conn));
}
error_log("User sessions table creation/verification successful");

// Create login_attempts table for security
$sql = "CREATE TABLE IF NOT EXISTS login_attempts (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempt_time DATETIME NOT NULL,
    success BOOLEAN DEFAULT FALSE,
    INDEX (email),
    INDEX (ip_address),
    INDEX (attempt_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

if (!mysqli_query($conn, $sql)) {
    error_log("Error creating login_attempts table: " . mysqli_error($conn));
    die("Error creating login_attempts table: " . mysqli_error($conn));
}
error_log("Login attempts table creation/verification successful");

// Create audit_log table for security tracking
$sql = "CREATE TABLE IF NOT EXISTS audit_log (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX (user_id),
    INDEX (action),
    INDEX (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

if (!mysqli_query($conn, $sql)) {
    error_log("Error creating audit_log table: " . mysqli_error($conn));
    die("Error creating audit_log table: " . mysqli_error($conn));
}
error_log("Audit log table creation/verification successful");

// Create and verify OTP table with enhanced security
$sql = "CREATE TABLE IF NOT EXISTS otp_verification (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(100) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    purpose ENUM('registration', 'login', 'password_reset') NOT NULL,
    attempts INT DEFAULT 0,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    INDEX (email),
    INDEX (created_at),
    INDEX (expires_at)
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

// Create user_preferences table
$sql = "CREATE TABLE IF NOT EXISTS user_preferences (
    user_id INT NOT NULL PRIMARY KEY,
    theme VARCHAR(20) DEFAULT 'light',
    email_notifications BOOLEAN DEFAULT TRUE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

if (!mysqli_query($conn, $sql)) {
    error_log("Error creating user_preferences table: " . mysqli_error($conn));
    die("Error creating user_preferences table: " . mysqli_error($conn));
}
error_log("User preferences table creation/verification successful");

// Test database connection with a simple query
$test_sql = "SELECT 1";
if (!mysqli_query($conn, $test_sql)) {
    error_log("Database connection test failed: " . mysqli_error($conn));
    die("Database connection test failed");
}
error_log("Database connection test successful");

error_log("Database and tables setup completed successfully");
?> 