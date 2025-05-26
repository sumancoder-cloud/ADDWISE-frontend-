<?php
// Database Configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'your_username');
define('DB_PASS', 'your_password');
define('DB_NAME', 'your_database');

// Application Configuration
define('APP_NAME', 'Addwise');
define('APP_URL', 'https://your-domain.com');
define('APP_ENV', 'development'); // 'development' or 'production'

// Security Configuration
define('SESSION_LIFETIME', 3600); // 1 hour
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minutes
define('OTP_EXPIRY', 600); // 10 minutes
define('PASSWORD_RESET_EXPIRY', 3600); // 1 hour

// Email Configuration
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'your-email@gmail.com');
define('SMTP_PASSWORD', 'your-app-password');
define('SMTP_FROM_EMAIL', 'your-email@gmail.com');
define('SMTP_FROM_NAME', 'Your Name');

// Error Reporting
if (APP_ENV === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}

// Database Connection
try {
    $conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if (!$conn) {
        throw new Exception("Database connection failed: " . mysqli_connect_error());
    }
    
    // Set charset to utf8mb4
    mysqli_set_charset($conn, "utf8mb4");
    
} catch (Exception $e) {
    error_log("Database connection error: " . $e->getMessage());
    die("Database connection failed. Please try again later.");
}

// Create database if it doesn't exist
$sql = "CREATE DATABASE IF NOT EXISTS " . DB_NAME . " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";
if (!mysqli_query($conn, $sql)) {
    error_log("Failed to create database: " . mysqli_error($conn));
}

// Select the database
mysqli_select_db($conn, DB_NAME);

// Create tables if they don't exist
$tables = [
    // Users table
    "CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('user', 'admin') DEFAULT 'user',
        status ENUM('pending', 'active', 'suspended') DEFAULT 'pending',
        last_login DATETIME,
        login_attempts INT DEFAULT 0,
        password_reset_token VARCHAR(64),
        password_reset_expires DATETIME,
        verification_token VARCHAR(64),
        email_verified BOOLEAN DEFAULT FALSE,
        created_at DATETIME NOT NULL,
        updated_at DATETIME ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_status (status),
        INDEX idx_role (role)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

    // User sessions table
    "CREATE TABLE IF NOT EXISTS user_sessions (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL,
        session_token VARCHAR(64) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT,
        last_activity DATETIME NOT NULL,
        created_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_session_token (session_token),
        INDEX idx_user_id (user_id),
        INDEX idx_expires_at (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

    // Login attempts table
    "CREATE TABLE IF NOT EXISTS login_attempts (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        attempt_time DATETIME NOT NULL,
        success BOOLEAN DEFAULT FALSE,
        INDEX idx_email_time (email, attempt_time),
        INDEX idx_ip_time (ip_address, attempt_time)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

    // Audit log table
    "CREATE TABLE IF NOT EXISTS audit_log (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT,
        action VARCHAR(50) NOT NULL,
        description TEXT,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT,
        created_at DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_user_id (user_id),
        INDEX idx_action (action),
        INDEX idx_created_at (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

    // OTP verification table
    "CREATE TABLE IF NOT EXISTS otp_verification (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(6) NOT NULL,
        purpose ENUM('registration', 'login', 'password_reset') NOT NULL,
        attempts INT DEFAULT 0,
        created_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        is_used BOOLEAN DEFAULT FALSE,
        INDEX idx_email_purpose (email, purpose),
        INDEX idx_expires_at (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

    // User preferences table
    "CREATE TABLE IF NOT EXISTS user_preferences (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL UNIQUE,
        theme VARCHAR(20) DEFAULT 'light',
        email_notifications BOOLEAN DEFAULT TRUE,
        two_factor_enabled BOOLEAN DEFAULT TRUE,
        language VARCHAR(10) DEFAULT 'en',
        timezone VARCHAR(50) DEFAULT 'UTC',
        created_at DATETIME NOT NULL,
        updated_at DATETIME ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
];

foreach ($tables as $sql) {
    if (!mysqli_query($conn, $sql)) {
        error_log("Failed to create table: " . mysqli_error($conn));
    }
}

// Function to check if a table exists
function tableExists($conn, $table) {
    $result = mysqli_query($conn, "SHOW TABLES LIKE '$table'");
    return mysqli_num_rows($result) > 0;
}

// Function to check if a column exists
function columnExists($conn, $table, $column) {
    $result = mysqli_query($conn, "SHOW COLUMNS FROM $table LIKE '$column'");
    return mysqli_num_rows($result) > 0;
}

// Verify database structure
$required_tables = ['users', 'user_sessions', 'login_attempts', 'audit_log', 'otp_verification', 'user_preferences'];
$missing_tables = [];

foreach ($required_tables as $table) {
    if (!tableExists($conn, $table)) {
        $missing_tables[] = $table;
    }
}

if (!empty($missing_tables)) {
    error_log("Missing tables: " . implode(', ', $missing_tables));
}

// Clean up expired sessions
$sql = "DELETE FROM user_sessions WHERE expires_at < NOW()";
mysqli_query($conn, $sql);

// Clean up expired OTPs
$sql = "DELETE FROM otp_verification WHERE expires_at < NOW()";
mysqli_query($conn, $sql);

// Clean up old login attempts
$sql = "DELETE FROM login_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)";
mysqli_query($conn, $sql);

// Clean up old audit logs (keep last 30 days)
$sql = "DELETE FROM audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)";
mysqli_query($conn, $sql);
?> 