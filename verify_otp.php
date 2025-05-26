<?php
require_once 'config.php';
require_once 'email_handler.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Enable error logging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', 'otp_verification.log');

header('Content-Type: application/json');

function logDebug($message, $data = null) {
    $logMessage = date('Y-m-d H:i:s') . " - " . $message;
    if ($data !== null) {
        $logMessage .= " - Data: " . print_r($data, true);
    }
    error_log($logMessage);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    logDebug("=== OTP Verification Request Started ===");
    logDebug("POST data", $_POST);
    logDebug("Session data", $_SESSION);
    logDebug("Session ID", session_id());
    
    $response = ['success' => false, 'message' => ''];
    
    // Validate input
    if (empty($_POST["otp"]) || !is_array($_POST["otp"]) || empty($_POST["email"])) {
        logDebug("Invalid input - OTP or email missing or invalid format");
        logDebug("OTP array", $_POST["otp"]);
        logDebug("Email", $_POST["email"]);
        $response['message'] = "Please enter the verification code correctly.";
        echo json_encode($response);
        exit;
    }

    $otp = implode('', $_POST["otp"]);
    $email = trim($_POST["email"]);
    
    logDebug("Processing verification", [
        'email' => $email,
        'otp' => $otp,
        'session_data' => isset($_SESSION['temp_auth']) ? $_SESSION['temp_auth'] : 'Not set'
    ]);
    
    // Verify session data
    if (!isset($_SESSION['temp_auth'])) {
        logDebug("Session temp_auth not found");
        $response['message'] = "Session expired. Please try again.";
        echo json_encode($response);
        exit;
    }

    if ($_SESSION['temp_auth']['email'] !== $email) {
        logDebug("Email mismatch", [
            'session_email' => $_SESSION['temp_auth']['email'],
            'post_email' => $email
        ]);
        $response['message'] = "Session expired. Please try again.";
        echo json_encode($response);
        exit;
    }

    // Initialize Auth class
    require_once 'auth.php';
    $auth = new Auth($conn);

    // Get the stored OTP from database for comparison
    $sql = "SELECT otp, created_at, is_used FROM otp_verification WHERE email = ? AND purpose = 'registration' ORDER BY created_at DESC LIMIT 1";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    if ($row = mysqli_fetch_assoc($result)) {
        logDebug("Found stored OTP", [
            'stored_otp' => $row['otp'],
            'entered_otp' => $otp,
            'created_at' => $row['created_at'],
            'is_used' => $row['is_used']
        ]);
        
        // Check if OTP is expired (15 minutes)
        $created_at = strtotime($row['created_at']);
        $now = time();
        if ($now - $created_at > 900) { // 15 minutes in seconds
            logDebug("OTP expired", [
                'created_at' => date('Y-m-d H:i:s', $created_at),
                'current_time' => date('Y-m-d H:i:s', $now),
                'difference' => $now - $created_at
            ]);
            $response['message'] = "Verification code has expired. Please request a new one.";
            echo json_encode($response);
            exit;
        }
        
        // Check if OTP is already used
        if ($row['is_used']) {
            logDebug("OTP already used");
            $response['message'] = "This verification code has already been used. Please request a new one.";
            echo json_encode($response);
            exit;
        }
        
        // Compare OTPs
        if ($row['otp'] === $otp) {
            logDebug("OTP matched successfully");
            $response['success'] = true;
            $response['message'] = "Verification successful! Your account has been created.";
            
            // Mark OTP as used
            $update_sql = "UPDATE otp_verification SET is_used = 1 WHERE email = ? AND otp = ?";
            $update_stmt = mysqli_prepare($conn, $update_sql);
            mysqli_stmt_bind_param($update_stmt, "ss", $email, $otp);
            mysqli_stmt_execute($update_stmt);
            
            // Clear session data
            unset($_SESSION['temp_auth']);
        } else {
            logDebug("OTP mismatch", [
                'stored_otp' => $row['otp'],
                'entered_otp' => $otp
            ]);
            $response['message'] = "Invalid verification code. Please try again.";
        }
    } else {
        logDebug("No OTP found for email", ['email' => $email]);
        $response['message'] = "No verification code found. Please request a new one.";
    }
    
    logDebug("Response", $response);
    logDebug("=== OTP Verification Request Ended ===");
    
    echo json_encode($response);
} else {
    logDebug("Invalid request method", ['method' => $_SERVER["REQUEST_METHOD"]]);
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
}

mysqli_close($conn);
?> 