<?php
require_once 'config.php';

function generateOTP() {
    // Generate a 6-digit OTP
    return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function sendOTPEmail($email, $otp) {
    error_log("=== Attempting to send OTP email ===");
    error_log("To: " . $email);
    error_log("OTP: " . $otp);
    
    $subject = "Addwise - Your Verification Code";
    
    $message = "<html>
    <head>
        <title>Email Verification</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .otp-code { 
                font-size: 24px; 
                font-weight: bold; 
                color: #ffcc00; 
                background: #1a1a2e; 
                padding: 10px 20px; 
                border-radius: 5px; 
                display: inline-block; 
                margin: 20px 0; 
            }
            .footer { 
                margin-top: 30px; 
                font-size: 12px; 
                color: #666; 
            }
        </style>
    </head>
    <body>
        <div class='container'>
            <h2>Welcome to Addwise!</h2>
            <p>Thank you for registering. Please use the following verification code to complete your registration:</p>
            <div class='otp-code'>$otp</div>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this code, please ignore this email.</p>
            <div class='footer'>
                <p>Best regards,<br>The Addwise Team</p>
            </div>
        </div>
    </body>
    </html>";
    
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= 'From: Addwise <noreply@addwise.com>' . "\r\n";
    
    error_log("Sending email with headers: " . $headers);
    
    $result = mail($email, $subject, $message, $headers);
    
    if ($result) {
        error_log("Email sent successfully");
    } else {
        error_log("Failed to send email. Error: " . error_get_last()['message']);
    }
    
    error_log("=== End of email sending attempt ===");
    return $result;
}

function storeOTP($email, $otp) {
    global $conn;
    
 
    $sql = "SELECT id FROM otp_verification WHERE email = ?";
    if ($stmt = mysqli_prepare($conn, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        
        if (mysqli_stmt_num_rows($stmt) > 0) {
         
            $sql = "UPDATE otp_verification SET otp = ?, created_at = NOW() WHERE email = ?";
        } else {
          
            $sql = "INSERT INTO otp_verification (email, otp, created_at) VALUES (?, ?, NOW())";
        }
        mysqli_stmt_close($stmt);
        
     
        if ($stmt = mysqli_prepare($conn, $sql)) {
            mysqli_stmt_bind_param($stmt, "ss", $otp, $email);
            return mysqli_stmt_execute($stmt);
        }
    }
    return false;
}

// Create OTP verification table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS otp_verification (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(100) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX (email)
)";

if (!mysqli_query($conn, $sql)) {
    die("Error creating OTP table: " . mysqli_error($conn));
}
?> 