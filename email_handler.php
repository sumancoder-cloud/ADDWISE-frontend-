<?php
require_once 'config.php';
require_once 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

class EmailHandler {
    private $mailer;
    
    public function __construct() {
        $this->mailer = new PHPMailer(true);
        $this->setupMailer();
    }
    
    private function setupMailer() {
        // Server settings
        $this->mailer->isSMTP();
        $this->mailer->Host = SMTP_HOST;
        $this->mailer->SMTPAuth = true;
        $this->mailer->Username = SMTP_USERNAME;
        $this->mailer->Password = SMTP_PASSWORD;
        $this->mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $this->mailer->Port = SMTP_PORT;
        
        // Default sender
        $this->mailer->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
    }
    
    public function sendOTP($email, $otp, $purpose) {
        try {
            $this->mailer->clearAddresses();
            $this->mailer->addAddress($email);
            $this->mailer->isHTML(true);
            
            switch ($purpose) {
                case 'registration':
                    $this->mailer->Subject = 'Verify Your Email Address';
                    $this->mailer->Body = "
                        <h2>Welcome to Our Platform!</h2>
                        <p>Thank you for registering. Please use the following code to verify your email address:</p>
                        <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                        <p>This code will expire in 10 minutes.</p>
                        <p>If you didn't request this code, please ignore this email.</p>
                    ";
                    break;
                    
                case 'login':
                    $this->mailer->Subject = 'Your Login Verification Code';
                    $this->mailer->Body = "
                        <h2>Login Verification</h2>
                        <p>Please use the following code to complete your login:</p>
                        <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                        <p>This code will expire in 10 minutes.</p>
                        <p>If you didn't attempt to login, please secure your account immediately.</p>
                    ";
                    break;
                    
                case 'password_reset':
                    $this->mailer->Subject = 'Password Reset Verification Code';
                    $this->mailer->Body = "
                        <h2>Password Reset Request</h2>
                        <p>Please use the following code to reset your password:</p>
                        <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                        <p>This code will expire in 10 minutes.</p>
                        <p>If you didn't request a password reset, please ignore this email.</p>
                    ";
                    break;
            }
            
            return $this->mailer->send();
        } catch (Exception $e) {
            error_log("Email sending failed: " . $this->mailer->ErrorInfo);
            return false;
        }
    }
    
    public function sendWelcome($email, $name) {
        try {
            $this->mailer->clearAddresses();
            $this->mailer->addAddress($email);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = 'Welcome to Our Platform!';
            
            $this->mailer->Body = "
                <h2>Welcome, {$name}!</h2>
                <p>Thank you for joining our platform. We're excited to have you on board!</p>
                <p>Here are a few things you can do to get started:</p>
                <ul>
                    <li>Complete your profile</li>
                    <li>Explore our features</li>
                    <li>Connect with other users</li>
                </ul>
                <p>If you have any questions, feel free to contact our support team.</p>
                <p>Best regards,<br>Your Team</p>
            ";
            
            return $this->mailer->send();
        } catch (Exception $e) {
            error_log("Welcome email sending failed: " . $this->mailer->ErrorInfo);
            return false;
        }
    }
    
    public function sendPasswordReset($email, $token) {
        try {
            $this->mailer->clearAddresses();
            $this->mailer->addAddress($email);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = 'Reset Your Password';
            
            $reset_link = "http://localhost/ADDWISE/reset-password.php?token=" . $token;
            
            $this->mailer->Body = "
                <h2>Password Reset Request</h2>
                <p>We received a request to reset your password. Click the link below to reset your password:</p>
                <p><a href='{$reset_link}' style='display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;'>Reset Password</a></p>
                <p>Or copy and paste this link in your browser:</p>
                <p>{$reset_link}</p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
            ";
            
            return $this->mailer->send();
        } catch (Exception $e) {
            error_log("Password reset email sending failed: " . $this->mailer->ErrorInfo);
            return false;
        }
    }
}

// Email configuration
// To use Gmail SMTP:
// 1. Enable 2-Step Verification in your Google Account
// 2. Generate an App Password: Google Account -> Security -> App Passwords
// 3. Select "Mail" and "Other (Custom name)" -> Name it "Addwise"
// 4. Copy the 16-character password and replace 'your-app-password' below
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'suman.tati2005@gmail.com');  // Your Gmail address
define('SMTP_PASSWORD', 'peaf rhep hytw rhpf');  // Replace with your 16-character app password
define('SMTP_FROM_EMAIL', 'suman.tati2005@gmail.com');
define('SMTP_FROM_NAME', 'Addwise');

function generateOTP() {
    // Generate a 6-digit OTP
    return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function sendOTPEmail($email, $otp, $purpose) {
    try {
        $mail = new PHPMailer(true);
        
        // Server settings
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USERNAME;
        $mail->Password = SMTP_PASSWORD;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        // Recipients
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        
        switch ($purpose) {
            case 'registration':
                $mail->Subject = 'Verify Your Email Address';
                $mail->Body = "
                    <h2>Welcome to Our Platform!</h2>
                    <p>Thank you for registering. Please use the following code to verify your email address:</p>
                    <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this code, please ignore this email.</p>
                ";
                break;
                
            case 'login':
                $mail->Subject = 'Your Login Verification Code';
                $mail->Body = "
                    <h2>Login Verification</h2>
                    <p>Please use the following code to complete your login:</p>
                    <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't attempt to login, please secure your account immediately.</p>
                ";
                break;
                
            case 'password_reset':
                $mail->Subject = 'Password Reset Verification Code';
                $mail->Body = "
                    <h2>Password Reset Request</h2>
                    <p>Please use the following code to reset your password:</p>
                    <h1 style='font-size: 32px; letter-spacing: 5px; color: #4CAF50;'>{$otp}</h1>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request a password reset, please ignore this email.</p>
                ";
                break;
        }

        $mail->send();
        return true;
        
    } catch (Exception $e) {
        error_log("Email sending failed: " . $mail->ErrorInfo);
        return false;
    }
}

function sendPasswordResetEmail($email, $token) {
    try {
        $mail = new PHPMailer(true);
        
        // Server settings
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com'; // Update with your SMTP server
        $mail->SMTPAuth = true;
        $mail->Username = 'your-email@gmail.com'; // Update with your email
        $mail->Password = 'your-app-password'; // Update with your app password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

        // Recipients
        $mail->setFrom('your-email@gmail.com', 'Your Name'); // Update with your details
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Reset Your Password';
        
        $reset_link = "https://your-domain.com/reset-password.php?token=" . $token;
        
        $mail->Body = "
            <h2>Password Reset Request</h2>
            <p>We received a request to reset your password. Click the link below to reset your password:</p>
            <p><a href='{$reset_link}' style='display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;'>Reset Password</a></p>
            <p>Or copy and paste this link in your browser:</p>
            <p>{$reset_link}</p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
        ";

        $mail->send();
        return true;
        
    } catch (Exception $e) {
        error_log("Password reset email sending failed: " . $mail->ErrorInfo);
        return false;
    }
}

function sendWelcomeEmail($email, $name) {
    try {
        $mail = new PHPMailer(true);
        
        // Server settings
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com'; // Update with your SMTP server
        $mail->SMTPAuth = true;
        $mail->Username = 'your-email@gmail.com'; // Update with your email
        $mail->Password = 'your-app-password'; // Update with your app password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

        // Recipients
        $mail->setFrom('your-email@gmail.com', 'Your Name'); // Update with your details
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Welcome to Our Platform!';
        
        $mail->Body = "
            <h2>Welcome, {$name}!</h2>
            <p>Thank you for joining our platform. We're excited to have you on board!</p>
            <p>Here are a few things you can do to get started:</p>
            <ul>
                <li>Complete your profile</li>
                <li>Explore our features</li>
                <li>Connect with other users</li>
            </ul>
            <p>If you have any questions, feel free to contact our support team.</p>
            <p>Best regards,<br>Your Team</p>
        ";

        $mail->send();
        return true;
        
    } catch (Exception $e) {
        error_log("Welcome email sending failed: " . $mail->ErrorInfo);
        return false;
    }
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