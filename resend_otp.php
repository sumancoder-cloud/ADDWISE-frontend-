<?php
require_once 'config.php';
require_once 'email_handler.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

header('Content-Type: application/json');

if ($_SERVER["REQUEST_METHOD"] == "POST" && !empty($_POST["email"])) {
    $email = trim($_POST["email"]);
    error_log("=== Resend OTP Request ===");
    error_log("Email: " . $email);
    error_log("Session data: " . print_r($_SESSION, true));
    
    // Check if this is a signup process (temp_user exists in session)
    $is_signup = isset($_SESSION['temp_user']) && $_SESSION['temp_user']['email'] === $email;
    
    if ($is_signup) {
        error_log("Resending OTP for signup process");
        // Generate and send new OTP for signup
        $otp = generateOTP();
        if (sendOTPEmail($email, $otp) && storeOTP($email, $otp)) {
            error_log("New OTP sent successfully for signup");
            echo json_encode(['success' => true]);
        } else {
            error_log("Failed to send new OTP for signup");
            echo json_encode([
                'success' => false,
                'message' => 'Failed to send verification code. Please try again.'
            ]);
        }
    } else {
        // This is a login process, check if user exists
        error_log("Checking for existing user account");
        $sql = "SELECT id FROM users WHERE email = ?";
        if ($stmt = mysqli_prepare($conn, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $email);
            if (mysqli_stmt_execute($stmt)) {
                mysqli_stmt_store_result($stmt);
                if (mysqli_stmt_num_rows($stmt) == 1) {
                    error_log("User found, sending new OTP for login");
                    // Generate and send new OTP for login
                    $otp = generateOTP();
                    if (sendOTPEmail($email, $otp) && storeOTP($email, $otp)) {
                        error_log("New OTP sent successfully for login");
                        echo json_encode(['success' => true]);
                    } else {
                        error_log("Failed to send new OTP for login");
                        echo json_encode([
                            'success' => false,
                            'message' => 'Failed to send verification code. Please try again.'
                        ]);
                    }
                } else {
                    error_log("No user account found with email: " . $email);
                    echo json_encode([
                        'success' => false,
                        'message' => 'No account found with that email.'
                    ]);
                }
            } else {
                error_log("Database error while checking user: " . mysqli_error($conn));
                echo json_encode([
                    'success' => false,
                    'message' => 'Oops! Something went wrong. Please try again later.'
                ]);
            }
            mysqli_stmt_close($stmt);
        }
    }
    error_log("=== End of Resend OTP Request ===");
} else {
    error_log("Invalid resend OTP request");
    echo json_encode([
        'success' => false,
        'message' => 'Invalid request.'
    ]);
}

mysqli_close($conn);
?> 