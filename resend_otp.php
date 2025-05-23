<?php
require_once 'config.php';
require_once 'email_handler.php';

header('Content-Type: application/json');

if ($_SERVER["REQUEST_METHOD"] == "POST" && !empty($_POST["email"])) {
    $email = trim($_POST["email"]);
    
//mail vundha ledha anicheck chesthunna
    $sql = "SELECT id FROM users WHERE email = ?";
    if ($stmt = mysqli_prepare($conn, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        if (mysqli_stmt_execute($stmt)) {
            mysqli_stmt_store_result($stmt);
            if (mysqli_stmt_num_rows($stmt) == 1) {
                // kotha otp cheyyadam kosam
                $otp = generateOTP();
                if (sendOTPEmail($email, $otp) && storeOTP($email, $otp)) {
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode([
                        'success' => false,
                        'message' => 'Failed to send verification code. Please try again.'
                    ]);
                }
            } else {
                echo json_encode([
                    'success' => false,
                    'message' => 'No account found with that email.'
                ]);
            }
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Oops! Something went wrong. Please try again later.'
            ]);
        }
        mysqli_stmt_close($stmt);
    }
} else {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid request.'
    ]);
}

mysqli_close($conn);
?> 