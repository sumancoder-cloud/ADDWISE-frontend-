<?php
session_start();

// Check if user came from successful registration
if (!isset($_SESSION['registration_success']) || !$_SESSION['registration_success']) {
    header("Location: signup.php");
    exit();
}

// Clear the success flag
$_SESSION['registration_success'] = false;
$user_name = $_SESSION['user_name'] ?? 'User';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Successful - Addwise</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
            background: #1a1a2e;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .success-container {
            background: rgba(0, 0, 0, 0.9);
            color: #ffcc00;
            padding: 40px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 0 20px rgba(255, 204, 0, 0.3);
            border: 2px solid #ffcc00;
            max-width: 500px;
            width: 90%;
            position: relative;
        }
        .success-icon {
            font-size: 48px;
            margin-bottom: 20px;
            color: #ffcc00;
        }
        h1 {
            margin: 0 0 20px 0;
            font-size: 28px;
            color: #ffcc00;
        }
        p {
            margin: 0 0 15px 0;
            font-size: 18px;
            line-height: 1.5;
        }
        .loading-spinner {
            width: 50px;
            height: 50px;
            margin: 20px auto;
            border: 5px solid #ffcc00;
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            100% { transform: rotate(360deg); }
        }
        .redirect-text {
            font-size: 16px;
            color: #ffffff;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="success-container">
        <div class="success-icon">✓</div>
        <h1>Registration Successful!</h1>
        <p>Welcome to Addwise, <?php echo htmlspecialchars($user_name); ?>!</p>
        <p>Your account has been created successfully.</p>
        <div class="loading-spinner"></div>
        <p class="redirect-text">You will be redirected to the login page in a moment...</p>
    </div>

    <script>
        // Redirect to login page after 3 seconds
        setTimeout(() => {
            window.location.href = 'login.php';
        }, 3000);
    </script>
</body>
</html> 