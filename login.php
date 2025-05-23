<?php
require_once 'config.php';
require_once 'email_handler.php';

session_start();

// Debug: Check all users in database at login page load
error_log("=== Checking Database Users at Login Page Load ===");
$check_sql = "SELECT id, name, email, created_at FROM users";
$check_result = mysqli_query($conn, $check_sql);
if ($check_result) {
    error_log("Total users in database: " . mysqli_num_rows($check_result));
    while ($row = mysqli_fetch_assoc($check_result)) {
        error_log("Found user - ID: " . $row['id'] . ", Name: '" . $row['name'] . "', Email: '" . $row['email'] . "', Created: " . $row['created_at']);
    }
} else {
    error_log("Error checking users: " . mysqli_error($conn));
}
error_log("=== End of Database Check ===");

$name = $email = $password = $otp = "";
$name_err = $email_err = $password_err = $otp_err = "";
$show_otp_form = false;
$success_message = "";

// Check for success message from signup
if (isset($_SESSION['success_message'])) {
    $success_message = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['send_otp'])) {
        // Debug: List all users in database
        $debug_sql = "SELECT id, name, email, created_at FROM users";
        $debug_result = mysqli_query($conn, $debug_sql);
        error_log("=== Current Users in Database During Login Attempt ===");
        if ($debug_result) {
            error_log("Total users found: " . mysqli_num_rows($debug_result));
            while ($row = mysqli_fetch_assoc($debug_result)) {
                error_log("User - ID: " . $row['id'] . ", Name: '" . $row['name'] . "', Email: '" . $row['email'] . "', Created: " . $row['created_at']);
            }
        }
        error_log("=== End of Users List ===");

        // Validate name
        if (empty(trim($_POST["name"] ?? ''))) {
            $name_err = "Please enter your name.";
            error_log("Login attempt - empty name");
        } else {
            $name = trim($_POST["name"] ?? '');
            error_log("Login attempt - Name: '" . $name . "'");
        }

        // Validate email
        if (empty(trim($_POST["email"] ?? ''))) {
            $email_err = "Please enter your email.";
            error_log("Login attempt - empty email");
        } else {
            $email = trim($_POST["email"] ?? '');
            error_log("Login attempt - Email: '" . $email . "'");
        }

        // Validate password
        if (!isset($_POST["password"]) || empty(trim($_POST["password"] ?? ''))) {
            $password_err = "Please enter your password.";
            error_log("Login attempt - empty password");
        } else {
            $password = trim($_POST["password"] ?? '');
            if (strlen($password) < 8) {
                $password_err = "Password must be at least 8 characters long.";
                error_log("Login attempt - password too short");
            } else {
                error_log("Login attempt - Password provided");
            }
        }
        
        // Validate credentials
        if (empty($name_err) && empty($email_err) && empty($password_err)) {
            error_log("Starting login verification for email: " . $email);
            
            // First check if user exists
            $sql = "SELECT id, name, email, password FROM users WHERE email = ?";
            error_log("Executing SQL: " . $sql . " with email: " . $email);
            
            if ($stmt = mysqli_prepare($conn, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $email);
                
                if (mysqli_stmt_execute($stmt)) {
                    mysqli_stmt_store_result($stmt);
                    
                    if (mysqli_stmt_num_rows($stmt) == 1) {
                        mysqli_stmt_bind_result($stmt, $user_id, $db_name, $db_email, $hashed_password);
                        mysqli_stmt_fetch($stmt);
                        
                        error_log("User found in database - ID: " . $user_id . ", Name: " . $db_name);
                        
                        // Verify password
                        if (password_verify($password, $hashed_password)) {
                            error_log("Password verified successfully");
                            
                            // Verify name matches (case-insensitive and trimmed)
                            if (strtolower(trim($name)) !== strtolower(trim($db_name))) {
                                error_log("Name Mismatch - Input: '" . $name . "' vs Stored: '" . $db_name . "'");
                                $name_err = "Name does not match our records.";
                            } else {
                                // Store user details in session
                                $_SESSION['user_id'] = $user_id;
                                $_SESSION['user_name'] = $db_name;
                                $_SESSION['user_email'] = $db_email;
                                $_SESSION['login_time'] = date('Y-m-d H:i:s');
                                
                                // Generate and send OTP
                                $otp = generateOTP();
                                if (sendOTPEmail($email, $otp) && storeOTP($email, $otp)) {
                                    error_log("OTP sent successfully to: " . $email);
                                    $_SESSION['email'] = $email;
                                    $_SESSION['name'] = $name;
                                    $show_otp_form = true;
                                    $success_message = "Verification code has been sent to your email!";
                                } else {
                                    error_log("Failed to send OTP to: " . $email);
                                    $email_err = "Failed to send verification code. Please try again.";
                                }
                            }
                        } else {
                            error_log("Password verification failed for user: " . $email);
                            $password_err = "Invalid password.";
                        }
                    } else {
                        error_log("No user found with email: " . $email);
                        $email_err = "No account found with that email. Please sign up first.";
                    }
                } else {
                    error_log("Error executing statement: " . mysqli_error($conn));
                    $email_err = "Something went wrong. Please try again later.";
                }
                mysqli_stmt_close($stmt);
            } else {
                error_log("Error preparing statement: " . mysqli_error($conn));
                $email_err = "Something went wrong. Please try again later.";
            }
        }
    } elseif (isset($_POST['verify_otp'])) {
        if (empty($_POST["otp"])) {
            $otp_err = "Please enter the verification code.";
        } else {
            $otp = implode('', $_POST["otp"]);
            $email = $_SESSION['email'];
            
            // Verify OTP
            $sql = "SELECT * FROM otp_verification WHERE email = ? AND otp = ? AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
            if ($stmt = mysqli_prepare($conn, $sql)) {
                mysqli_stmt_bind_param($stmt, "ss", $email, $otp);
                if (mysqli_stmt_execute($stmt)) {
                    mysqli_stmt_store_result($stmt);
                    if (mysqli_stmt_num_rows($stmt) == 1) {
                        // OTP is valid, complete login
                        $_SESSION['loggedin'] = true;
                        
                        // Clear OTP data
                        $sql = "DELETE FROM otp_verification WHERE email = ?";
                        if ($stmt = mysqli_prepare($conn, $sql)) {
                            mysqli_stmt_bind_param($stmt, "s", $email);
                            mysqli_stmt_execute($stmt);
                        }
                        
                        // Set success message
                        $success_message = "Login successful! Welcome back, " . htmlspecialchars($_SESSION['user_name']) . "!";
                        
                        // Show success message and redirect
                        echo "<script>
                            alert('Login successful! Welcome back, " . htmlspecialchars($_SESSION['user_name']) . "!');
                            window.location.href = 'dashboard.html';
                        </script>";
                        exit();
                    } else {
                        $otp_err = "Invalid or expired verification code. Please try again.";
                    }
                } else {
                    $otp_err = "Oops! Something went wrong. Please try again later.";
                }
                mysqli_stmt_close($stmt);
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login - Addwise</title>
    <link rel="stylesheet" href="form.css">
    <style>
        .error-message, .success-message {
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            display: none;
        }
        .error-message {
            color: #dc3545;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
        }
        .success-message {
            color: #28a745;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
        }
        .otp-container {
            display: none;
        }
        .otp-inputs {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin: 15px 0;
        }
        .otp-inputs input {
            width: 40px;
            height: 40px;
            text-align: center;
            font-size: 18px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: #1a1a2e;
            color: white;
        }
        .otp-inputs input:focus {
            border-color: #ffcc00;
            outline: none;
        }
        .resend-timer {
            text-align: center;
            color: #666;
            font-size: 14px;
            margin: 10px 0;
        }
        .back-link {
            text-align: center;
            margin-top: 10px;
        }
        .back-link a {
            color: #ffcc00;
            text-decoration: none;
        }
        .back-link a:hover {
            text-decoration: underline;
        }
        .form-container {
            background: rgba(64, 3, 3, 0.05);
            backdrop-filter: blur(10px);
            padding: 30px 40px;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            width: 100%;
            max-width: 400px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #ffcc00;
            color: black;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
        }
        button:hover {
            background: #fff;
            transform: translateY(-2px);
        }
        .password-toggle {
            position: relative;
            display: inline-block;
            width: 100%;
        }
        .password-toggle input {
            padding-right: 40px;
        }
        .password-toggle .toggle-btn {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #666;
            cursor: pointer;
            padding: 0;
            width: auto;
        }
        .password-toggle .toggle-btn:hover {
            color: #ffcc00;
            background: none;
            transform: translateY(-50%);
        }
    </style>
</head>
<body>
    <div class="form-container">
        <form id="loginForm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" 
              style="display: <?php echo $show_otp_form ? 'none' : 'block'; ?>">
            <h2>Login to Addwise</h2>
            
            <div class="error-message" style="display: <?php echo !empty($name_err) ? 'block' : 'none'; ?>">
                <?php echo $name_err; ?>
            </div>

            <div class="error-message" style="display: <?php echo !empty($email_err) ? 'block' : 'none'; ?>">
                <?php echo $email_err; ?>
            </div>

            <div class="error-message" style="display: <?php echo !empty($password_err) ? 'block' : 'none'; ?>">
                <?php echo $password_err; ?>
            </div>

            <div class="success-message" style="display: <?php echo !empty($success_message) ? 'block' : 'none'; ?>">
                <?php echo htmlspecialchars($success_message); ?>
            </div>

            <label for="name">Full Name</label>
            <input type="text" id="name" name="name" required 
                   value="<?php echo $name; ?>"
                   pattern="[A-Za-z\s]+"
                   title="Please enter your full name (letters and spaces only)">

            <label for="email">Email Address</label>
            <input type="email" id="email" name="email" required 
                   value="<?php echo $email; ?>"
                   pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                   title="Please enter a valid email address">

            <label for="password">Password</label>
            <div class="password-toggle">
                <input type="password" id="password" name="password" required 
                       minlength="8"
                       title="Please enter your password">
                <button type="button" class="toggle-btn" onclick="togglePassword()">Show</button>
            </div>

            <div class="options">
                <a href="forget_password.html" style="color: #ffcc00; text-decoration: none;">Forgot Password?</a>
            </div>

            <button type="submit" name="send_otp">Continue to Verification</button>

            <p class="switch">Don't have an account? <a href="signup.php">Sign Up</a></p>
        </form>

        <form id="otpForm" class="otp-container" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"
              style="display: <?php echo $show_otp_form ? 'block' : 'none'; ?>">
            <h2>Enter Verification Code</h2>
            
            <div class="error-message" style="display: <?php echo !empty($otp_err) ? 'block' : 'none'; ?>">
                <?php echo $otp_err; ?>
            </div>

            <p style="text-align: center; color: #666; margin-bottom: 15px;">
                We've sent a verification code to <?php echo htmlspecialchars($email); ?>
            </p>

            <div class="otp-inputs">
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)">
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)">
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)">
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)">
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)">
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)">
            </div>

            <button type="submit" name="verify_otp">Verify Code</button>

            <div class="resend-timer">
                Resend code in <span id="timer">60</span>s
            </div>

            <div class="back-link">
                <a href="#" onclick="showLoginForm()">Back to login</a>
            </div>
        </form>
    </div>

    <script>
        function moveToNext(input) {
            if (input.value.length === 1) {
                const nextInput = input.nextElementSibling;
                if (nextInput) {
                    nextInput.focus();
                }
            }
        }

        function showLoginForm() {
            document.getElementById('otpForm').style.display = 'none';
            document.getElementById('loginForm').style.display = 'block';
            resetOTPInputs();
        }

        function resetOTPInputs() {
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            otpInputs.forEach(input => {
                input.value = '';
            });
            otpInputs[0].focus();
        }

        function startTimer() {
            let timeLeft = 60;
            const timerSpan = document.getElementById('timer');
            const timer = setInterval(() => {
                timeLeft--;
                timerSpan.textContent = timeLeft;
                if (timeLeft <= 0) {
                    clearInterval(timer);
                    document.querySelector('.resend-timer').innerHTML = 
                        '<a href="#" onclick="resendOTP()" style="color: #ffcc00; text-decoration: none;">Resend code</a>';
                }
            }, 1000);
        }

        async function resendOTP() {
            const email = document.getElementById('email').value;
            try {
                const response = await fetch('resend_otp.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'email=' + encodeURIComponent(email)
                });
                const data = await response.json();
                if (data.success) {
                    alert('New verification code sent!');
                    resetOTPInputs();
                    startTimer();
                } else {
                    alert(data.message || 'Failed to resend code. Please try again.');
                }
            } catch (error) {
                alert('Failed to resend code. Please try again.');
            }
        }

        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const toggleBtn = document.querySelector('.toggle-btn');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleBtn.textContent = 'Hide';
            } else {
                passwordInput.type = 'password';
                toggleBtn.textContent = 'Show';
            }
        }

        if (document.getElementById('otpForm').style.display === 'block') {
            startTimer();
            document.querySelector('.otp-inputs input').focus();
        }
    </script>
</body>
</html>
<?php

mysqli_close($conn);
?> 