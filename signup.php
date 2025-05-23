<?php
require_once 'config.php';
require_once 'email_handler.php';

session_start();

$name = $email = $password = $confirm_password = $otp = "";
$name_err = $email_err = $password_err = $confirm_password_err = $otp_err = "";
$show_otp_form = false;
$success_message = "";

// Process form data when form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['register'])) {
        error_log("=== Starting Registration Process ===");
        // Validate name
        if (empty(trim($_POST["name"]))) {
            $name_err = "Please enter your name.";
            error_log("Name validation failed - empty name");
        } else {
            $name = trim($_POST["name"]);
            if (!preg_match("/^[a-zA-Z ]*$/", $name)) {
                $name_err = "Name can only contain letters and spaces.";
                error_log("Name validation failed - invalid characters in name: " . $name);
            } elseif (strlen($name) < 2) {
                $name_err = "Name must be at least 2 characters long.";
                error_log("Name validation failed - name too short: " . $name);
            } else {
                error_log("Name validation successful: " . $name);
            }
        }
        
        // Validate email
        if (empty(trim($_POST["email"]))) {
            $email_err = "Please enter your email.";
            error_log("Email validation failed - empty email");
        } else {
            $email = trim($_POST["email"]);
            error_log("Validating email: " . $email);
            
            // Check if email exists
            $sql = "SELECT id FROM users WHERE email = ?";
            if ($stmt = mysqli_prepare($conn, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $email);
                if (mysqli_stmt_execute($stmt)) {
                    mysqli_stmt_store_result($stmt);
                    if (mysqli_stmt_num_rows($stmt) > 0) {
                        $email_err = "This email is already registered. Please login instead.";
                        error_log("Email validation failed - email already exists: " . $email);
                    } else {
                        error_log("Email validation successful - email is unique: " . $email);
                    }
                } else {
                    $email_err = "Oops! Something went wrong. Please try again later.";
                    error_log("Email validation failed - database error: " . mysqli_error($conn));
                }
                mysqli_stmt_close($stmt);
            }
        }
        
        // Validate password
        if (empty(trim($_POST["password"]))) {
            $password_err = "Please enter a password.";     
        } else {
            $password = trim($_POST["password"]);
            // Password validation rules
            $uppercase = preg_match('@[A-Z]@', $password);
            $lowercase = preg_match('@[a-z]@', $password);
            $number    = preg_match('@[0-9]@', $password);
            $specialChars = preg_match('@[^\w]@', $password);
            
            if(strlen($password) < 8) {
                $password_err = "Password must be at least 8 characters long.";
            } elseif(!$uppercase) {
                $password_err = "Password must contain at least one uppercase letter.";
            } elseif(!$lowercase) {
                $password_err = "Password must contain at least one lowercase letter.";
            } elseif(!$number) {
                $password_err = "Password must contain at least one number.";
            } elseif(!$specialChars) {
                $password_err = "Password must contain at least one special character.";
            }
        }
        
        // Validate confirm password
        if (empty(trim($_POST["confirm_password"]))) {
            $confirm_password_err = "Please confirm your password.";     
        } else {
            $confirm_password = trim($_POST["confirm_password"]);
            if (empty($password_err) && ($password != $confirm_password)) {
                $confirm_password_err = "Passwords do not match. Please try again.";
            }
        }
        
        // Check input errors before proceeding
        if (empty($name_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)) {
            error_log("All validations passed, proceeding with OTP generation");
            // Generate and send OTP
            $otp = generateOTP();
            if (sendOTPEmail($email, $otp) && storeOTP($email, $otp)) {
                error_log("OTP generated and stored successfully for email: " . $email);
                // Store user data in session
                $_SESSION['temp_user'] = [
                    'name' => $name,
                    'email' => $email,
                    'password' => password_hash($password, PASSWORD_DEFAULT)
                ];
                error_log("Temporary user data stored in session: " . print_r($_SESSION['temp_user'], true));
                $show_otp_form = true;
                $success_message = "Verification code has been sent to your email!";
            } else {
                $email_err = "Failed to send verification code. Please try again.";
                error_log("Failed to send/store OTP for email: " . $email);
            }
        } else {
            error_log("Registration validation failed - Name error: " . $name_err . ", Email error: " . $email_err . ", Password error: " . $password_err . ", Confirm password error: " . $confirm_password_err);
        }
    } elseif (isset($_POST['verify_otp'])) {
        error_log("=== OTP Verification Attempt ===");
        error_log("POST data: " . print_r($_POST, true));
        error_log("Session data: " . print_r($_SESSION, true));
        
        if (empty($_POST["otp"])) {
            $otp_err = "Please enter the verification code.";
            error_log("OTP verification failed - empty OTP");
        } else {
            $otp = implode('', $_POST["otp"]);
            
            // Check if we have the temporary user data
            if (!isset($_SESSION['temp_user'])) {
                error_log("Session data missing - temp_user not found");
                $otp_err = "Session expired. Please try registering again.";
                echo "<script>alert('Session expired. Please try registering again.');</script>";
            } else {
                $email = $_SESSION['temp_user']['email'];
                $name = $_SESSION['temp_user']['name'];
                $hashed_password = $_SESSION['temp_user']['password'];
                
                error_log("Verifying OTP for email: " . $email);
                error_log("Entered OTP: " . $otp);
                
                // Verify OTP
                $sql = "SELECT * FROM otp_verification WHERE email = ? AND otp = ? AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)";
                if ($stmt = mysqli_prepare($conn, $sql)) {
                    mysqli_stmt_bind_param($stmt, "ss", $email, $otp);
                    if (mysqli_stmt_execute($stmt)) {
                        mysqli_stmt_store_result($stmt);
                        if (mysqli_stmt_num_rows($stmt) == 1) {
                            error_log("OTP verified successfully");
                            
                            // Create user account
                            $sql = "INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, NOW())";
                            if ($stmt = mysqli_prepare($conn, $sql)) {
                                mysqli_stmt_bind_param($stmt, "sss", $name, $email, $hashed_password);
                                
                                if (mysqli_stmt_execute($stmt)) {
                                    error_log("User account created successfully");
                                    
                                    // Clear OTP data
                                    $sql = "DELETE FROM otp_verification WHERE email = ?";
                                    if ($stmt = mysqli_prepare($conn, $sql)) {
                                        mysqli_stmt_bind_param($stmt, "s", $email);
                                        mysqli_stmt_execute($stmt);
                                    }
                                    
                                    // Clear temporary session data
                                    unset($_SESSION['temp_user']);
                                    
                                    // Set success message and redirect
                                    $_SESSION['success_message'] = "Registration successful! You can now login.";
                                    echo "<script>
                                        alert('Registration successful! You can now login.');
                                        window.location.href = 'login.php';
                                    </script>";
                                    exit();
                                } else {
                                    error_log("Failed to create user account: " . mysqli_error($conn));
                                    $otp_err = "Registration failed. Please try again.";
                                    echo "<script>alert('Registration failed. Please try again.');</script>";
                                }
                            }
                        } else {
                            error_log("Invalid or expired OTP");
                            $otp_err = "Invalid or expired verification code. Please try again.";
                            echo "<script>alert('Invalid or expired verification code. Please try again.');</script>";
                        }
                    } else {
                        error_log("Database error during OTP verification: " . mysqli_error($conn));
                        $otp_err = "Something went wrong. Please try again.";
                        echo "<script>alert('Something went wrong. Please try again.');</script>";
                    }
                    mysqli_stmt_close($stmt);
                }
            }
        }
        error_log("=== End of OTP Verification Attempt ===");
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign Up - Addwise</title>
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
        .password-requirements {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            font-size: 13px;
            color: #666;
        }
        .password-requirements ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .password-requirements li {
            margin: 5px 0;
            list-style-type: none;
            position: relative;
            padding-left: 25px;
        }
        .password-requirements li:before {
            content: "✕";
            position: absolute;
            left: 0;
            color: #dc3545;
        }
        .password-requirements li.valid:before {
            content: "✓";
            color: #28a745;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <form id="signupForm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"
              style="display: <?php echo $show_otp_form ? 'none' : 'block'; ?>">
            <h2>Create Account</h2>
            
            <div class="error-message" style="display: <?php echo !empty($name_err) ? 'block' : 'none'; ?>">
                <?php echo $name_err; ?>
            </div>
            <div class="error-message" style="display: <?php echo !empty($email_err) ? 'block' : 'none'; ?>">
                <?php echo $email_err; ?>
            </div>
            <div class="error-message" style="display: <?php echo !empty($password_err) ? 'block' : 'none'; ?>">
                <?php echo $password_err; ?>
            </div>
            <div class="error-message" style="display: <?php echo !empty($confirm_password_err) ? 'block' : 'none'; ?>">
                <?php echo $confirm_password_err; ?>
            </div>

            <div class="success-message" style="display: <?php echo !empty($success_message) ? 'block' : 'none'; ?>">
                <?php echo $success_message; ?>
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
            <input type="password" id="password" name="password" required 
                   minlength="8"
                   title="Password must be at least 8 characters long and include uppercase, lowercase, number, and special character">
            
            <div class="password-requirements">
                <p>Password must contain:</p>
                <ul>
                    <li id="length">At least 8 characters</li>
                    <li id="uppercase">One uppercase letter</li>
                    <li id="lowercase">One lowercase letter</li>
                    <li id="number">One number</li>
                    <li id="special">One special character</li>
                </ul>
            </div>

            <label for="confirm_password">Confirm Password</label>
            <input type="password" id="confirm_password" name="confirm_password" required>

            <button type="submit" name="register">Continue to Verification</button>

            <p class="switch">Already have an account? <a href="login.php">Login</a></p>
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
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" onkeyup="moveToNext(this)" required>
            </div>

            <button type="submit" name="verify_otp">Verify Code</button>

            <div class="resend-timer">
                Resend code in <span id="timer">60</span>s
            </div>

            <div class="back-link">
                <a href="#" onclick="showSignupForm()">Back to signup</a>
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
            
            // Check if all inputs are filled
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            const allFilled = Array.from(otpInputs).every(input => input.value.length === 1);
            if (allFilled) {
                // Automatically submit the form when all digits are entered
                document.getElementById('otpForm').submit();
            }
        }

        function showSignupForm() {
            document.getElementById('otpForm').style.display = 'none';
            document.getElementById('signupForm').style.display = 'block';
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

        // Start timer if OTP form is shown
        if (document.getElementById('otpForm').style.display === 'block') {
            startTimer();
            document.querySelector('.otp-inputs input').focus();
        }

        const password = document.getElementById('password');
        const confirmPassword = document.getElementById('confirm_password');
        const requirements = {
            length: document.getElementById('length'),
            uppercase: document.getElementById('uppercase'),
            lowercase: document.getElementById('lowercase'),
            number: document.getElementById('number'),
            special: document.getElementById('special')
        };

        function validatePassword() {
            const value = password.value;
            
            // Check each requirement
            requirements.length.classList.toggle('valid', value.length >= 8);
            requirements.uppercase.classList.toggle('valid', /[A-Z]/.test(value));
            requirements.lowercase.classList.toggle('valid', /[a-z]/.test(value));
            requirements.number.classList.toggle('valid', /[0-9]/.test(value));
            requirements.special.classList.toggle('valid', /[^A-Za-z0-9]/.test(value));
            
            // Update confirm password validation
            if (confirmPassword.value) {
                confirmPassword.setCustomValidity(
                    confirmPassword.value === value ? '' : 'Passwords do not match'
                );
            }
        }

        function validateConfirmPassword() {
            confirmPassword.setCustomValidity(
                confirmPassword.value === password.value ? '' : 'Passwords do not match'
            );
        }

        password.addEventListener('input', validatePassword);
        confirmPassword.addEventListener('input', validateConfirmPassword);
    </script>
</body>
</html>
<?php
// Close connection
mysqli_close($conn);
?> 