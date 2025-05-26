<?php
require_once 'config.php';
require_once 'auth.php';

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

$email = $password = "";
$email_err = $password_err = $login_err = "";
$show_otp_form = false;

// Initialize Auth class
$auth = new Auth($conn);

// Process login form
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['login'])) {
        error_log("=== Login Attempt Started ===");
        error_log("POST data: " . print_r($_POST, true));

        // Validate email
        if (empty(trim($_POST["email"] ?? ''))) {
            $email_err = "Please enter your email.";
            error_log("Login attempt - empty email");
        } else {
            $email = trim($_POST["email"]);
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $email_err = "Please enter a valid email address.";
                error_log("Login attempt - invalid email format: " . $email);
            } else {
                error_log("Email validation passed: " . $email);
            }
        }

        // Validate password
        if (empty(trim($_POST["password"] ?? ''))) {
            $password_err = "Please enter your password.";
            error_log("Login attempt - empty password");
        } else {
            $password = trim($_POST["password"]);
            error_log("Password validation passed (length: " . strlen($password) . ")");
        }
        
        // If no validation errors, proceed with login
        if (empty($email_err) && empty($password_err)) {
            error_log("Form validation passed, attempting login...");
            
            // Check if user exists before login attempt
            $check_user_sql = "SELECT id, email, status FROM users WHERE email = ?";
            $check_stmt = mysqli_prepare($conn, $check_user_sql);
            mysqli_stmt_bind_param($check_stmt, "s", $email);
            mysqli_stmt_execute($check_stmt);
            $check_result = mysqli_stmt_get_result($check_stmt);
            if ($user_data = mysqli_fetch_assoc($check_result)) {
                error_log("User found in database - ID: " . $user_data['id'] . ", Status: " . $user_data['status']);
            } else {
                error_log("No user found with email: " . $email);
            }
            mysqli_stmt_close($check_stmt);
            
            $result = $auth->login($email, $password);
            error_log("Login attempt result: " . print_r($result, true));
            
            if ($result['success']) {
                if ($result['requires_otp']) {
                    // Store temporary data in session
                    $_SESSION['temp_auth'] = [
                        'email' => $email,
                        'purpose' => 'login'
                    ];
                                    $show_otp_form = true;
                    error_log("Login OTP sent to: " . $email);
                } else {
                    // Login successful, redirect to dashboard
                    error_log("Login successful, redirecting to dashboard");
                    header("location: dashboard.php");
                    exit();
                }
            } else {
                $login_err = $result['message'];
                error_log("Login failed: " . $result['message']);
            }
        } else {
            error_log("Form validation failed - Email error: " . $email_err . ", Password error: " . $password_err);
        }
        error_log("=== Login Attempt Ended ===");
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
        .form-container {
            background: rgba(64, 3, 3, 0.05);
            backdrop-filter: blur(10px);
            padding: 30px 40px;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            width: 100%;
            max-width: 400px;
        }
        
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
            display: block;
        }
        
        .success-message {
            color: #28a745;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            display: block;
        }
        
        .form-group {
            position: relative;
            margin-bottom: 20px;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: #1a1a2e;
            color: white;
            transition: all 0.3s;
        }
        
        .form-group input:focus {
            border-color: #ffcc00;
            outline: none;
            box-shadow: 0 0 0 2px rgba(255, 204, 0, 0.2);
        }
        
        .form-group input.valid {
            border-color: #28a745;
            background-color: rgba(40, 167, 69, 0.1);
        }
        
        .form-group input.invalid {
            border-color: #dc3545;
            background-color: rgba(220, 53, 69, 0.1);
        }
        
        .validation-icon {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 18px;
            display: none;
        }
        
        .validation-icon.valid {
            display: block;
            color: #28a745;
        }
        
        .validation-icon.invalid {
            display: block;
            color: #dc3545;
        }
        
        button[type="submit"] {
            width: 100%;
            padding: 12px;
            background: #ffcc00;
            color: black;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            margin-top: 20px;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        button[type="submit"]:hover {
            background: #fff;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        
        button[type="submit"]:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
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
        
        .otp-inputs input.valid {
            border-color: #28a745;
            background-color: rgba(40, 167, 69, 0.1);
        }
        
        .otp-inputs input.invalid {
            border-color: #dc3545;
            background-color: rgba(220, 53, 69, 0.1);
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
        
        .forgot-password {
            text-align: right;
            margin-top: -15px;
            margin-bottom: 15px;
        }
        
        .forgot-password a {
            color: #ffcc00;
            text-decoration: none;
            font-size: 14px;
        }
        
        .forgot-password a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <form id="loginForm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" 
              style="display: <?php echo $show_otp_form ? 'none' : 'block'; ?>">
            <h2>Login to Your Account</h2>
            
            <div class="error-message" style="display: <?php echo !empty($login_err) ? 'block' : 'none'; ?>">
                <?php echo $login_err; ?>
            </div>
            <div class="error-message" style="display: <?php echo !empty($email_err) ? 'block' : 'none'; ?>">
                <?php echo $email_err; ?>
            </div>
            <div class="error-message" style="display: <?php echo !empty($password_err) ? 'block' : 'none'; ?>">
                <?php echo $password_err; ?>
            </div>

            <div class="form-group">
            <label for="email">Email Address</label>
            <input type="email" id="email" name="email" required 
                   value="<?php echo $email; ?>"
                   pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                       title="Please enter a valid email address"
                       oninput="validateEmail(this)">
                <span class="validation-icon" id="emailIcon"></span>
            </div>

            <div class="form-group">
            <label for="password">Password</label>
                <input type="password" id="password" name="password" required 
                       oninput="validatePassword(this)">
                <span class="validation-icon" id="passwordIcon"></span>
            </div>

            <div class="forgot-password">
                <a href="forgot_password.php">Forgot Password?</a>
            </div>

            <button type="submit" name="login" id="loginButton" disabled>Login</button>

            <p class="switch">Don't have an account? <a href="signup.php">Sign Up</a></p>
        </form>

        <form id="otpForm" class="otp-container" action="verify_otp.php" method="post"
              style="display: <?php echo $show_otp_form ? 'block' : 'none'; ?>"
              onsubmit="return handleOTPSubmit(event)">
            <h2>Enter Verification Code</h2>
            
            <div id="otpError" class="error-message" style="display: none;"></div>
            <div id="otpSuccess" class="success-message" style="display: none;"></div>

            <p style="text-align: center; color: #666; margin-bottom: 15px;">
                We've sent a verification code to <?php echo htmlspecialchars($email); ?>
            </p>

            <input type="hidden" name="email" value="<?php echo htmlspecialchars($email); ?>">

            <div class="otp-inputs">
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
                <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" name="otp[]" 
                       onkeyup="validateOTPInput(this)" oninput="validateOTPInput(this)" required>
            </div>

            <div id="otpValidationStatus" class="otp-validation-status"></div>

            <button type="submit" name="verify_otp" id="verifyButton" disabled>Verify Code</button>

            <div class="resend-timer">
                Resend code in <span id="timer">60</span>s
            </div>

            <div class="back-link">
                <a href="#" onclick="return showLoginForm()">Back to login</a>
            </div>
        </form>
    </div>

    <script>
        // Add debug mode
        const DEBUG = true;

        function logDebug(...args) {
            if (DEBUG) {
                console.log('[DEBUG]', ...args);
            }
        }

        function validateEmail(input) {
            const value = input.value.trim();
            const isValid = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value);
            updateValidationStatus(input, isValid, 'emailIcon');
            validateForm();
        }

        function validatePassword(input) {
            const value = input.value;
            const isValid = value.length >= 8;
            updateValidationStatus(input, isValid, 'passwordIcon');
            validateForm();
        }

        function updateValidationStatus(input, isValid, iconId) {
            input.classList.remove('valid', 'invalid');
            const icon = document.getElementById(iconId);
            icon.classList.remove('valid', 'invalid');
            
            if (input.value.length > 0) {
                input.classList.add(isValid ? 'valid' : 'invalid');
                icon.classList.add(isValid ? 'valid' : 'invalid');
                icon.textContent = isValid ? '✓' : '✕';
            }
        }

        function validateForm() {
            const email = document.getElementById('email');
            const password = document.getElementById('password');
            
            const isEmailValid = email.classList.contains('valid');
            const isPasswordValid = password.classList.contains('valid');
            
            const loginButton = document.getElementById('loginButton');
            loginButton.disabled = !(isEmailValid && isPasswordValid);
        }

        function validateOTPInput(input) {
            const value = input.value.trim();
            const isValid = /^[0-9]$/.test(value);
            
            input.classList.remove('valid', 'invalid');
            
            if (value.length === 1) {
                if (isValid) {
                    input.classList.add('valid');
                const nextInput = input.nextElementSibling;
                if (nextInput) {
                    nextInput.focus();
                    }
                } else {
                    input.classList.add('invalid');
                    input.value = '';
                }
            }
            
            updateOTPValidationStatus();
        }

        function updateOTPValidationStatus() {
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            const validationStatus = document.getElementById('otpValidationStatus');
            const filledInputs = Array.from(otpInputs).filter(input => input.value.length === 1).length;
            
            if (filledInputs === 0) {
                validationStatus.textContent = 'Enter the 6-digit verification code';
                validationStatus.className = 'otp-validation-status';
            } else if (filledInputs < 6) {
                validationStatus.textContent = `Enter ${6 - filledInputs} more digit${6 - filledInputs === 1 ? '' : 's'}`;
                validationStatus.className = 'otp-validation-status';
            } else {
                const allValid = Array.from(otpInputs).every(input => 
                    input.value.length === 1 && input.classList.contains('valid')
                );
                if (allValid) {
                    validationStatus.textContent = 'Verification code is valid';
                    validationStatus.className = 'otp-validation-status valid';
                    document.getElementById('verifyButton').disabled = false;
                } else {
                    validationStatus.textContent = 'Please enter valid digits only';
                    validationStatus.className = 'otp-validation-status invalid';
                    document.getElementById('verifyButton').disabled = true;
                }
            }
        }

        function handleOTPSubmit(event) {
            event.preventDefault();
            
            const form = document.getElementById('otpForm');
            const submitButton = document.getElementById('verifyButton');
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            
            // Clear previous messages
            document.getElementById('otpError').style.display = 'none';
            document.getElementById('otpSuccess').style.display = 'none';
            
            // Validate all inputs
            let otp = [];
            let isValid = true;
            
            otpInputs.forEach((input, index) => {
                const value = input.value.trim();
                if (!value || !/^[0-9]$/.test(value)) {
                    isValid = false;
                    input.classList.add('invalid');
                } else {
                    input.classList.add('valid');
                    otp.push(value);
                }
            });

            if (!isValid || otp.length !== 6) {
                showError('Please enter a valid 6-digit verification code');
                return false;
            }

            // Show loading state
            submitButton.disabled = true;
            submitButton.classList.add('verifying');
            submitButton.textContent = 'Verifying...';
            
            // Create FormData object
            const formData = new FormData();
            const email = form.querySelector('input[name="email"]').value;
            formData.append('email', email);
            otp.forEach((digit, index) => {
                formData.append('otp[]', digit);
            });

            // Log the request
            if (DEBUG) {
                logDebug('Sending OTP verification request', {
                    email: email,
                    otp: otp.join('')
                });
            }

            // Submit form using fetch
            fetch('verify_otp.php', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (DEBUG) {
                    logDebug('Received response status:', response.status);
                }
                return response.json();
            })
            .then(data => {
                if (DEBUG) {
                    logDebug('Received response data:', data);
                }
                
                submitButton.classList.remove('verifying');
                
                if (data.success) {
                    showSuccess(data.message || 'Login successful!');
                    otpInputs.forEach(input => {
                        input.disabled = true;
                        input.classList.add('valid');
                    });
                    submitButton.style.display = 'none';
                    
                    // Redirect to dashboard after successful login
                    setTimeout(() => {
                        window.location.href = 'dashboard.php';
                    }, 1500);
                } else {
                    showError(data.message || 'Invalid verification code. Please try again.');
                    submitButton.disabled = false;
                    submitButton.textContent = 'Verify Code';
            resetOTPInputs();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                if (DEBUG) {
                    logDebug('Error during verification:', error);
                }
                submitButton.classList.remove('verifying');
                showError('Something went wrong. Please try again.');
                submitButton.disabled = false;
                submitButton.textContent = 'Verify Code';
            });

            return false;
        }

        function showError(message) {
            const errorDiv = document.getElementById('otpError');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            document.getElementById('otpSuccess').style.display = 'none';
            
            if (DEBUG) {
                logDebug('Showing error message:', message);
            }
        }

        function showSuccess(message) {
            const successDiv = document.getElementById('otpSuccess');
            successDiv.textContent = message;
            successDiv.style.display = 'block';
            document.getElementById('otpError').style.display = 'none';
            
            if (DEBUG) {
                logDebug('Showing success message:', message);
            }
        }

        function resetOTPInputs() {
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            otpInputs.forEach(input => {
                input.value = '';
                input.disabled = false;
                input.classList.remove('valid', 'invalid');
            });
            otpInputs[0].focus();
            
            document.getElementById('otpError').style.display = 'none';
            document.getElementById('otpSuccess').style.display = 'none';
            document.getElementById('otpValidationStatus').textContent = 'Enter the 6-digit verification code';
            document.getElementById('otpValidationStatus').className = 'otp-validation-status';
            
            const verifyButton = document.getElementById('verifyButton');
            verifyButton.disabled = true;
            verifyButton.textContent = 'Verify Code';
            verifyButton.style.display = 'block';
        }

        function showLoginForm() {
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('otpForm').style.display = 'none';
            return false;
        }

        // Start timer if OTP form is shown
        if (document.getElementById('otpForm').style.display === 'block') {
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
            document.querySelector('.otp-inputs input').focus();
        }

        // Initialize validation on page load
        document.addEventListener('DOMContentLoaded', function() {
            const inputs = document.querySelectorAll('#loginForm input');
            inputs.forEach(input => {
                if (input.value) {
                    const event = new Event('input');
                    input.dispatchEvent(event);
                }
            });
        });

        if (DEBUG) {
            logDebug('Page loaded');
            logDebug('Session status:', '<?php echo isset($_SESSION['temp_auth']) ? 'Active' : 'Expired'; ?>');
            logDebug('Email:', '<?php echo htmlspecialchars($email); ?>');
        }
    </script>
</body>
</html>
<?php
// Close connection
mysqli_close($conn);
?> 