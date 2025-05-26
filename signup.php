<?php
require_once 'config.php';
require_once 'auth.php';

// Remove session_start() since it's handled in Auth class
$name = $email = $password = $confirm_password = "";
$name_err = $email_err = $password_err = $confirm_password_err = $otp_err = "";
$show_otp_form = false;
$success_message = "";

// Initialize Auth class
$auth = new Auth($conn);

// Process registration form
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['register'])) {
        // Validate name
        if (empty(trim($_POST["name"] ?? ''))) {
            $name_err = "Please enter your name.";
            error_log("Registration attempt - empty name");
        } else {
            $name = trim($_POST["name"]);
            if (!preg_match('/^[a-zA-Z\s]+$/', $name)) {
                $name_err = "Name can only contain letters and spaces.";
                error_log("Registration attempt - invalid name format: " . $name);
            }
        }
        
        // Validate email
        if (empty(trim($_POST["email"] ?? ''))) {
            $email_err = "Please enter your email.";
            error_log("Registration attempt - empty email");
        } else {
            $email = trim($_POST["email"]);
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $email_err = "Please enter a valid email address.";
                error_log("Registration attempt - invalid email format: " . $email);
            } else {
            // Check if email exists
                $result = $auth->checkEmailExists($email);
                if ($result['exists']) {
                    $email_err = "This email is already registered.";
                    error_log("Registration attempt - email already exists: " . $email);
                }
            }
        }
        
        // Validate password
        if (empty(trim($_POST["password"] ?? ''))) {
            $password_err = "Please enter a password.";     
            error_log("Registration attempt - empty password");
        } else {
            $password = trim($_POST["password"]);
            if (strlen($password) < 8) {
                $password_err = "Password must have at least 8 characters.";
                error_log("Registration attempt - password too short");
            } elseif (!preg_match('/[A-Z]/', $password)) {
                $password_err = "Password must contain at least one uppercase letter.";
                error_log("Registration attempt - password missing uppercase");
            } elseif (!preg_match('/[a-z]/', $password)) {
                $password_err = "Password must contain at least one lowercase letter.";
                error_log("Registration attempt - password missing lowercase");
            } elseif (!preg_match('/[0-9]/', $password)) {
                $password_err = "Password must contain at least one number.";
                error_log("Registration attempt - password missing number");
            } elseif (!preg_match('/[^A-Za-z0-9]/', $password)) {
                $password_err = "Password must contain at least one special character.";
                error_log("Registration attempt - password missing special character");
            }
        }
        
        // Validate confirm password
        if (empty(trim($_POST["confirm_password"] ?? ''))) {
            $confirm_password_err = "Please confirm password.";
            error_log("Registration attempt - empty confirm password");
        } else {
            $confirm_password = trim($_POST["confirm_password"]);
            if ($password != $confirm_password) {
                $confirm_password_err = "Passwords did not match.";
                error_log("Registration attempt - passwords do not match");
            }
        }
        
        // If no validation errors, proceed with registration
        if (empty($name_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)) {
            $result = $auth->register($name, $email, $password);
            
            if ($result['success']) {
                // Store temporary data in session
                $_SESSION['temp_auth'] = [
                    'email' => $email,
                    'name' => $name
                ];
                $show_otp_form = true;
                $success_message = "Registration successful! Please verify your email with the code sent.";
                error_log("Registration successful, OTP sent to: " . $email);
            } else {
                $email_err = $result['message'];
                error_log("Registration failed: " . $result['message']);
            }
        }
    } elseif (isset($_POST['verify_otp'])) {
        if (!isset($_SESSION['temp_auth'])) {
            $otp_err = "Session expired. Please register again.";
            error_log("OTP verification failed - no temporary session data");
        } else {
            $email = $_SESSION['temp_auth']['email'];
            $otp = implode('', $_POST['otp'] ?? []);
            
            if (empty($otp)) {
                $otp_err = "Please enter the verification code.";
                error_log("OTP verification failed - empty OTP");
            } else {
                $result = $auth->verifyOTP($email, $otp, 'registration');
                
                if ($result['success']) {
                                    // Clear temporary session data
                    unset($_SESSION['temp_auth']);
                                    
                                    // Set success message and redirect
                    $_SESSION['success_message'] = "Registration completed successfully! You can now login.";
                    header("location: login.php");
                                    exit();
                                } else {
                    $otp_err = $result['message'];
                    error_log("OTP verification failed: " . $result['message']);
                }
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
            display: block;
        }
        .success-message {
            color: #28a745;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            display: block;
        }
        .otp-container {
            display: none;
        }
        .otp-inputs {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin: 15px 0;
            position: relative;
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
            position: relative;
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
        .otp-inputs input::after {
            content: '';
            position: absolute;
            right: -20px;
            top: 50%;
            transform: translateY(-50%);
            width: 16px;
            height: 16px;
            background-size: contain;
            background-repeat: no-repeat;
        }
        .otp-inputs input.valid::after {
            content: '✓';
            color: #28a745;
            position: absolute;
            right: -25px;
            top: 50%;
            transform: translateY(-50%);
        }
        .otp-inputs input.invalid::after {
            content: '✕';
            color: #dc3545;
            position: absolute;
            right: -25px;
            top: 50%;
            transform: translateY(-50%);
        }
        .otp-validation-status {
            text-align: center;
            margin-top: 10px;
            font-size: 14px;
            color: #666;
        }
        .otp-validation-status.valid {
            color: #28a745;
        }
        .otp-validation-status.invalid {
            color: #dc3545;
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
        #verifyButton {
            width: 100%;
            padding: 12px;
            background: #ffcc00;
            color: black;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
        }
        #verifyButton:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        #verifyButton.verifying {
            background: #ffcc00;
            cursor: wait;
        }
        #verifyButton.verifying::after {
            content: '...';
            position: absolute;
            right: 20px;
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

            <div class="form-group">
            <label for="name">Full Name</label>
            <input type="text" id="name" name="name" required 
                   value="<?php echo $name; ?>"
                   pattern="[A-Za-z\s]+"
                       title="Please enter your full name (letters and spaces only)"
                       oninput="validateName(this)">
                <span class="validation-icon" id="nameIcon"></span>
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
                   minlength="8"
                       title="Password must be at least 8 characters long and include uppercase, lowercase, number, and special character"
                       oninput="validatePassword(this)">
                <span class="validation-icon" id="passwordIcon"></span>
            </div>
            
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

            <div class="form-group">
            <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required
                       oninput="validateConfirmPassword(this)">
                <span class="validation-icon" id="confirmPasswordIcon"></span>
            </div>

            <button type="submit" name="register" id="registerButton" disabled>Create Account</button>

            <p class="switch">Already have an account? <a href="login.php">Login</a></p>
        </form>

        <form id="otpForm" class="otp-container" action="verify_otp.php" method="post"
              style="display: <?php echo $show_otp_form ? 'block' : 'none'; ?>"
              onsubmit="return handleOTPSubmit(event)">
            <h2>Enter Verification Code</h2>
            
            <div id="otpError" class="error-message" style="display: none;"></div>
            <div id="otpSuccess" class="success-message" style="display: none;"></div>
            <div id="verificationStatus" style="display: none;"></div>

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
                <a href="#" onclick="return showSignupForm()">Back to signup</a>
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

        function validateOTPInput(input) {
            const value = input.value.trim();
            const isValid = /^[0-9]$/.test(value);
            
            // Remove existing classes
            input.classList.remove('valid', 'invalid');
            
            if (value.length === 1) {
                if (isValid) {
                    input.classList.add('valid');
                    // Move to next input
                const nextInput = input.nextElementSibling;
                if (nextInput) {
                    nextInput.focus();
                    }
                } else {
                    input.classList.add('invalid');
                    input.value = ''; // Clear invalid input
                }
            }
            
            // Update validation status
            updateOTPValidationStatus();
            
            // Enable/disable verify button
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            const allValid = Array.from(otpInputs).every(input => 
                input.value.length === 1 && input.classList.contains('valid')
            );
            document.getElementById('verifyButton').disabled = !allValid;
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
                } else {
                    validationStatus.textContent = 'Please enter valid digits only';
                    validationStatus.className = 'otp-validation-status invalid';
                }
            }
        }

        function handleOTPSubmit(event) {
            event.preventDefault();
            
            const form = document.getElementById('otpForm');
            const submitButton = document.getElementById('verifyButton');
            const otpInputs = document.querySelectorAll('.otp-inputs input');
            const verificationStatus = document.getElementById('verificationStatus');
            
            // Clear previous messages
            document.getElementById('otpError').style.display = 'none';
            document.getElementById('otpSuccess').style.display = 'none';
            verificationStatus.style.display = 'none';
            
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
                    showSuccess(data.message || 'Verification successful! Your account has been created.');
                    otpInputs.forEach(input => {
                        input.disabled = true;
                        input.classList.add('valid');
                    });
                    submitButton.style.display = 'none';
                    
                    // Add login button
                    const loginButton = document.createElement('button');
                    loginButton.type = 'button';
                    loginButton.textContent = 'Go to Login';
                    loginButton.style.marginTop = '15px';
                    loginButton.onclick = function() {
                        window.location.href = 'login.php';
                    };
                    submitButton.parentNode.insertBefore(loginButton, submitButton.nextSibling);
                    
                    document.querySelector('.resend-timer').style.display = 'none';
                    document.querySelector('.back-link').style.display = 'none';
                } else {
                    showError(data.message || 'Invalid verification code. Please try again.');
                    submitButton.disabled = false;
                    submitButton.textContent = 'Verify Code';
                    
                    // Reset OTP inputs on error
            otpInputs.forEach(input => {
                input.value = '';
                        input.disabled = false;
                        input.classList.remove('valid', 'invalid');
                    });
                    otpInputs[0].focus();
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

        // Add this to your existing script
        if (DEBUG) {
            // Log when the page loads
            logDebug('Page loaded');
            logDebug('Session status:', '<?php echo isset($_SESSION['temp_auth']) ? 'Active' : 'Expired'; ?>');
            logDebug('Email:', '<?php echo htmlspecialchars($email); ?>');
        }

        // Add validation functions
        function validateName(input) {
            const value = input.value.trim();
            const isValid = /^[a-zA-Z\s]+$/.test(value) && value.length > 0;
            updateValidationStatus(input, isValid, 'nameIcon');
            validateForm();
        }

        function validateEmail(input) {
            const value = input.value.trim();
            const isValid = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value);
            updateValidationStatus(input, isValid, 'emailIcon');
            validateForm();
        }

        function validatePassword(input) {
            const value = input.value;
            const requirements = {
                length: value.length >= 8,
                uppercase: /[A-Z]/.test(value),
                lowercase: /[a-z]/.test(value),
                number: /[0-9]/.test(value),
                special: /[^A-Za-z0-9]/.test(value)
            };
            
            // Update requirement indicators
            Object.keys(requirements).forEach(req => {
                const element = document.getElementById(req);
                if (requirements[req]) {
                    element.classList.add('valid');
                } else {
                    element.classList.remove('valid');
                }
            });
            
            const isValid = Object.values(requirements).every(Boolean);
            updateValidationStatus(input, isValid, 'passwordIcon');
            validateForm();
            
            // Update confirm password validation if it has a value
            const confirmPassword = document.getElementById('confirm_password');
            if (confirmPassword.value) {
                validateConfirmPassword(confirmPassword);
            }
        }

        function validateConfirmPassword(input) {
            const password = document.getElementById('password').value;
            const value = input.value;
            const isValid = value === password && value.length > 0;
            updateValidationStatus(input, isValid, 'confirmPasswordIcon');
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
            const name = document.getElementById('name');
            const email = document.getElementById('email');
            const password = document.getElementById('password');
            const confirmPassword = document.getElementById('confirm_password');
            
            const isNameValid = name.classList.contains('valid');
            const isEmailValid = email.classList.contains('valid');
            const isPasswordValid = password.classList.contains('valid');
            const isConfirmPasswordValid = confirmPassword.classList.contains('valid');
            
            const registerButton = document.getElementById('registerButton');
            registerButton.disabled = !(isNameValid && isEmailValid && isPasswordValid && isConfirmPasswordValid);
        }

        // Initialize validation on page load
        document.addEventListener('DOMContentLoaded', function() {
            const inputs = document.querySelectorAll('#signupForm input');
            inputs.forEach(input => {
                if (input.value) {
                    const event = new Event('input');
                    input.dispatchEvent(event);
                }
            });
        });
    </script>
</body>
</html>
<?php
// Close connection
mysqli_close($conn);
?> 