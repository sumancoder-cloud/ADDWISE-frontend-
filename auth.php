<?php
require_once 'config.php';
require_once 'email_handler.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class Auth {
    private $conn;
    private $session_lifetime = 3600; // 1 hour
    private $max_login_attempts = 5;
    private $lockout_time = 900; // 15 minutes
    private $emailHandler;

    public function __construct($conn) {
        $this->conn = $conn;
        $this->emailHandler = new EmailHandler();
        $this->startSecureSession();
    }

    private function startSecureSession() {
        if (session_status() === PHP_SESSION_NONE) {
            // Set secure session parameters
            ini_set('session.cookie_httponly', 1);
            ini_set('session.cookie_secure', 1);
            ini_set('session.cookie_samesite', 'Strict');
            ini_set('session.gc_maxlifetime', $this->session_lifetime);
            
            session_start();
        }
    }

    public function register($name, $email, $password) {
        try {
            // Validate input
            if (!$this->validateRegistrationInput($name, $email, $password)) {
                return ['success' => false, 'message' => 'Invalid input data'];
            }

            // Check if email exists
            if ($this->emailExists($email)) {
                return ['success' => false, 'message' => 'Email already registered'];
            }

            // Hash password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            
            // Generate verification token
            $verification_token = bin2hex(random_bytes(32));
            
            // Begin transaction
            mysqli_begin_transaction($this->conn);
            
            try {
                // Insert user
                $sql = "INSERT INTO users (name, email, password, verification_token, created_at) 
                        VALUES (?, ?, ?, ?, NOW())";
                $stmt = mysqli_prepare($this->conn, $sql);
                mysqli_stmt_bind_param($stmt, "ssss", $name, $email, $hashed_password, $verification_token);
                
                if (!mysqli_stmt_execute($stmt)) {
                    throw new Exception("Failed to create user account");
                }
                
                $user_id = mysqli_insert_id($this->conn);
                
                // Create user preferences
                $sql = "INSERT INTO user_preferences (user_id) VALUES (?)";
                $stmt = mysqli_prepare($this->conn, $sql);
                mysqli_stmt_bind_param($stmt, "i", $user_id);
                
                if (!mysqli_stmt_execute($stmt)) {
                    throw new Exception("Failed to create user preferences");
                }
                
                // Log the registration
                $this->logAudit($user_id, 'registration', 'User registered successfully');
                
                // Generate and send OTP
                $otp = $this->generateOTP($email, 'registration');
                
                mysqli_commit($this->conn);
                
                return [
                    'success' => true,
                    'message' => 'Registration successful. Please verify your email.',
                    'user_id' => $user_id,
                    'verification_token' => $verification_token
                ];
                
            } catch (Exception $e) {
                mysqli_rollback($this->conn);
                throw $e;
            }
            
        } catch (Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Registration failed. Please try again.'];
        }
    }

    public function login($email, $password) {
        try {
            error_log("=== Auth::login Started ===");
            error_log("Attempting login for email: " . $email);
            
            // Check login attempts
            if ($this->isAccountLocked($email)) {
                error_log("Account is locked for email: " . $email);
                return [
                    'success' => false,
                    'message' => 'Account is temporarily locked. Please try again later.'
                ];
            }
            error_log("Account is not locked");

            // Get user
            $user = $this->getUserByEmail($email);
            if (!$user) {
                error_log("No user found with email: " . $email);
                $this->logFailedAttempt($email);
                return ['success' => false, 'message' => 'Invalid email or password'];
            }
            error_log("User found - ID: " . $user['id'] . ", Status: " . ($user['status'] ?? 'not set'));

            // Verify password
            error_log("Verifying password...");
            if (!password_verify($password, $user['password'])) {
                error_log("Password verification failed");
                $this->logFailedAttempt($email);
                $this->incrementLoginAttempts($user['id']);
                return ['success' => false, 'message' => 'Invalid email or password'];
            }
            error_log("Password verified successfully");

            // Check account status
            if (!isset($user['status']) || $user['status'] !== 'active') {
                error_log("Account is not active - Status: " . ($user['status'] ?? 'not set'));
                return [
                    'success' => false,
                    'message' => 'Account is not active. Please contact support.'
                ];
            }
            error_log("Account is active");

            // Reset login attempts on successful login
            $this->resetLoginAttempts($user['id']);
            error_log("Login attempts reset");

            // Generate OTP for 2FA
            error_log("Generating OTP for 2FA...");
            $otp = $this->generateOTP($email, 'login');
            if (!$otp) {
                error_log("Failed to generate OTP");
                return ['success' => false, 'message' => 'Failed to send verification code. Please try again.'];
            }
            error_log("OTP generated and sent successfully");

            // Store temporary session data
            $_SESSION['temp_auth'] = [
                'user_id' => $user['id'],
                'email' => $user['email'],
                'name' => $user['name'],
                'requires_2fa' => true
            ];
            error_log("Temporary session data stored");

            // Log successful login attempt
            $this->logAudit($user['id'], 'login_attempt', 'Login attempt successful, waiting for 2FA');
            error_log("Login attempt logged in audit");

            error_log("=== Auth::login Completed Successfully ===");
            return [
                'success' => true,
                'message' => 'Please enter the verification code sent to your email',
                'requires_2fa' => true
            ];

        } catch (Exception $e) {
            error_log("Login error: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            return ['success' => false, 'message' => 'Login failed. Please try again.'];
        }
    }

    public function verifyOTP($email, $otp, $purpose) {
        try {
            // Get the latest OTP
            $sql = "SELECT * FROM otp_verification 
                    WHERE email = ? AND purpose = ? AND is_used = FALSE 
                    AND expires_at > NOW() 
                    ORDER BY created_at DESC LIMIT 1";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "ss", $email, $purpose);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if (!$otp_data = mysqli_fetch_assoc($result)) {
                return ['success' => false, 'message' => 'Invalid or expired verification code'];
            }

            // Check attempts
            if ($otp_data['attempts'] >= 3) {
                return ['success' => false, 'message' => 'Too many attempts. Please request a new code'];
            }

            // Verify OTP
            if ($otp_data['otp'] !== $otp) {
                // Increment attempts
                $sql = "UPDATE otp_verification SET attempts = attempts + 1 WHERE id = ?";
                $stmt = mysqli_prepare($this->conn, $sql);
                mysqli_stmt_bind_param($stmt, "i", $otp_data['id']);
                mysqli_stmt_execute($stmt);

                return ['success' => false, 'message' => 'Invalid verification code'];
            }

            // Mark OTP as used
            $sql = "UPDATE otp_verification SET is_used = TRUE WHERE id = ?";
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "i", $otp_data['id']);
            mysqli_stmt_execute($stmt);

            // Handle different purposes
            switch ($purpose) {
                case 'registration':
                    return $this->completeRegistration($email);
                case 'login':
                    return $this->completeLogin($email);
                case 'password_reset':
                    return $this->completePasswordReset($email);
                default:
                    return ['success' => false, 'message' => 'Invalid verification purpose'];
            }

        } catch (Exception $e) {
            error_log("OTP verification error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Verification failed. Please try again.'];
        }
    }

    private function completeRegistration($email) {
        try {
            $user = $this->getUserByEmail($email);
            if (!$user) {
                return ['success' => false, 'message' => 'User not found'];
            }

            // Update user status to active and mark email as verified
            $sql = "UPDATE users SET 
                    status = 'active',
                    email_verified = TRUE,
                    verification_token = NULL 
                    WHERE id = ?";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "i", $user['id']);
            
            if (!mysqli_stmt_execute($stmt)) {
                throw new Exception("Failed to complete registration");
            }

            // Create session
            $session_token = $this->createSession($user['id']);

            // Log successful registration
            $this->logAudit($user['id'], 'registration_complete', 'Email verification completed');

            // Send welcome email
            $this->emailHandler->sendWelcome($email, $user['name']);

            // Set session data
            $_SESSION['user'] = [
                'id' => $user['id'],
                'name' => $user['name'],
                'email' => $user['email'],
                'role' => $user['role'],
                'session_token' => $session_token
            ];

            return [
                'success' => true,
                'message' => 'Registration completed successfully',
                'user' => [
                    'id' => $user['id'],
                    'name' => $user['name'],
                    'email' => $user['email'],
                    'role' => $user['role']
                ]
            ];
        } catch (Exception $e) {
            error_log("Registration completion error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to complete registration'];
        }
    }

    private function completePasswordReset($email) {
        try {
            $user = $this->getUserByEmail($email);
            if (!$user) {
                return ['success' => false, 'message' => 'User not found'];
            }

            // Clear password reset token
            $sql = "UPDATE users SET 
                    password_reset_token = NULL,
                    password_reset_expires = NULL 
                    WHERE id = ?";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "i", $user['id']);
            
            if (!mysqli_stmt_execute($stmt)) {
                throw new Exception("Failed to complete password reset");
            }

            // Log password reset completion
            $this->logAudit($user['id'], 'password_reset_complete', 'Password reset completed');

            return [
                'success' => true,
                'message' => 'Password reset completed successfully'
            ];

        } catch (Exception $e) {
            error_log("Password reset completion error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to complete password reset'];
        }
    }

    private function completeLogin($email) {
        $user = $this->getUserByEmail($email);
        if (!$user) {
            return ['success' => false, 'message' => 'User not found'];
        }

        // Create session
        $session_token = $this->createSession($user['id']);

        // Update last login
        $sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $user['id']);
        mysqli_stmt_execute($stmt);

        // Log successful login
        $this->logAudit($user['id'], 'login', 'User logged in successfully');

        // Set session data
        $_SESSION['user'] = [
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            'role' => $user['role'],
            'session_token' => $session_token
        ];

        unset($_SESSION['temp_auth']);

        return [
            'success' => true,
            'message' => 'Login successful',
            'user' => [
                'id' => $user['id'],
                'name' => $user['name'],
                'email' => $user['email'],
                'role' => $user['role']
            ]
        ];
    }

    private function createSession($user_id) {
        $session_token = bin2hex(random_bytes(32));
        $expires_at = date('Y-m-d H:i:s', time() + $this->session_lifetime);
        
        $sql = "INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, last_activity, expires_at) 
                VALUES (?, ?, ?, ?, NOW(), ?)";
        
        $stmt = mysqli_prepare($this->conn, $sql);
        $ip = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'];
        
        mysqli_stmt_bind_param($stmt, "issss", $user_id, $session_token, $ip, $user_agent, $expires_at);
        mysqli_stmt_execute($stmt);
        
        return $session_token;
    }

    public function logout() {
        if (isset($_SESSION['user']['session_token'])) {
            // Invalidate session
            $sql = "UPDATE user_sessions SET is_active = FALSE 
                    WHERE session_token = ? AND user_id = ?";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "si", $_SESSION['user']['session_token'], $_SESSION['user']['id']);
            mysqli_stmt_execute($stmt);

            // Log logout
            $this->logAudit($_SESSION['user']['id'], 'logout', 'User logged out');
        }

        // Clear session
        session_unset();
        session_destroy();
        
        return ['success' => true, 'message' => 'Logged out successfully'];
    }

    public function isLoggedIn() {
        if (!isset($_SESSION['user']['session_token'])) {
            return false;
        }

        // Verify session
        $sql = "SELECT * FROM user_sessions 
                WHERE session_token = ? AND user_id = ? 
                AND is_active = TRUE AND expires_at > NOW()";
        
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "si", $_SESSION['user']['session_token'], $_SESSION['user']['id']);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        if (!$session = mysqli_fetch_assoc($result)) {
            $this->logout();
            return false;
        }

        // Update last activity
        $sql = "UPDATE user_sessions SET last_activity = NOW() WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $session['id']);
        mysqli_stmt_execute($stmt);

        return true;
    }

    private function validateRegistrationInput($name, $email, $password) {
        // Validate name
        if (empty($name) || strlen($name) < 2 || !preg_match("/^[a-zA-Z ]*$/", $name)) {
            return false;
        }

        // Validate email
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }

        // Validate password
        if (empty($password) || strlen($password) < 8 ||
            !preg_match('/[A-Z]/', $password) || // uppercase
            !preg_match('/[a-z]/', $password) || // lowercase
            !preg_match('/[0-9]/', $password) || // number
            !preg_match('/[^A-Za-z0-9]/', $password)) { // special char
            return false;
        }

        return true;
    }

    private function emailExists($email) {
        $sql = "SELECT id FROM users WHERE email = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        return mysqli_stmt_num_rows($stmt) > 0;
    }

    private function getUserByEmail($email) {
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        return mysqli_fetch_assoc($result);
    }

    private function generateOTP($email, $purpose) {
        try {
            // Generate a 6-digit OTP
            $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            
            // Store OTP in database
            $sql = "INSERT INTO otp_verification (email, otp, purpose, created_at) 
                    VALUES (?, ?, ?, NOW())
                    ON DUPLICATE KEY UPDATE 
                    otp = VALUES(otp),
                    purpose = VALUES(purpose),
                    created_at = VALUES(created_at),
                    attempts = 0,
                    is_used = FALSE";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "sss", $email, $otp, $purpose);
            
            if (!mysqli_stmt_execute($stmt)) {
                throw new Exception("Failed to store OTP");
            }
            
            // Send OTP via email
            if (!$this->emailHandler->sendOTP($email, $otp, $purpose)) {
                throw new Exception("Failed to send OTP email");
            }
            
            return $otp;
            
        } catch (Exception $e) {
            error_log("OTP generation error: " . $e->getMessage());
            return false;
        }
    }

    private function isAccountLocked($email) {
        $sql = "SELECT COUNT(*) as attempts FROM login_attempts 
                WHERE email = ? AND success = FALSE 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL ? SECOND)";
        
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "si", $email, $this->lockout_time);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $row = mysqli_fetch_assoc($result);
        
        return $row['attempts'] >= $this->max_login_attempts;
    }

    private function logFailedAttempt($email) {
        $sql = "INSERT INTO login_attempts (email, ip_address, attempt_time) 
                VALUES (?, ?, NOW())";
        
        $stmt = mysqli_prepare($this->conn, $sql);
        $ip = $_SERVER['REMOTE_ADDR'];
        mysqli_stmt_bind_param($stmt, "ss", $email, $ip);
        mysqli_stmt_execute($stmt);
    }

    private function incrementLoginAttempts($user_id) {
        $sql = "UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        mysqli_stmt_execute($stmt);
    }

    private function resetLoginAttempts($user_id) {
        $sql = "UPDATE users SET login_attempts = 0 WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        mysqli_stmt_execute($stmt);
    }

    private function logAudit($user_id, $action, $description) {
        $sql = "INSERT INTO audit_log (user_id, action, description, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)";
        
        $stmt = mysqli_prepare($this->conn, $sql);
        $ip = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'];
        
        mysqli_stmt_bind_param($stmt, "issss", $user_id, $action, $description, $ip, $user_agent);
        mysqli_stmt_execute($stmt);
    }

    public function changePassword($user_id, $current_password, $new_password) {
        try {
            // Get user
            $sql = "SELECT password FROM users WHERE id = ?";
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "i", $user_id);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $user = mysqli_fetch_assoc($result);

            if (!$user || !password_verify($current_password, $user['password'])) {
                return ['success' => false, 'message' => 'Current password is incorrect'];
            }

            // Validate new password
            if (!$this->validatePassword($new_password)) {
                return ['success' => false, 'message' => 'New password does not meet requirements'];
            }

            // Update password
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $sql = "UPDATE users SET password = ? WHERE id = ?";
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "si", $hashed_password, $user_id);
            
            if (mysqli_stmt_execute($stmt)) {
                $this->logAudit($user_id, 'password_change', 'Password changed successfully');
                return ['success' => true, 'message' => 'Password changed successfully'];
            }

            return ['success' => false, 'message' => 'Failed to change password'];

        } catch (Exception $e) {
            error_log("Password change error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to change password'];
        }
    }

    private function validatePassword($password) {
        return strlen($password) >= 8 &&
               preg_match('/[A-Z]/', $password) &&
               preg_match('/[a-z]/', $password) &&
               preg_match('/[0-9]/', $password) &&
               preg_match('/[^A-Za-z0-9]/', $password);
    }

    public function requestPasswordReset($email) {
        try {
            $user = $this->getUserByEmail($email);
            if (!$user) {
                return ['success' => false, 'message' => 'Email not found'];
            }

            // Generate reset token
            $token = bin2hex(random_bytes(32));
            $expires = date('Y-m-d H:i:s', strtotime('+1 hour'));
            
            // Store reset token
            $sql = "UPDATE users SET 
                    reset_token = ?,
                    reset_token_expires = ?
                    WHERE id = ?";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "ssi", $token, $expires, $user['id']);
            
            if (!mysqli_stmt_execute($stmt)) {
                throw new Exception("Failed to store reset token");
            }

            // Send reset email
            if (!$this->emailHandler->sendPasswordReset($email, $token)) {
                throw new Exception("Failed to send reset email");
            }

            return ['success' => true, 'message' => 'Password reset instructions sent to your email'];
            
        } catch (Exception $e) {
            error_log("Password reset request error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to process password reset request'];
        }
    }

    public function resetPassword($token, $new_password) {
        try {
            // Validate token
            $sql = "SELECT id FROM users 
                    WHERE password_reset_token = ? 
                    AND password_reset_expires > NOW()";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "s", $token);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if (!$user = mysqli_fetch_assoc($result)) {
                return ['success' => false, 'message' => 'Invalid or expired reset token'];
            }

            // Validate new password
            if (!$this->validatePassword($new_password)) {
                return ['success' => false, 'message' => 'New password does not meet requirements'];
            }

            // Update password
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $sql = "UPDATE users SET 
                    password = ?, 
                    password_reset_token = NULL, 
                    password_reset_expires = NULL 
                    WHERE id = ?";
            
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "si", $hashed_password, $user['id']);
            
            if (mysqli_stmt_execute($stmt)) {
                $this->logAudit($user['id'], 'password_reset', 'Password reset successfully');
                return ['success' => true, 'message' => 'Password reset successfully'];
            }

            return ['success' => false, 'message' => 'Failed to reset password'];

        } catch (Exception $e) {
            error_log("Password reset error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to reset password'];
        }
    }

    /**
     * Check if an email already exists in the database
     * @param string $email The email to check
     * @return array ['exists' => bool, 'message' => string]
     */
    public function checkEmailExists($email) {
        $sql = "SELECT id FROM users WHERE email = ?";
        if ($stmt = mysqli_prepare($this->conn, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $email);
            if (mysqli_stmt_execute($stmt)) {
                mysqli_stmt_store_result($stmt);
                $exists = mysqli_stmt_num_rows($stmt) > 0;
                mysqli_stmt_close($stmt);
                return [
                    'exists' => $exists,
                    'message' => $exists ? 'Email already registered' : 'Email available'
                ];
            }
        }
        return [
            'exists' => false,
            'message' => 'Error checking email'
        ];
    }
}

// Initialize Auth class
$auth = new Auth($conn);
?> 