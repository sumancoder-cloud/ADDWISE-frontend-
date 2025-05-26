# Addwise Authentication System

A secure and robust authentication system for the Addwise platform, built with PHP and MySQL.

## Features

- Secure user registration with email verification
- Two-factor authentication using OTP
- Password reset functionality
- Session management with security features
- Login attempt tracking and account locking
- Audit logging for security events
- User preferences management
- Secure password hashing and validation
- Protection against common security vulnerabilities

## Requirements

- PHP 7.4 or higher
- MySQL 5.7 or higher
- Composer for dependency management
- SMTP server for email functionality

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/addwise.git
cd addwise
```

2. Install dependencies using Composer:
```bash
composer install
```

3. Create a MySQL database and import the schema:
```bash
mysql -u your_username -p your_database < database/schema.sql
```

4. Configure your environment:
   - Copy `config.example.php` to `config.php`
   - Update the database credentials in `config.php`
   - Update the SMTP settings in `email_handler.php`

5. Set up your web server:
   - Point your web server to the project's root directory
   - Ensure the `vendor` directory is not publicly accessible
   - Configure your web server to use HTTPS

## Configuration

### Database Configuration
Update the following settings in `config.php`:
```php
define('DB_HOST', 'localhost');
define('DB_USER', 'your_username');
define('DB_PASS', 'your_password');
define('DB_NAME', 'your_database');
```

### Email Configuration
Update the following settings in `email_handler.php`:
```php
$mail->Host = 'smtp.gmail.com'; // Your SMTP server
$mail->Username = 'your-email@gmail.com';
$mail->Password = 'your-app-password';
$mail->setFrom('your-email@gmail.com', 'Your Name');
```

### Security Settings
The following security settings can be adjusted in `auth.php`:
```php
private $session_lifetime = 3600; // Session lifetime in seconds
private $max_login_attempts = 5; // Maximum login attempts before lockout
private $lockout_time = 900; // Lockout duration in seconds
```

## Usage

### User Registration
```php
require_once 'auth.php';

$result = $auth->register($name, $email, $password);
if ($result['success']) {
    // Registration successful, OTP sent to email
    echo $result['message'];
} else {
    // Registration failed
    echo $result['message'];
}
```

### User Login
```php
$result = $auth->login($email, $password);
if ($result['success']) {
    if ($result['requires_2fa']) {
        // OTP sent to email, proceed with 2FA
        echo $result['message'];
    } else {
        // Login successful
        echo "Welcome back!";
    }
} else {
    // Login failed
    echo $result['message'];
}
```

### OTP Verification
```php
$result = $auth->verifyOTP($email, $otp, $purpose);
if ($result['success']) {
    // OTP verified successfully
    echo $result['message'];
} else {
    // OTP verification failed
    echo $result['message'];
}
```

### Password Reset
```php
// Request password reset
$result = $auth->requestPasswordReset($email);
if ($result['success']) {
    // Reset instructions sent to email
    echo $result['message'];
}

// Reset password using token
$result = $auth->resetPassword($token, $new_password);
if ($result['success']) {
    // Password reset successful
    echo $result['message'];
}
```

### Session Management
```php
// Check if user is logged in
if ($auth->isLoggedIn()) {
    // User is logged in
    $user = $_SESSION['user'];
    echo "Welcome, " . $user['name'];
}

// Logout
$auth->logout();
```

## Security Features

1. **Password Security**
   - Passwords are hashed using PHP's `password_hash()` function
   - Password requirements include uppercase, lowercase, numbers, and special characters
   - Minimum password length of 8 characters

2. **Session Security**
   - Secure session configuration with HTTP-only cookies
   - Session tokens stored in database
   - Automatic session expiration
   - Protection against session fixation

3. **Login Protection**
   - Account locking after multiple failed attempts
   - Two-factor authentication using email OTP
   - IP address and user agent tracking
   - Audit logging of all login attempts

4. **Email Security**
   - Email verification required for registration
   - Secure password reset process
   - OTP expiration after 10 minutes
   - Rate limiting for OTP requests

## Error Handling

The system includes comprehensive error handling and logging:
- All errors are logged to the server's error log
- User-friendly error messages are returned to the client
- Sensitive information is never exposed in error messages
- Database errors are caught and handled gracefully

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please email  or create an issue in the repository. 
