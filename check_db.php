<?php
require_once 'config.php';

echo "=== Database Status Check ===\n\n";

// Check database connection
if ($conn) {
    echo "Database connection successful\n";
} else {
    echo "Database connection failed: " . mysqli_connect_error() . "\n";
    exit;
}

// Check if database exists
$result = mysqli_query($conn, "SHOW DATABASES LIKE '" . DB_NAME . "'");
if (mysqli_num_rows($result) > 0) {
    echo "\nDatabase '" . DB_NAME . "' exists\n";
} else {
    echo "\nDatabase '" . DB_NAME . "' does not exist\n";
    exit;
}

// Check users table
$result = mysqli_query($conn, "SHOW TABLES LIKE 'users'");
if (mysqli_num_rows($result) > 0) {
    echo "\nTable 'users' exists\n";
    
    // Show table structure
    echo "\nTable structure:\n";
    $result = mysqli_query($conn, "DESCRIBE users");
    while ($row = mysqli_fetch_assoc($result)) {
        echo $row['Field'] . " - " . $row['Type'] . " - " . $row['Null'] . " - " . $row['Key'] . " - " . $row['Default'] . "\n";
    }
    
    // Show user count
    $result = mysqli_query($conn, "SELECT COUNT(*) as count FROM users");
    $row = mysqli_fetch_assoc($result);
    echo "\nTotal users in database: " . $row['count'] . "\n";
    
    // Show recent users
    echo "\nRecent users:\n";
    $result = mysqli_query($conn, "SELECT id, name, email, created_at FROM users ORDER BY created_at DESC LIMIT 5");
    while ($row = mysqli_fetch_assoc($result)) {
        echo "ID: " . $row['id'] . ", Name: " . $row['name'] . ", Email: " . $row['email'] . ", Created: " . $row['created_at'] . "\n";
    }
} else {
    echo "\nTable 'users' does not exist\n";
}

mysqli_close($conn);
?> 