<?php

// Used ChatGPT for most of this since it is for a write-up. Not exactly a fan of this code, but it's good enough for demonstrating SQLi.

session_start();
// DB connection (replace with your DB details)
$conn = new mysqli('localhost', '', '', '');

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create tables if they don't exist
$createUsersTable = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
)";

$createLoginAttemptsTable = "CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    useragent VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50) NOT NULL,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";

$conn->query($createUsersTable);
$conn->query($createLoginAttemptsTable);


// Signup handler
if (isset($_POST['signup'])) {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT); // Hash password with bcrypt
    $query = "INSERT INTO users (username, password) VALUES ('$username', '$password')";
    if ($conn->query($query) === TRUE) {
        echo "<p>User registered successfully!</p>";
    } else {
        echo "<p>Error: " . $conn->error . "</p>";
    }
}

// Login handler
if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $useragent = $_SERVER['HTTP_USER_AGENT']; // User-Agent from browser
    $ip = $_SERVER['REMOTE_ADDR']; // IP address of the user

    // Retrieve user from the database
    $query = "SELECT * FROM users WHERE username = '$username'";
    $result = $conn->query($query);

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        // Verify hashed password
        if (password_verify($password, $user['password'])) {
            $_SESSION['logged_in'] = true;
            $_SESSION['username'] = $username;
            // Record login attempt with useragent and IP
            $loginAttemptQuery = "INSERT INTO login_attempts (username, useragent, ip_address) VALUES ('$username', '$useragent', '$ip')";
            $conn->query($loginAttemptQuery);

            echo "<p>Login successful!</p>";
        } else {
            echo "<p>Login failed: incorrect password.</p>";
        }
    } else {
        echo "<p>Login failed: user not found.</p>";
    }
}
// Search by User Agent feature (vulnerable to SQL injection)
if (isset($_POST['search']) && $_SESSION['logged_in']) {
    $searchUserAgent = $_POST['search_useragent']; // User-supplied search term
    $username = $_SESSION['username']; // Logged in username

    // Intentionally vulnerable to SQL injection
    $searchQuery = "SELECT username, useragent, ip_address, attempt_time FROM login_attempts WHERE username = '$username' AND useragent = '$searchUserAgent'";
    $searchResult = $conn->query($searchQuery);

    echo "<h3>Search Results:</h3>";
    echo "<table><tr><th>Username</th><th>User Agent</th><th>IP Address</th><th>Attempt Time</th></tr>";
    while($row = $searchResult->fetch_assoc()) {
        echo "<tr><td>".$row['username']."</td><td>".$row['useragent']."</td><td>".$row['ip_address']."</td><td>".$row['attempt_time']."</td></tr>";
    }
    echo "</table>";
}

// Display login attempts to logged in users
if ($_SESSION['logged_in']) {
    $username = $_SESSION['username']; // Logged in username
    $attemptsQuery = "SELECT * FROM login_attempts WHERE username = '$username'";
    $attempts = $conn->query($attemptsQuery);

    echo "<h3>Login Attempts:</h3>";
    echo "<table><tr><th>Username</th><th>User Agent</th><th>IP Address</th><th>Attempt Time</th></tr>";
    while($attempt = $attempts->fetch_assoc()) {
        echo "<tr><td>".$attempt['username']."</td><td>".$attempt['useragent']."</td><td>".$attempt['ip_address']."</td><td>".$attempt['attempt_time']."</td></tr>";
    }
    echo "</table>";
}
?>

<!-- HTML Form for Signup -->
<form method="post">
    <h2>Signup</h2>
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" required>
    <label for="password">Password:</label>
    <input type="password" id="password" name="password" required>
    <input type="submit" name="signup" value="Signup">
</form>

<!-- HTML Form for Login -->
<form method="post">
    <h2>Login</h2>
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" required>
    <label for="password">Password:</label>
    <input type="password" id="password" name="password" required>
    <input type="submit" name="login" value="Login">
</form>

<?php if ($_SESSION['logged_in']): ?>
<!-- HTML Form for Search by User Agent -->
<form method="post">
    <h2>Search by User Agent</h2>
    <label for="search_useragent">User Agent:</label>
    <input type="text" id="search_useragent" name="search_useragent" required>
    <input type="submit" name="search" value="Search">
</form>
<?php endif; ?>
