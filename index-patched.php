<?php

// Patched it using ChatGPT and reviewed it to make sure it properly added prepared statements.
// This is for a write-up and is sufficient for that purpose. This code would be atrocious in a real application.

session_start();
// DB connection (replace with your DB details)
$conn = new mysqli('localhost', '', '', '');

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create tables if they don't exist
$conn->query("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
)");

$conn->query("CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    useragent VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50) NOT NULL,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

// Signup handler
if (isset($_POST['signup'])) {
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    if ($stmt->affected_rows > 0) {
        echo "<p>User registered successfully!</p>";
    } else {
        echo "<p>Error: " . htmlspecialchars($stmt->error) . "</p>";
    }
    $stmt->close();
}

// Login handler
if (isset($_POST['login'])) {
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $username = $_POST['username'];
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($user = $result->fetch_assoc()) {
        if (password_verify($_POST['password'], $user['password'])) {
            $_SESSION['logged_in'] = true;
            $_SESSION['username'] = $username;
            $useragent = $_SERVER['HTTP_USER_AGENT'];
            $ip = $_SERVER['REMOTE_ADDR'];

            $stmt = $conn->prepare("INSERT INTO login_attempts (username, useragent, ip_address) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $useragent, $ip);
            $stmt->execute();
            $stmt->close();

            echo "<p>Login successful!</p>";
        } else {
            echo "<p>Login failed: incorrect password.</p>";
        }
    } else {
        echo "<p>Login failed: user not found.</p>";
    }
}

// Search by User Agent feature for logged-in users
if (isset($_POST['search']) && $_SESSION['logged_in']) {
    $stmt = $conn->prepare("SELECT * FROM login_attempts WHERE username = ? AND useragent = ?");
    $searchUserAgent = $_POST['search_useragent'];
    $username = $_SESSION['username'];
    $stmt->bind_param("ss", $username, $searchUserAgent);
    $stmt->execute();
    $result = $stmt->get_result();

    echo "<h3>Search Results:</h3>";
    echo "<table><tr><th>Username</th><th>User Agent</th><th>IP Address</th><th>Attempt Time</th></tr>";
    while($row = $result->fetch_assoc()) {
        echo "<tr><td>".htmlspecialchars($row['username'])."</td><td>".htmlspecialchars($row['useragent'])."</td><td>".htmlspecialchars($row['ip_address'])."</td><td>".$row['attempt_time']."</td></tr>";
    }
    echo "</table>";
    $stmt->close();
}

// Display login attempts to logged-in users
if ($_SESSION['logged_in']) {
    $stmt = $conn->prepare("SELECT * FROM login_attempts WHERE username = ?");
    $username = $_SESSION['username'];
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    echo "<h3>Login Attempts:</h3>";
    echo "<table><tr><th>Username</th><th>User Agent</th><th>IP Address</th><th>Attempt Time</th></tr>";
    while($attempt = $result->fetch_assoc()) {
        echo "<tr><td>".htmlspecialchars($attempt['username'])."</td><td>".htmlspecialchars($attempt['useragent'])."</td><td>".htmlspecialchars($attempt['ip_address'])."</td><td>".$attempt['attempt_time']."</td></tr>";
    }
    echo "</table>";
    $stmt->close();
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
