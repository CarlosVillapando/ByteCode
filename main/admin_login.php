<?php
session_start();

$error = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_SESSION['admin_login_attempts'])) {
        $_SESSION['admin_login_attempts'] = 0;
    }

    if ($_SESSION['admin_login_attempts'] >= 3) {
        $error = "Too many failed login attempts. Please try again later.";
    } else {
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);

        // Hardcoded admin credentials
        $hardcoded_username = "adminmigs";
        $hardcoded_password = "Admin123!";

        // Check credentials
        if ($username === $hardcoded_username && $password === $hardcoded_password) {
            $_SESSION['admin_username'] = $username;
            $_SESSION['admin_login_attempts'] = 0; // Reset attempts on successful login
            header("Location: dashboard.php");  // Changed from admin_dashboard.html to dashboard.php
            exit;
        } else {
            $_SESSION['admin_login_attempts']++;
            $error = "Invalid username or password.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
  <!-- Link to the shared CSS file -->
  <link rel="stylesheet" href="login.css">
</head>
<body>
  <div class="login-container">
    <h2>Admin Login</h2>

    <?php if (!empty($error)) : ?>
      <p class="error-message"><?php echo $error; ?></p>
    <?php endif; ?>

    <form action="admin_login.php" method="POST">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="Enter username" required>

      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter password" required>

      <button type="submit">Login</button> <!-- Removed empty <a> tag inside button -->
    </form>
  </div>
</body>
</html>