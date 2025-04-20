<?php
session_start();
require 'db.php'; // Database connection

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email_or_phone = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Check if input is an email or phone number
    $column = filter_var($email_or_phone, FILTER_VALIDATE_EMAIL) ? 'email' : 'phone_number';

    // Prepare SQL query - now including the role field
    $stmt = $conn->prepare("SELECT id, first_name, last_name, password_hash, role FROM users WHERE $column = ?");
    $stmt->bind_param("s", $email_or_phone);
    $stmt->execute();
    $result = $stmt->get_result();

    // Check if user exists
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();

        // Verify password
        if (password_verify($password, $user['password_hash'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_name'] = $user['first_name'] . " " . $user['last_name'];
            $_SESSION['user_role'] = $user['role']; // Store role in session

            // Redirect based on role
            if ($user['role'] == 'admin') {
                header("Location: dashboard.html");
            } else {
                // Assuming any non-admin is a resident
                header("Location: resident_dashboard.php");
            }
            exit;
        } else {
            $error = "Invalid email/phone or password.";
        }
    } else {
        $error = "No account found with this email or phone.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>StreetFix - Login</title>
  <link rel="stylesheet" href="login.css">
</head>
<body>
<header>
  <div class="container">
    <h1 class="logo">STREETFIX</h1>
    <nav>
      <ul>
        <li><a href="index.php#home">Home</a></li>
        <li><a href="index.php#services">Services</a></li>
        <li><a href="index.php#about">About</a></li>
        <li><a href="index.php#contact">Contact</a></li>
        <li><a href="login.php" class="active">Login</a></li>
        <li><a href="register.php">Register</a></li>
        <li><a href="admin_login.php" class="secret-button" title="Admin Login"></a></li>
      </ul>
    </nav>
  </div>

</header>

<div class="login-container">
  <div class="login-left">
    <h2>Sign In</h2>

    <?php if (!empty($error)) : ?>
      <p style="color:red;"><?php echo $error; ?></p>
    <?php endif; ?>

    <form action="login.php" method="POST">
      <label for="email">Email / Phone Number</label>
      <input type="text" id="email" name="email" placeholder="Enter email or phone" required>

      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter password" required>

      <button type="submit" class="signin-btn">Sign In</button>
    </form>
  </div>

  <div class="login-right">
    <h2>Welcome Back!</h2>
    <p>Don't have an account?</p>
    <a href="register.php" class="signup-btn">Sign up</a>
  </div>
</div>
</body>
</html>