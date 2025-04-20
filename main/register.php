<?php
session_start();
require 'db.php'; // Database connection

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Collect and sanitize input
    $first_name = trim($_POST['first_name']);
    $last_name = trim($_POST['last_name']);
    $street_address = trim($_POST['street_address']);
    $city = trim($_POST['city']);
    $province = trim($_POST['province']);
    $zip = trim($_POST['zip']);
    $phone = trim($_POST['phone']);
    $email = trim($_POST['email']);
    $role = trim($_POST['role']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Validate password match
    if ($password !== $confirm_password) {
        $error = "Passwords do not match!";
    } else {
        // Check if email or phone already exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? OR phone_number = ?");
        $stmt->bind_param("ss", $email, $phone);
        $stmt->execute();
        $stmt->store_result();
        
        if ($stmt->num_rows > 0) {
            $error = "Email or phone number already registered!";
        } else {
            // Hash password
            $password_hash = password_hash($password, PASSWORD_DEFAULT);

            // Handle file upload (Proof of Residency)
            $proof_file = null;
            if (!empty($_FILES['proof']['name'])) {
                $target_dir = "uploads/"; // Ensure this directory exists and is writable
                $proof_file = $target_dir . basename($_FILES["proof"]["name"]);
                move_uploaded_file($_FILES["proof"]["tmp_name"], $proof_file);
            }

            // Insert new user
            $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, street_address, city, state_province, postal_zip_code, phone_number, email, role, proof_of_residency, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("sssssssssss", $first_name, $last_name, $street_address, $city, $province, $zip, $phone, $email, $role, $proof_file, $password_hash);

            if ($stmt->execute()) {
                $_SESSION['user_id'] = $stmt->insert_id;
                $_SESSION['user_name'] = $first_name . " " . $last_name;
                
                // Redirect to login page
                header("Location: login.php?success=registered");
                exit;
            } else {
                $error = "Registration failed. Please try again.";
            }
        }
        $stmt->close();
    }
}
?>

<!-- Registration Form with PHP Error Handling -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="register.css">
</head>
<body>
    <div class="register-container">
        <h2>Register Form</h2>
        <p class="sub-title">Account Details:</p>
        
        <?php if (isset($error)) echo "<p style='color: red;'>$error</p>"; ?>

        <form action="register.php" method="POST" enctype="multipart/form-data">
            <div class="form-row">
                <div class="input-group">
                    <label>First Name</label>
                    <input type="text" name="first_name" required>
                </div>
                <div class="input-group">
                    <label>Last Name</label>
                    <input type="text" name="last_name" required>
                </div>
            </div>

            <div class="input-group full">
                <label>Street Address</label>
                <input type="text" name="street_address" required>
            </div>

            <div class="form-row">
                <div class="input-group">
                    <label>City</label>
                    <input type="text" name="city" required>
                </div>
                <div class="input-group">
                    <label>State / Province</label>
                    <input type="text" name="province" required>
                </div>
            </div>

            <div class="input-group full">
                <label>Postal / Zip Code</label>
                <input type="text" name="zip" required>
            </div>

            <div class="form-row">
                <div class="input-group">
                    <label>Phone Number</label>
                    <input type="text" name="phone" required>
                </div>
                <div class="input-group">
                    <label>Email</label>
                    <input type="email" name="email" required>
                </div>
            </div>

            <div class="form-row">
                <div class="input-group">
                    <label>Role</label>
                    <select name="role" required>
                        <option value="Resident">Resident</option>
                        <option value="Barangay Official">Barangay Official</option>
                        <option value="Maintenance Team">Maintenance Team</option>
                    </select>
                </div>
                <div class="input-group">
                    <label>Proof of Residency</label>
                    <input type="file" name="proof" required>
                </div>
            </div>

            <div class="form-row">
                <div class="input-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                <div class="input-group">
                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password" required>
                </div>
            </div>

            <div class="submit-group">
                <button type="submit">Register</button>
                <p>Already have an account? <a href="login.php">Login Here</a></p>
            </div>
        </form>
    </div>
</body>
</html>