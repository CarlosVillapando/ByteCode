<?php
header("Content-Type: application/json");
require 'db.php'; // Make sure this points to your actual DB connection file

$response = ['success' => false, 'message' => 'Invalid request'];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email_or_phone = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Decide whether input is email or phone
    $column = filter_var($email_or_phone, FILTER_VALIDATE_EMAIL) ? 'email' : 'phone_number';

    // Prepare SQL
    $stmt = $conn->prepare("SELECT id, first_name, last_name, password_hash, role FROM users WHERE $column = ?");
    $stmt->bind_param("s", $email_or_phone);
    $stmt->execute();
    $result = $stmt->get_result();

    // Check if user exists
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();

        // Validate password
        if (password_verify($password, $user['password_hash'])) {
            $response = [
                'success' => true,
                'user_id' => $user['id'],
                'user_name' => $user['first_name'] . ' ' . $user['last_name'],
                'role' => $user['role']
            ];
        } else {
            $response['message'] = 'Incorrect password';
        }
    } else {
        $response['message'] = 'User not found';
    }
}

echo json_encode($response);
?>
