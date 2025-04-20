<?php
session_start();
require 'db.php'; // Make sure this file establishes $conn

// Verify database connection
if (!isset($conn) || $conn->connect_error) {
    die("Database connection failed: " . ($conn->connect_error ?? "No connection"));
}

// Verify user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// Prepare the statement with error handling
$sql = "SELECT first_name, last_name, email, created_at FROM users WHERE id = ?";
$stmt = $conn->prepare($sql);

if ($stmt === false) {
    die("Error preparing query: " . $conn->error);
}

// Bind parameters and execute
$user_id = $_SESSION['user_id'];
$stmt->bind_param("i", $user_id);

if (!$stmt->execute()) {
    die("Error executing query: " . $stmt->error);
}

// Get results
$result = $stmt->get_result();
if (!$result) {
    die("Error getting results: " . $stmt->error);
}

$user = $result->fetch_assoc();
if (!$user) {
    die("No user found with ID: $user_id");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <link rel="stylesheet" href="resident_dashboard.css" />
  <title>StreetFix Resident Dashboard</title>
</head>
<body>
  <div class="sidebar">
    <h2>STREETFIX</h2>
    <ul>
      <li class="active"><a href="#">🏠 Dashboard</a></li>
      <li><a href="resident_announcement.php">🔔 Announcements</a></li>
      <li><a href="#">📈 Report & Analytics</a></li>
    </ul>
  </div>

  <div class="main-content">
    <header>
      <div class="user-dropdown" onclick="toggleDropdown()">
        <div class="user-info">
          <span class="avatar">👤</span>
          <span><?php echo htmlspecialchars($user['first_name']); ?></span>
          <span class="dropdown">▾</span>
        </div>
        <div id="userDropdown" class="dropdown-content">
          <a href="#" id="viewProfileLink">👤 View Profile</a>
          <a href="logout.php">🚪 Logout</a>
        </div>
      </div>
    </header>

    <section class="dashboard-overview">
      <h2>Dashboard Overview</h2>
      <div class="overview-cards">
        <div class="card"><h3>Total Reports</h3><p>120</p></div>
        <div class="card"><h3>Resolved</h3><p>87</p></div>
        <div class="card"><h3>Pending</h3><p>33</p></div>
      </div>
    </section>

    <section class="recent-reports">
      <h2>Recent Reports</h2>
      <table>
        <thead>
          <tr>
            <th>Issue</th>
            <th>Status</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Pothole on 5th Ave</td>
            <td>Resolved</td>
            <td>Apr 2, 2025</td>
          </tr>
          <tr>
            <td>Clogged Drain</td>
            <td>Pending</td>
            <td>Apr 3, 2025</td>
          </tr>
          <tr>
            <td>Broken Street Light</td>
            <td>Resolved</td>
            <td>Apr 1, 2025</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>

  <div id="profileModal" class="modal">
    <div class="modal-content">
      <span class="close">&times;</span>
      <h2>Your Profile</h2>
      <div class="profile-info">
        <div class="profile-avatar">👤</div>
        <div class="profile-details">
          <p><strong>Name:</strong> <?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?></p>
          <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
          <?php if (isset($user['address']) && !empty($user['address'])): ?>
            <p><strong>Address:</strong> <?php echo htmlspecialchars($user['address']); ?></p>
          <?php endif; ?>
          <p><strong>Member Since:</strong> <?php echo date("F Y", strtotime($user['created_at'])); ?></p>
        </div>
      </div>
      <div class="profile-actions">
        <button class="close-btn">Close</button>
      </div>
    </div>
  </div>

  <script>
    // Dropdown functionality
    function toggleDropdown() {
      document.getElementById("userDropdown").classList.toggle("show");
    }
    
    // Modal functionality
    const modal = document.getElementById("profileModal");
    const viewProfileLink = document.getElementById("viewProfileLink");
    const closeBtn = document.querySelector(".close");
    const closeModalBtn = document.querySelector(".close-btn");
    
    // Open modal when View Profile is clicked
    viewProfileLink.addEventListener("click", function(e) {
      e.preventDefault();
      modal.style.display = "block";
      // Close dropdown if open
      document.getElementById("userDropdown").classList.remove("show");
    });
    
    // Close modal when X is clicked
    closeBtn.addEventListener("click", function() {
      modal.style.display = "none";
    });
    
    // Close modal when Close button is clicked
    closeModalBtn.addEventListener("click", function() {
      modal.style.display = "none";
    });
    
    // Close modal when clicking outside
    window.addEventListener("click", function(event) {
      if (event.target == modal) {
        modal.style.display = "none";
      }
      
      // Close dropdown if clicked outside (existing functionality)
      if (!event.target.matches('.user-dropdown') && !event.target.closest('.user-dropdown')) {
        var dropdowns = document.getElementsByClassName("dropdown-content");
        for (var i = 0; i < dropdowns.length; i++) {
          var openDropdown = dropdowns[i];
          if (openDropdown.classList.contains('show')) {
            openDropdown.classList.remove('show');
          }
        }
      }
    });
  </script>
</body>
</html>