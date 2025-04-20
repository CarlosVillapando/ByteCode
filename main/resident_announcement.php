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

// Get user data
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT first_name, last_name, email, created_at FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <link rel="stylesheet" href="resident_dashboard.css" /> <!-- Using same CSS as dashboard -->
  <title>StreetFix - Announcements</title>
</head>
<body>
  <div class="sidebar">
    <h2>STREETFIX</h2>
    <ul>
      <li><a href="resident_dashboard.php">🏠 Dashboard</a></li>
      <li class="active"><a href="resident_announcement.php">🔔 Announcements</a></li>
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

    <section class="announcements-container" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.1);">
      <h2>Announcements</h2>
      
      <!-- Announcement 1 -->
      <div class="announcement" style="border-bottom: 1px solid #eee; padding: 15px 0;">
        <h3 style="margin-top: 0; color: #b2853c;">Road Repair Schedule</h3>
        <div class="announcement-meta" style="color: #666; font-size: 0.9em; margin-bottom: 10px;">
          <span class="announcement-date" style="font-weight: bold;">Posted: May 15, 2023</span>
        </div>
        <p>The maintenance team will be repairing potholes along Kalayaan Street from May 20-25, 2023. Please plan your routes accordingly.</p>
      </div>

      <!-- Announcement 2 -->
      <div class="announcement" style="border-bottom: 1px solid #eee; padding: 15px 0;">
        <h3 style="margin-top: 0; color: #b2853c;">Drainage Cleaning</h3>
        <div class="announcement-meta" style="color: #666; font-size: 0.9em; margin-bottom: 10px;">
          <span class="announcement-date" style="font-weight: bold;">Posted: May 10, 2023</span>
        </div>
        <p>Scheduled drainage cleaning for the entire barangay will begin next week. Please keep the streets clear of vehicles during your scheduled day.</p>
      </div>

      <!-- Announcement 3 -->
      <div class="announcement" style="border-bottom: 1px solid #eee; padding: 15px 0;">
        <h3 style="margin-top: 0; color: #b2853c;">New Reporting Feature</h3>
        <div class="announcement-meta" style="color: #666; font-size: 0.9em; margin-bottom: 10px;">
          <span class="announcement-date" style="font-weight: bold;">Posted: May 5, 2023</span>
        </div>
        <p>We've added a new feature to report street light outages directly through the app. Please use this for faster response times.</p>
      </div>
    </section>
  </div>

  <!-- Profile Modal (same as dashboard) -->
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