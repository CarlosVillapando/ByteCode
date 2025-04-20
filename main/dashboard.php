<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>StreetFix Admin Dashboard</title>
  <link rel="stylesheet" href="dashboard.css" />
  <script>
    function toggleDropdown() {
      document.getElementById("dropdownContent").classList.toggle("show");
    }

    function openProfileModal() {
      document.getElementById("profileModal").style.display = "block";
    }

    function closeProfileModal() {
      document.getElementById("profileModal").style.display = "none";
    }

    window.onclick = function(event) {
      if (!event.target.matches('.avatar') && !event.target.matches('.dropdown')) {
        const dropdowns = document.getElementsByClassName("dropdown-content");
        for (let i = 0; i < dropdowns.length; i++) {
          if (dropdowns[i].classList.contains('show')) {
            dropdowns[i].classList.remove('show');
          }
        }
      }
      if (event.target == document.getElementById("profileModal")) {
        closeProfileModal();
      }
    }
  </script>
</head>
<body>
  <div class="sidebar">
    <h2>STREETFIX</h2>
    <ul>
        <li class="active"><a href="dashboard.php">🏠 Dashboard</a></li>
        <li><a href="progress_tracking.php">🛠 Progress Tracking</a></li>
        <li><a href="announcement.html">🔔 Announcements</a></li>
        <li><a href="reports_analytics.php">📈 Reports & Analytics</a></li>
    </ul>
  </div>

  <div class="main-content">
  <header>
  <div class="user-dropdown" onclick="toggleDropdown()">
    <div class="user-info">
      <span class="user-name">👤 Admin</span>
      <span class="dropdown">▾</span>
    </div>
    <div id="userDropdown" class="dropdown-content">
      <a href="logout.php">🚪 Logout</a>
    </div>
  </div>
</header>


    <section class="dashboard">
      <h2>Dashboard Overview</h2>
      <div class="overview">
        <div class="box blue">Total Issues<br><strong>247</strong></div>
        <div class="box green">Resolved Issues<br><strong>225</strong></div>
        <div class="box yellow">Pending Issues<br><strong>22</strong></div>
      </div>

      <div class="reports">
        <h3>Recent Reports</h3>
        <table>
          <thead>
            <tr>
              <th>Issue Code</th>
              <th>Type of Issue</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>ISSUE-247</td><td>Pothole</td><td><span class="status pending">Pending</span></td></tr>
            <tr><td>ISSUE-238</td><td>Broken Streetlight</td><td><span class="status progress">In Progress</span></td></tr>
            <tr><td>ISSUE-235</td><td>Pothole</td><td><span class="status resolved">Resolved</span></td></tr>
            <tr><td>ISSUE-228</td><td>Road Obstruction</td><td><span class="status resolved">Resolved</span></td></tr>
            <tr><td>ISSUE-246</td><td>Drainage Blockage</td><td><span class="status pending">Pending</span></td></tr>
          </tbody>
        </table>
      </div>

      <div class="activities">
        <h3>Recent Activities</h3>
        <ul>
          <li>10:00 AM - Resident: Villapando - Reported a pothole on Kalayaan St.</li>
          <li>12:54 PM - Barangay Official - Submitted report ISSUE-246</li>
          <li>3:28 PM - Maintenance Team - Updated status of ISSUE-238</li>
        </ul>
      </div>
    </section>
  </div>

  <!-- Profile Modal -->
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
