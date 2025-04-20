<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>StreetFix Reports & Analytics</title>
  <link rel="stylesheet" href="reports_analytics.css" />
  </head>
<body>
  <div class="sidebar">
    <h2>STREETFIX</h2>
    <ul>
      <li><a href="dashboard.php">🏠 Dashboard</a></li>
      <li><a href="progress_tracking.php">🛠 Progress Tracking</a></li>
      <li><a href="announcement.html">🔔 Announcements</a></li>
      <li class="active"><a href="#">📈 Reports & Analytics</a></li>
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
      <h2>Reports & Analytics</h2>
      
      <div class="analytics-section">
        <!-- Frequent Infrastructure Issues Card -->
        <div class="analytics-card">
          <div class="card-header">
            <h3>Frequent Infrastructure Issues</h3>
            <div class="sort-options">
              <span>Sort By:</span>
              <button class="active">Monthly</button>
              <button>Weekly</button>
              <button>Yearly</button>
            </div>
          </div>
          
          <div class="chart-container">
            <div class="chart-placeholder">
              [Bar chart showing 25 reports this month]
            </div>
          </div>
          
          
          <div class="download-section">
            <button class="download-btn">Download</button>
          </div>
        </div>
        
        <!-- Response Time Analysis Card -->
        <div class="analytics-card">
          <div class="card-header">
            <h3>Response Time Analysis</h3>
            <div class="sort-options">
              <span>Sort By:</span>
              <button class="active">All</button>
              <button>Delay</button>
              <button>On Time</button>
            </div>
          </div>
          
          <div class="chart-container">
            <div class="chart-placeholder">
              [Line chart showing response times]
            </div>
          </div>
          
          <div class="download-section">
            <button class="download-btn">Download</button>
          </div>
        </div>
      </div>
    </section>
  </div>

  <script>
    function toggleDropdown() {
      document.getElementById("userDropdown").classList.toggle("show");
    }
    
    // Close dropdown when clicking outside
    window.onclick = function(event) {
      if (!event.target.matches('.user-dropdown') && !event.target.closest('.user-dropdown')) {
        var dropdowns = document.getElementsByClassName("dropdown-content");
        for (var i = 0; i < dropdowns.length; i++) {
          var openDropdown = dropdowns[i];
          if (openDropdown.classList.contains('show')) {
            openDropdown.classList.remove('show');
          }
        }
      }
    }
    
    // Sort option selection
    document.querySelectorAll('.sort-options button').forEach(button => {
      button.addEventListener('click', function() {
        // Remove active class from all buttons in this group
        this.parentElement.querySelectorAll('button').forEach(btn => {
          btn.classList.remove('active');
        });
        // Add active class to clicked button
        this.classList.add('active');
        
        // Here you would typically update the chart data based on selection
        // For now we'll just log the selection
        console.log('Selected:', this.textContent);
      });
    });
  </script>
</body>
</html>