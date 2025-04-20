<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>StreetFix</title>
  <link rel="stylesheet" href="style.css" />
  <style>
    html {
      scroll-behavior: smooth;
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1 class="logo">STREETFIX</h1>
      <nav>
        <ul>
          <li><a href="#home">Home</a></li>
          <li><a href="#services">Services</a></li>
          <li><a href="#about">About</a></li>
          <li><a href="#contact">Contact</a></li>

          <?php if (isset($_SESSION['user_name'])): ?>
            <li><a href="profile.php"><?php echo htmlspecialchars($_SESSION['user_name']); ?></a></li>
            <li><a href="logout.php">Logout</a></li>
          <?php else: ?>
            <li><a href="login.php">Login</a></li>
            <li><a href="register.php">Register</a></li>
          <?php endif; ?>
          
        </ul>
      </nav>
    </div>
  </header>

  <!-- Home -->
  <section id="home" class="hero">
    <div class="hero-text">
      <h2>Together,<br/>We Build Safer Streets</h2>
      <p>
        StreetFix is a smart and efficient way to report, classify, and prioritize infrastructure issues in Barangay 201. Powered by AI-driven image classification and automated priority tagging, our system streamlines the process of reporting concerns, helping barangay officials respond to issues faster and more effectively.
      </p>
      <button onclick="getStarted()">Get Started</button>
    </div>
    <div class="hero-image"></div>
  </section>

  <!-- Services -->
  <section id="services" class="services">
    <h3>SERVICES</h3>
    <h2>Empowering communities with AI-driven infrastructure<br>issue reporting and resolution</h2>
    <div class="service-cards">
      <div class="service-card">
        <img src="images/location.png" alt="Location Icon"/>
        <h4>Issue Reporting & Tracking</h4>
        <p>Snap a photo, describe the problem, and submit it. Our AI automatically classifies and prioritizes your report.</p>
      </div>
      <div class="service-card">
        <img src="images/ai.png" alt="AI Icon" width="150" height="150" />
        <h4>AI Issue Classification and Priority Tagging</h4>
        <p>Our system analyzes reports and assigns priority levels, ensuring faster resolution.</p>
      </div>
      <div class="service-card">
        <img src="images/calendar.png" alt="Calendar Icon" width="150" height="150" />
        <h4>Real-Time Updates</h4>
        <p>Stay informed about the status of your reports with real-time notifications and progress tracking.</p>
      </div>
    </div>
  </section>

  <!-- About -->
  <section id="about" class="about">
    <div class="about-text">
      <h3>About</h3>
      <h2>What is StreetFix?</h2>
      <p>
        StreetFix is an AI-driven infrastructure issue reporting platform designed to streamline the way communities identify, report, and resolve street-related problems. Whether it's potholes, damaged streetlights, drainage blockages, or other road hazards, StreetFix enables residents, local officials, and maintenance teams to collaborate in real-time for faster and more efficient problem resolution.
      </p>
      <p>
        StreetFix enhances the efficiency of traditional issue reporting by reducing the reliance on manual documentation and minimizing communication delays. The system is designed to ensure that all reported infrastructure concerns are accurately classified, properly prioritized, and addressed in a timely manner.
      </p>
    </div>
    <div class="about-image">
      <img src="images/pothole.jpg" alt="Pothole Image" />
    </div>
  </section>

  <!-- Contact -->
  <section id="contact" class="contact">
    <div class="contact-left">
      <h3>Contact Us</h3>
      <h2>Let’s Work Together</h2>
      <p><strong>Address:</strong> Gate 2 Kalayaan Village Barangay 201, Zone 20 Pasay City, Philippines</p>
      <p><strong>Email:</strong> barangay201pasaycity2018@gmail.com</p>
      <p><strong>Tel:</strong> 0995-984-0893</p>
    </div>
    <div class="contact-right">
      <h3>Email Us</h3>
      <form action="#" method="post">
        <label>First Name</label>
        <input type="text" name="first-name" required>
  
        <label>Last Name</label>
        <input type="text" name="last-name" required>
  
        <label>Email</label>
        <input type="email" name="email" required>
  
        <label>Phone</label>
        <input type="tel" name="phone">
  
        <label>Message</label>
        <textarea name="message" rows="5" placeholder="Type your message here..." required></textarea>
  
        <button type="submit">Submit</button>
      </form>
    </div>
  </section>

  <script>
    function getStarted() {
      window.location.href = "login.php";
    }
  </script>
</body>
</html>