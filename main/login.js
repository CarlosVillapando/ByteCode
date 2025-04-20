document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.querySelector("form");

  loginForm.addEventListener("submit", (event) => {
    event.preventDefault(); // Prevent form submission

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    // Simulate login validation (replace with actual backend validation)
    if (email === "user@example.com" && password === "password123") {
      alert("Login successful!");
      window.location.href = "index.html"; // Redirect to index.html
    } else {
      alert("Invalid email or password. Please try again.");
    }
  });
});