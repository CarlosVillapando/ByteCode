function validateForm(event) {
  event.preventDefault(); // Prevent form submission

  // Clear previous error messages
  const errorMessages = document.querySelectorAll(".error-message");
  errorMessages.forEach((msg) => msg.remove());

  // Get form values
  const form = document.forms["registerForm"];
  const firstName = form["first_name"];
  const lastName = form["last_name"];
  const email = form["email"];
  const phone = form["phone"];
  const password = form["password"];
  const confirmPassword = form["confirm_password"];

  // Validation flags
  let isValid = true;

  // Helper function to display error messages
  function showError(input, message) {
    isValid = false;
    const error = document.createElement("span");
    error.className = "error-message";
    error.style.color = "brown"; // Warning color
    error.style.fontSize = "0.9em";
    error.textContent = message;
    input.parentElement.appendChild(error);
  }

  // Validate email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email.value)) {
    showError(email, "Invalid email address.");
  }

  // Validate phone number (Philippine mobile number, exactly 11 digits)
  const phoneRegex = /^09\d{9}$/;
  if (!phoneRegex.test(phone.value) || phone.value.length !== 11) {
    showError(phone, "Invalid mobile number.");
  }

  // Validate password
  const passwordRegex = /^(?=.*[A-Z]).{8,}$/;
  if (!passwordRegex.test(password.value)) {
    showError(password, "Password must be at least 8 characters long and contain at least one capital letter.");
  }

  // Check if passwords match
  if (password.value !== confirmPassword.value) {
    showError(confirmPassword, "Passwords do not match.");
  }

  // Redirect if valid
  if (isValid) {
    window.location.href = "index.html";
  }
}