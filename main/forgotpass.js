function handleForgotPassword(event) {
  event.preventDefault(); // Prevent form submission

  const mobileNumber = document.getElementById("mobile_number");
  const verificationCodeGroup = document.getElementById("verification-code-group");
  const newPasswordGroup = document.getElementById("new-password-group");
  const confirmPasswordGroup = document.getElementById("confirm-password-group");
  const submitButton = document.getElementById("submit-button");

  if (!verificationCodeGroup.style.display || verificationCodeGroup.style.display === "none") {
    // Step 1: Validate mobile number
    const phoneRegex = /^09\d{9}$/;
    if (!phoneRegex.test(mobileNumber.value)) {
      alert("Please enter a valid 11-digit mobile number starting with '09'.");
      return;
    }

    // Simulate sending SMS
    alert("A 4-digit verification code has been sent to your mobile number.");
    verificationCodeGroup.style.display = "block";
    submitButton.textContent = "Verify Code";
  } else if (!newPasswordGroup.style.display || newPasswordGroup.style.display === "none") {
    // Step 2: Validate verification code
    const verificationCode = document.getElementById("verification_code").value;
    if (verificationCode !== "1234") { // Simulated verification code
      alert("Invalid verification code. Please try again.");
      return;
    }

    alert("Verification successful. You can now reset your password.");
    newPasswordGroup.style.display = "block";
    confirmPasswordGroup.style.display = "block";
    submitButton.textContent = "Reset Password";
  } else {
    // Step 3: Validate and reset password
    const newPassword = document.getElementById("new_password").value;
    const confirmPassword = document.getElementById("confirm_password").value;

    if (newPassword.length < 8) {
      alert("Password must be at least 8 characters long.");
      return;
    }

    if (newPassword !== confirmPassword) {
      alert("Passwords do not match. Please try again.");
      return;
    }

    alert("Your password has been successfully reset.");
    window.location.href = "login.html"; // Redirect to login page
  }
}