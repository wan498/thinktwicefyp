/* =========================
   MODALS
========================= */

function openForgotModal() {
  document.getElementById("forgotModal").style.display = "flex";
}

function closeForgotModal() {
  document.getElementById("forgotModal").style.display = "none";
}

function openSignupModal() {
  document.getElementById("signupModal").style.display = "flex";
}

function closeSignupModal() {
  document.getElementById("signupModal").style.display = "none";
}

/* =========================
   THEME
========================= */

function toggleTheme() {
  const body = document.body;
  const themeText = document.getElementById("themeText");
  const themeIcon = document.getElementById("themeIcon");

  if (body.classList.contains("light-mode")) {
    body.classList.remove("light-mode");
    body.classList.add("dark-mode");

    themeText.innerText = "Dark";
    themeIcon.className = "fa-solid fa-moon";
  } else {
    body.classList.remove("dark-mode");
    body.classList.add("light-mode");

    themeText.innerText = "Light";
    themeIcon.className = "fa-solid fa-sun";
  }
}

/* =========================
   SIGNUP (FIXED)
========================= */

document.getElementById("signupBtn").addEventListener("click", async () => {
  const inputs = document.querySelectorAll("#signupModal input");

  const fullname = inputs[0].value.trim();
  const email = inputs[1].value.trim();
  const password = inputs[2].value;
  const confirmPassword = inputs[3].value;

  if (!fullname || !email || !password) {
    alert("Fill all fields");
    return;
  }

  if (password !== confirmPassword) {
    alert("Passwords do not match");
    return;
  }

  const res = await fetch("/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fullname, email, password })
  });

  const data = await res.json();

  alert(data.message);

  if (data.success) {
    closeSignupModal();
  }
});

/* =========================
   LOGIN (FIXED + SAFE REDIRECT)
========================= */

document.getElementById("loginBtn").addEventListener("click", async () => {
  const email = document.querySelector(".login-card input[type='email']").value.trim();
  const password = document.getElementById("loginPassword").value;
  const remember = document.getElementById("rememberMe").checked;

  if (!email || !password) {
    alert("Please enter email and password");
    return;
  }

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    alert(data.message);

    if (data.success) {
      localStorage.setItem("user", JSON.stringify(data.user));

      if (remember) {
        localStorage.setItem("savedEmail", email);
      } else {
        localStorage.removeItem("savedEmail");
      }

      window.location.href = "/fyp.html";
    }

  } catch (err) {
    alert("Login failed. Server error.");
    console.error(err);
  }
});

/* =========================
   AUTO FILL EMAIL
========================= */

window.addEventListener("DOMContentLoaded", () => {
  const savedEmail = localStorage.getItem("savedEmail");

  if (savedEmail) {
    const emailInput = document.querySelector(".login-card input[type='email']");
    if (emailInput) emailInput.value = savedEmail;

    document.getElementById("rememberMe").checked = true;
  }
});

/* =========================
   PASSWORD TOGGLE
========================= */

function setupPasswordToggle(toggleId, inputId) {
  const toggle = document.getElementById(toggleId);
  const input = document.getElementById(inputId);

  if (!toggle || !input) return;

  toggle.addEventListener("click", () => {
    if (input.type === "password") {
      input.type = "text";
      toggle.classList.replace("fa-eye", "fa-eye-slash");
    } else {
      input.type = "password";
      toggle.classList.replace("fa-eye-slash", "fa-eye");
    }
  });
}

setupPasswordToggle("loginToggle", "loginPassword");
setupPasswordToggle("signupToggle", "signupPassword");
setupPasswordToggle("confirmToggle", "confirmPassword");
setupPasswordToggle("toggleNewPassword", "newPassword");
setupPasswordToggle("toggleConfirmNewPassword", "confirmNewPassword");

/* =========================
   FORGOT PASSWORD FLOW (FIXED)
========================= */

let resetToken = null;
let step = 1;

document.getElementById("sendResetBtn").addEventListener("click", async () => {

  const email = document.querySelector("#forgotModal input[type='email']").value.trim();

  if (!email) {
    alert("Please enter email");
    return;
  }

  try {

    /* STEP 1 */
    if (step === 1) {

      const res = await fetch("/check-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email })
      });

      const data = await res.json();

      if (!data.exists) {
        alert("Email not found");
        return;
      }

      alert("Email verified. Enter new password.");

      resetToken = data.token;

      document.getElementById("newPasswordBox").style.display = "flex";
      document.getElementById("confirmNewPasswordBox").style.display = "flex";

      document.getElementById("sendResetBtn").innerText = "Update Password";

      step = 2;
      return;
    }

    /* STEP 2 */
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmNewPassword").value;

    if (!newPassword || !confirmPassword) {
      alert("Please enter password");
      return;
    }

    if (newPassword !== confirmPassword) {
      alert("Passwords do not match");
      return;
    }

    const res = await fetch("/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        token: resetToken,
        newPassword
      })
    });

    const data = await res.json();

    alert(data.message);

    if (data.success) {
      closeForgotModal();

      step = 1;
      resetToken = null;

      document.getElementById("sendResetBtn").innerText = "Verify Email";

      document.getElementById("newPasswordBox").style.display = "none";
      document.getElementById("confirmNewPasswordBox").style.display = "none";
    }

  } catch (err) {
    alert("Request failed");
    console.error(err);
  }
});
