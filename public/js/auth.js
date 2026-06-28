// --- Authentication & Client utilities for AuthGuard-MFA ---

const API_BASE = '/api/auth';

// Helper: Show custom alerts in the DOM
function showAlert(message, type = 'danger') {
  const container = document.getElementById('alert-container');
  if (!container) return;

  const iconClass = type === 'success' ? 'fa-circle-check' : 'fa-circle-exclamation';
  container.innerHTML = `
    <div class="alert alert-${type}">
      <i class="fa-solid ${iconClass}"></i>
      <div>${message}</div>
    </div>
  `;
}

// Helper: Clear alerts
function clearAlerts() {
  const container = document.getElementById('alert-container');
  if (container) container.innerHTML = '';
}

// 1. Live Password Strength Checker
function checkPasswordStrength(password) {
  const progressBar = document.getElementById('strength-progress');
  const strengthText = document.getElementById('strength-text');
  
  if (!progressBar || !strengthText) return;

  if (!password) {
    progressBar.style.width = '0%';
    strengthText.innerText = 'Password Strength: None';
    return;
  }

  let score = 0;
  
  // Rule 1: Length
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;

  // Rule 2: Upper & Lower case letters
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;

  // Rule 3: Has numbers
  if (/\d/.test(password)) score++;

  // Rule 4: Has special character
  if (/[^A-Za-z0-9]/.test(password)) score++;

  // Render Visual Progress
  let width = '0%';
  let color = 'var(--accent-danger)';
  let label = 'Weak';

  if (score <= 2) {
    width = '33%';
    color = 'var(--accent-danger)';
    label = 'Weak (Needs numbers/cases)';
  } else if (score === 3 || score === 4) {
    width = '66%';
    color = 'var(--accent-warning)';
    label = 'Medium (Include special characters)';
  } else if (score >= 5) {
    width = '100%';
    color = 'var(--accent-primary)';
    label = 'Strong (Secure password)';
  }

  progressBar.style.width = width;
  progressBar.style.backgroundColor = color;
  strengthText.innerText = `Password Strength: ${label}`;
  strengthText.style.color = color;
}

// 2. Handle User Registration
async function handleRegister(event) {
  event.preventDefault();
  clearAlerts();

  const username = document.getElementById('username').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirm-password').value;

  if (password !== confirmPassword) {
    showAlert('Passwords do not match.', 'danger');
    return;
  }

  const submitBtn = document.getElementById('submit-btn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Hashing & Enrolling...';

  try {
    const res = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });

    const data = await res.json();
    
    if (!res.ok) {
      throw new Error(data.error || 'Registration failed.');
    }

    showAlert(data.message, 'success');
    document.getElementById('register-form').reset();
    checkPasswordStrength('');
    
    // Smooth redirect to login
    setTimeout(() => {
      window.location.href = 'login.html';
    }, 2000);

  } catch (err) {
    showAlert(err.message, 'danger');
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<i class="fa-solid fa-user-plus"></i> Create Account';
  }
}

// 3. Handle Login Step 1 (Username + Password)
let preAuthSessionToken = null; // Temp holder for MFA stage

async function handleLoginStep1(event) {
  event.preventDefault();
  clearAlerts();

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  try {
    const res = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Authentication failed.');
    }

    if (data.mfa_required) {
      // Prompt MFA Verification Stage
      preAuthSessionToken = data.token; // Save temporary JWT
      
      // Animate Forms
      document.getElementById('login-form').style.display = 'none';
      document.getElementById('login-header').style.display = 'none';
      
      document.getElementById('mfa-form').style.display = 'block';
      document.getElementById('mfa-header').style.display = 'block';
      document.getElementById('bottom-link').style.display = 'none';
      
      document.getElementById('otp').focus();
    } else {
      // Standard login, save token and load dashboard
      localStorage.setItem('token', data.token);
      window.location.href = 'dashboard.html';
    }

  } catch (err) {
    showAlert(err.message, 'danger');
  }
}

// 4. Handle Login Step 2 (MFA TOTP Verification)
async function handleLoginStep2(event) {
  event.preventDefault();
  clearAlerts();

  const code = document.getElementById('otp').value.trim();

  if (!code || code.length !== 6) {
    showAlert('Please enter a valid 6-digit code.', 'danger');
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/verify-mfa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, token: preAuthSessionToken })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Verification failed.');
    }

    // Save final verified JWT
    localStorage.setItem('token', data.token);
    window.location.href = 'dashboard.html';

  } catch (err) {
    showAlert(err.message, 'danger');
  }
}

// Reset Login Stage back to username/password
function resetLoginStage() {
  preAuthSessionToken = null;
  clearAlerts();
  
  document.getElementById('login-form').style.display = 'block';
  document.getElementById('login-header').style.display = 'block';
  
  document.getElementById('mfa-form').style.display = 'none';
  document.getElementById('mfa-header').style.display = 'none';
  document.getElementById('bottom-link').style.display = 'block';
}

// 5. Load MFA Setup QR Details
async function loadMfaSetupDetails() {
  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/setup-mfa`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });

    const data = await res.json();

    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        localStorage.removeItem('token');
        window.location.href = 'login.html';
        return;
      }
      throw new Error(data.error || 'Failed to setup MFA.');
    }

    // Display QR and manual key
    document.getElementById('qr-code-img').src = data.qrCode;
    document.getElementById('manual-secret-key').innerText = data.secret;

  } catch (err) {
    showAlert(err.message, 'danger');
  }
}

// 6. Confirm and Register MFA Code
async function handleConfirmMfa(event) {
  event.preventDefault();
  clearAlerts();

  const code = document.getElementById('verification-code').value.trim();
  const token = localStorage.getItem('token');

  if (!code || code.length !== 6) {
    showAlert('Please enter a valid 6-digit code.', 'danger');
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/confirm-mfa`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ code })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Setup verification failed.');
    }

    // Save the newly generated verified token
    localStorage.setItem('token', data.token);
    showAlert('Multi-factor Authentication successfully activated!', 'success');

    setTimeout(() => {
      window.location.href = 'dashboard.html';
    }, 2000);

  } catch (err) {
    showAlert(err.message, 'danger');
  }
}

// Logout session helper
function logout() {
  localStorage.removeItem('token');
  window.location.href = 'index.html';
}

// --- Programmatic Event Listeners Binding (Strict CSP Compliance) ---
document.addEventListener('DOMContentLoaded', () => {
  // Register Form
  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', handleRegister);
  }

  // Live Password Strength Meter
  const passwordInput = document.getElementById('password');
  if (passwordInput && (window.location.pathname.includes('register.html') || document.title.includes('Register'))) {
    passwordInput.addEventListener('input', (e) => checkPasswordStrength(e.target.value));
  }

  // Login Stage 1 Form
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', handleLoginStep1);
  }

  // Login Stage 2 MFA Form
  const mfaForm = document.getElementById('mfa-form');
  if (mfaForm) {
    mfaForm.addEventListener('submit', handleLoginStep2);
  }

  // Cancel MFA button (resets stage)
  const cancelMfaBtn = document.getElementById('cancel-mfa-btn');
  if (cancelMfaBtn) {
    cancelMfaBtn.addEventListener('click', resetLoginStage);
  }

  // Confirm MFA setup form
  const confirmMfaForm = document.getElementById('confirm-mfa-form');
  if (confirmMfaForm) {
    confirmMfaForm.addEventListener('submit', handleConfirmMfa);
  }
});

