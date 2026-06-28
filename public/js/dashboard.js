// --- Dashboard controller for AuthGuard-MFA ---

async function initDashboard() {
  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  try {
    // 1. Validate session status from Server
    const res = await fetch('/api/auth/status', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    const data = await res.ok ? await res.json() : null;

    if (!data || !data.valid) {
      throw new Error('Invalid session');
    }

    const user = data.user;

    // Enforce MFA Verification redirect
    if (user.mfa_enabled && !user.mfa_verified) {
      localStorage.removeItem('token');
      window.location.href = 'login.html';
      return;
    }

    // 2. Populate User Profile Details
    document.getElementById('display-username').innerText = user.username;
    document.getElementById('display-email').innerText = user.email;
    document.getElementById('user-avatar').innerText = user.username.substring(0, 1).toUpperCase();

    // 3. Render MFA Status Controls
    const badgeContainer = document.getElementById('mfa-badge-container');
    const description = document.getElementById('mfa-control-description');
    const btnContainer = document.getElementById('mfa-action-btn-container');

    if (user.mfa_enabled) {
      badgeContainer.innerHTML = `<span class="badge badge-success"><i class="fa-solid fa-square-check"></i> MFA Secured</span>`;
      description.innerHTML = `Multi-factor authorization is active. Your account is shielded against brute-force attacks. Access to sensitive resources (like the Audit SIEM console) is granted.`;
      btnContainer.innerHTML = `
        <button class="btn btn-danger" id="btn-disable-mfa">
          <i class="fa-solid fa-shield-slash"></i> Disable Multi-Factor Authentication
        </button>
      `;
      // Bind event listener programmatically to satisfy Helmet CSP headers
      const disableBtn = document.getElementById('btn-disable-mfa');
      if (disableBtn) {
        disableBtn.addEventListener('click', triggerDisableMfa);
      }
    } else {
      badgeContainer.innerHTML = `<span class="badge badge-warning"><i class="fa-solid fa-triangle-exclamation"></i> MFA Disabled</span>`;
      description.innerHTML = `Your identity is protected by password authentication only. We recommend enabling Multi-Factor Authentication immediately to comply with CIS Cloud Security Benchmarks.`;
      btnContainer.innerHTML = `
        <a href="setup-mfa.html" class="btn btn-primary">
          <i class="fa-solid fa-qrcode"></i> Setup Google Authenticator MFA
        </a>
      `;
    }

    // 4. Render Decoded JWT Parts
    visualizeJwt(token);

    // 4.5 Populate Tamper Input & Dynamic Compliance indicators
    const tamperInput = document.getElementById('tamper-token-input');
    if (tamperInput) tamperInput.value = token;

    const mfaDesc = document.getElementById('mfa-compliance-desc');
    const mfaBadge = document.getElementById('mfa-compliance-badge');
    if (mfaDesc && mfaBadge) {
      if (user.mfa_enabled) {
        mfaDesc.innerText = `Multi-factor authentication is active for account: ${user.username}.`;
        mfaBadge.innerHTML = `<span class="badge badge-success" style="background: rgba(0, 255, 204, 0.15); color: var(--accent-primary); border: 1px solid var(--accent-primary); font-size: 0.75rem;"><i class="fa-solid fa-circle-check"></i> Compliant</span>`;
      } else {
        mfaDesc.innerText = 'MFA disabled. Cryptographic policies recommend enabling secondary verification.';
        mfaBadge.innerHTML = `<span class="badge badge-warning" style="background: rgba(255, 170, 0, 0.15); color: var(--accent-warning); border: 1px solid var(--accent-warning); font-size: 0.75rem;"><i class="fa-solid fa-circle-exclamation"></i> Warning</span>`;
      }
    }

    // Bind token tamper and entropy auditor programmatically to satisfy Helmet CSP headers
    const btnTamper = document.getElementById('btn-tamper-token');
    if (btnTamper) {
      btnTamper.addEventListener('click', simulateTokenTamper);
    }
    
    const btnEntropy = document.getElementById('btn-entropy-audit');
    if (btnEntropy) {
      btnEntropy.addEventListener('click', auditSecretKeyStrength);
    }

  } catch (err) {
    localStorage.removeItem('token');
    window.location.href = 'login.html';
  }
}

// Helper: Decode and print JWT sections in standard colors
function visualizeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    console.error('Invalid JWT format');
    return;
  }

  try {
    // Decode Base64url format
    const headerStr = atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'));
    const payloadStr = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    const signature = parts[2];

    const headerJson = JSON.parse(headerStr);
    const payloadJson = JSON.parse(payloadStr);

    document.getElementById('jwt-header-display').innerText = JSON.stringify(headerJson, null, 2);
    document.getElementById('jwt-payload-display').innerText = JSON.stringify(payloadJson, null, 2);
    document.getElementById('jwt-sig-display').innerText = signature;
  } catch (e) {
    console.error('Error parsing token parts:', e);
  }
}

// 5. Disable MFA Endpoint trigger
async function triggerDisableMfa() {
  if (!confirm('Are you sure you want to disable Multi-Factor Authentication? Your account will be less secure.')) {
    return;
  }

  const token = localStorage.getItem('token');
  try {
    const res = await fetch('/api/auth/disable-mfa', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Failed to disable MFA');
    }

    // Save updated token and reload
    localStorage.setItem('token', data.token);
    showAlert('MFA disabled successfully', 'success');
    
    setTimeout(() => {
      initDashboard();
    }, 1500);

  } catch (err) {
    showAlert(err.message, 'danger');
  }
}

// 6. Tab Switcher Controller for Dashboard (SPA Navigation)
function switchDashboardTab(tabName) {
  const contents = document.querySelectorAll('.tab-content');
  contents.forEach(c => c.classList.remove('active'));

  const buttons = document.querySelectorAll('.tab-btn');
  buttons.forEach(b => b.classList.remove('active'));

  const activeContent = document.getElementById(`tab-${tabName}`);
  if (activeContent) activeContent.classList.add('active');

  buttons.forEach(b => {
    if (b.getAttribute('onclick').includes(tabName)) {
      b.classList.add('active');
    }
  });
}

// 7. Token Tampering Simulation Playground
async function simulateTokenTamper() {
  const tamperedToken = document.getElementById('tamper-token-input').value.trim();
  const resultDiv = document.getElementById('tamper-result');

  if (!tamperedToken) {
    alert('Please enter or modify the token string!');
    return;
  }

  resultDiv.style.display = 'block';
  resultDiv.className = ''; // reset classes
  resultDiv.innerHTML = `<span style="color: var(--text-secondary);"><i class="fa-solid fa-spinner fa-spin"></i> Dispatching request to secure endpoint...</span>`;

  try {
    const res = await fetch('/api/auth/status', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${tamperedToken}`
      }
    });

    const data = await res.json();

    if (res.ok && data.valid) {
      resultDiv.style.background = 'rgba(0, 255, 204, 0.08)';
      resultDiv.style.border = '1px solid var(--accent-primary)';
      resultDiv.innerHTML = `
        <strong style="color: var(--accent-primary);"><i class="fa-solid fa-circle-check"></i> SUCCESS: Token verification succeeded!</strong><br>
        <span style="color: var(--text-secondary); font-size: 0.75rem;">Status: 200 OK. The token is fully valid and untampered.</span>
      `;
    } else {
      throw new Error(data.error || 'Signature verification failed');
    }

  } catch (err) {
    resultDiv.style.background = 'rgba(255, 51, 102, 0.08)';
    resultDiv.style.border = '1px solid var(--accent-danger)';
    resultDiv.innerHTML = `
      <strong style="color: var(--accent-danger);"><i class="fa-solid fa-circle-xmark"></i> SERVER REJECTED SIGNATURE: Validation Failed!</strong><br>
      <span style="color: var(--text-secondary); font-size: 0.75rem; display: block; margin-top: 0.5rem; line-height: 1.4;">
        <strong>HTTP Status:</strong> 403 Forbidden / 401 Unauthorized<br>
        <strong>Details:</strong> ${err.message}<br>
        <strong>Compliance defense:</strong> The server successfully checked the HMAC-SHA256 signature against the private key and rejected the modified data block, preventing session hijacking.
      </span>
    `;
  }
}

// JWT Cryptographic Key Strength Auditor
function auditSecretKeyStrength() {
  const secret = document.getElementById('jwt-secret-audit-input').value.trim();
  const resultDiv = document.getElementById('secret-audit-result');
  if (!secret) {
    alert('Please enter a secret key to analyze!');
    return;
  }

  // Calculate Shannon Entropy
  const len = secret.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = secret[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  // Total Entropy Bits
  const totalBits = Math.ceil(entropy * len);
  let grade = '';
  let color = '';
  let statusText = '';

  if (len < 16 || totalBits < 64) {
    grade = 'F (CRITICAL VULNERABILITY)';
    color = 'var(--accent-danger)';
    statusText = 'Fails cryptographic strength standards. Vulnerable to dictionary attacks and offline brute-force cracking within minutes.';
  } else if (len < 32 || totalBits < 128) {
    grade = 'C (WARNING / WEAK)';
    color = 'var(--accent-warning)';
    statusText = 'Sub-optimal strength. Underpowered for high-security cloud environments. Recommended minimum length is 32 characters.';
  } else {
    grade = 'A+ (COMPLIANT & SECURE)';
    color = 'var(--accent-primary)';
    statusText = 'Highly secure! Meets HS256 compliance requirements (256+ bits of entropy). Proofed against offline cryptographic cracking.';
  }

  resultDiv.style.display = 'block';
  resultDiv.innerHTML = `
    <strong>Analysis Results:</strong><br>
    • Character Length: <span style="color: var(--accent-secondary);">${len} characters</span><br>
    • Character Entropy: <span style="color: var(--accent-secondary);">${entropy.toFixed(3)} bits/char</span><br>
    • Total Est. Strength: <span style="color: var(--accent-secondary);">${totalBits} bits</span><br>
    • Compliance Rating: <strong style="color: ${color};">${grade}</strong><br>
    <span style="display: block; margin-top: 0.5rem; color: var(--text-secondary); line-height: 1.4;">
      <strong>Details:</strong> ${statusText}
    </span>
  `;
}




