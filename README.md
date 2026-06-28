# 🔐 AuthGuard-MFA — Cloud Security & Web Application Auditor Console

AuthGuard-MFA is a Next-Generation, Zero-Trust Identity Portal and Security Information & Event Management (SIEM) console. It is built as a Web Application Security (WAS) and Cloud/Virtualization Security capstone project, demonstrating compliance against strict **CIS Benchmarks**, **OWASP Top 10**, and **Least Privilege Policies (RBAC)**.

![AuthGuard-MFA Security Command Center Dashboard](was_mini_dashboard.png)

---

## 💎 Design System & Aesthetics
* **macOS-Style Saturation Glassmorphic Theme:** Beautiful frosted-glass panels utilizing macOS saturate-blur filters (`backdrop-filter: blur(20px) saturate(180%)`) floating over animated, glow-glowing background spheres.
* **Responsive Command Grid:** All tools, live terminal boxes, subnets, and compliance metrics load stacked side-by-side or in multi-columns. No tabs or clicks required.
* **File Protocol Warning Banner:** Injects automatic warnings if HTML pages are clicked locally via `file:///` protocol instead of the server origin.

---

## 🛠️ Advanced Security Features

### 1. Multi-Factor Authentication (MFA/TOTP)
* Fully functional Google Authenticator / Authy time-based enrollment (TOTP).
* Extends speakeasy verification with a **+/- 5 minutes drift-drift tolerance window**.
* **Emergency Bypass Backdoor:** Support bypass codes `123456` or `000000` to prevent presentation failures during network clock drifts on virtual machine engines.

### 2. Least Privilege & Role-Based Access Control (RBAC)
* Change user roles dynamically between **Admin**, **SecOps**, and **Guest** in the SIEM panel.
* **Guest Role:** Censors all logs and block exploits simulations (OWASP A01: Broken Access Control compliance).
* **SecOps Role:** Redacts SQLite Bcrypt password hashes and blocks write-simulations.
* **Admin Role:** Full master clearance.

### 3. WAS Exploit Simulators
* **Brute-Force Simulator:** Fires 10 rapid login actions. Triggers backend rate-limit blocks (HTTP 429) after 5 failed attempts.
* **XSS Sanitizer Input:** Real-time sanitization of HTML script tags via backend entity escaping.
* **Session Theft Auditor:** Proves session security by checking that HttpOnly cookies cannot be read by browser script nodes.

### 4. SIEM Log Parser & AWS CloudWatch SNS Alarms
* Regex-based parser extracts timestamps, severity weights, usernames, and source IPs from server raw logs.
* Dispatches simulated **AWS SNS topic alerts** for `WARNING` and `CRITICAL` logs.
* **VCS-style Ingestion Animation:** Visualizes a `log_entry.json` file traveling step-by-step from Docker Container ➔ JSON Formatter ➔ Cloud Aggregator ➔ SIEM Alerting in real-time.

### 5. Cryptographic Strength Auditor
* Live calculator utilizing **Shannon Entropy** to check strength bits and rating grades (A+ to F) for custom JWT Secret Keys.

### 6. Excel Logs Exporter
* Exports SIEM event log database to a downloadable CSV spreadsheet formatted with UTF-8 BOM so Microsoft Excel loads titles, columns, and timestamps correctly.

---

## 🚀 Installation & Running Locally

### Prerequisites
* [Node.js](https://nodejs.org/) (v16+)
* npm

### Running Server
1. Clone the repository and enter the directory.
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Run the Express service:
   ```bash
   npm start
   ```
4. Access the application in your browser:
   * **Home:** [http://localhost:3000](http://localhost:3000)
   * **Console Dashboard:** [http://localhost:3000/login.html](http://localhost:3000/login.html)
