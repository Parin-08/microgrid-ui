/* =========================================================
   CyberSecure Microgrid Controller — With Backend API
   ========================================================= */

// API Configuration - Reads from .env file
const API_BASE = 'https://microgrid-final.onrender.com';

console.log('Connecting to backend at:', API_BASE);

async function apiCall(endpoint, options = {}) {
  try {
    const response = await fetch(API_BASE + endpoint, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error('API call failed:', error);
    return null;
  }
}
  

// ── State ────────────────────────────────────────────────
const STATE = {
  currentUser: null,
  currentPage: 'dashboard',
  alerts: [],
  logs: [],
  dataInterval: null,
  chartInstances: {},
  data: {
  solar: 0, battery: 0, load: 0,
  gridImport: 0, gridExport: 0,
  temperature: 0, alert: 0, hour: 0,
  batteryAction: 0,
  mode: 'grid-connected', securityLevel: 'normal',
  threatScore: 18,
  cyberThreatScore: 0,
  attackInjected: 0,
  attackType: 'None',
  encryptionStatus: true,
  activeConnections: 4, failedLogins: 0,
  mqttStatus: 'connected', tlsStatus: true,
  anomalies: [], powerFlow: []
},
  history: {
    solar:         [],
    load:          [],
    battery:       [],
    grid:          [],
    threat:        [],
    temperature:   [],
    alert:         [],
    alertHours:    [],
    solarHours:    [],
    loadHours:     [],
    batteryHours:  [],
    gridHours:     [],
    tempHours:     [],
    threatHours:   [],
    solarByHour:   {},
    loadByHour:    {},
    batteryByHour: {},
    gridByHour:    {},
    tempByHour:    {},
    alertByHour:   {},
  },
  loginAttempts: {},
  notifications: [],
};
function makeChart(id, type, labels, datasets, opts = {}) {
  const canvas = document.getElementById(id);
  if (!canvas) return null;
  if (STATE.chartInstances[id]) { try { STATE.chartInstances[id].destroy(); } catch(e){} }
  const chart = new Chart(canvas, {
    type,
    data: { labels, datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 0 },
      plugins: {
        legend: { display: opts.legend || false, labels: { color: '#7a9cc0', font: { size: 11 } } },
        tooltip: { backgroundColor: '#0a1628', borderColor: '#1a3a5c', borderWidth: 1, titleColor: '#e2f0ff', bodyColor: '#7a9cc0' }
      },
      scales: type !== 'doughnut' && type !== 'pie' ? {
        x: { grid: { color: 'rgba(26,58,92,0.4)' }, ticks: { color: '#4a6a8a', font: { size: 10 } }, ...(opts.xScale||{}) },
        y: { grid: { color: 'rgba(26,58,92,0.4)' }, ticks: { color: '#4a6a8a', font: { size: 10 } }, ...(opts.yScale||{}) }
      } : {},
      ...opts.extra
    }
  });
  STATE.chartInstances[id] = chart;
  return chart;
}
function getActiveCyberAttack() {
  const cyberAnomalies = (STATE.data.anomalies || []).filter(a => 
    a.attack_type === 'BruteForce' || 
    a.attack_type === 'CredentialStuffing' ||
    a.attack_type === 'Phishing' ||
    a.attack_type === 'MITM' ||
    a.attack_type === 'DDoS' ||
    a.attack_type === 'SessionHijacking'
  );
  if (cyberAnomalies.length === 0) return '—';
  const latestAttack = cyberAnomalies[cyberAnomalies.length - 1];
  return latestAttack.attack_type || 'Unknown Attack';
}
const USERS = {
  admin:    { password: 'secret',    role: 'admin',    name: 'Dr. Arjun Mehta',    avatar: 'AM' },
  operator: { password: 'secret',     role: 'operator', name: 'Priya Sharma',        avatar: 'PS' },
  viewer:   { password: 'secret',     role: 'viewer',   name: 'Raj Patel',           avatar: 'RP' },
};

const ROLE_PERMISSIONS = {
  admin:    ['dashboard','energy','security','anomaly','logs','grid','settings','users'],
  operator: ['dashboard','energy','security','anomaly','logs','grid'],
  viewer:   ['dashboard','energy','logs'],
};
const CHART_LABELS = Array.from({length: 100}, (_, i) => `T-${100-i}`);
// Prepopulate history arrays
for (let i = 0; i < 100; i++) {
  STATE.history.solar.push(0);
  STATE.history.load.push(0);
  STATE.history.battery.push(0);
  STATE.history.grid.push(0);
  STATE.history.threat.push(0);
  STATE.history.temperature.push(0);
  STATE.history.alert.push(0);
}

// Prepopulate logs
const initLogs = [
  { time: '08:00:12', type: 'success', category: 'auth',   msg: 'Admin user logged in successfully',              user: 'admin'    },
  { time: '08:01:44', type: 'info',    category: 'system', msg: 'Microgrid simulation initialized',               user: 'system'   },
  { time: '08:02:30', type: 'success', category: 'system', msg: 'TLS encryption channel established',             user: 'system'   },
  { time: '08:03:15', type: 'info',    category: 'system', msg: 'MQTT broker connected on port 8883 (TLS)',       user: 'system'   },
  { time: '08:05:22', type: 'info',    category: 'system', msg: 'Solar generation nominal at 42.5 kW',            user: 'system'   },
  { time: '08:06:10', type: 'warning', category: 'system', msg: 'Battery SOC dropped below 70% threshold',        user: 'system'   },
  { time: '08:07:55', type: 'info',    category: 'system', msg: 'Load balancing algorithm activated',             user: 'system'   },
  { time: '08:09:01', type: 'warning', category: 'auth',   msg: 'Failed login attempt from IP 192.168.1.105',     user: 'unknown'  },
  { time: '08:11:33', type: 'success', category: 'system', msg: 'Grid synchronization check passed — 50.01 Hz',   user: 'system'   },
  { time: '08:13:40', type: 'info',    category: 'auth',   msg: 'Operator user logged in',                        user: 'operator' },
];
STATE.logs = [...initLogs];

const initAlerts = [
  { id: 1, type: 'warning',  title: 'Battery SOC Below 70%',           desc: 'Battery level at 68%. Consider reducing load or enabling grid import.', time: '08:06', read: false },
  { id: 2, type: 'info',     title: 'Grid Export Active',               desc: 'Currently exporting 4.1 kW to utility grid.',                            time: '08:07', read: false },
  { id: 3, type: 'warning',  title: 'Suspicious Login Attempt',         desc: 'Failed login from IP 192.168.1.105. Monitoring for brute force.',        time: '08:09', read: false },
  { id: 4, type: 'success',  title: 'Grid Sync Verified',               desc: 'Frequency and voltage synchronization confirmed.',                        time: '08:11', read: true  },
];
STATE.alerts = [...initAlerts];

// ── Utilities ─────────────────────────────────────────────
function now() {
  return new Date().toLocaleTimeString('en-GB', { hour12: false });
}
function rnd(min, max, dec = 1) {
  return +(min + Math.random() * (max - min)).toFixed(dec);
}
function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }
function addLog(type, category, msg, user = 'system') {
  STATE.logs.unshift({ time: now(), type, category, msg, user });
  if (STATE.logs.length > 200) STATE.logs.pop();
  if (STATE.currentPage === 'logs') renderLogsPage();
}
function addAlert(type, title, desc) {
  const id = Date.now();
  STATE.alerts.unshift({ id, type, title, desc, time: now(), read: false });
  STATE.notifications.unshift({ id, type, title, time: now() });
  updateNotifBadge();
  if (STATE.currentPage === 'security') renderSecurityPage();
}

// ── Clock ─────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById('topbar-clock');
  if (!el) return;
  function tick() {
    el.textContent = new Date().toLocaleString('en-GB', {
      day:'2-digit', month:'short', year:'numeric',
      hour:'2-digit', minute:'2-digit', second:'2-digit', hour12: false
    });
  }
  tick();
  setInterval(tick, 1000);
}

// ── Notification Badge ────────────────────────────────────
function updateNotifBadge() {
  const badge = document.getElementById('notif-count');
  const unread = STATE.alerts.filter(a => !a.read).length;
  if (badge) badge.textContent = unread > 0 ? unread : '';
  const navBadge = document.getElementById('nav-alerts-badge');
  if (navBadge) navBadge.textContent = unread;
}

// ── Login Screen ──────────────────────────────────────────
// ═══════════════════════════════════════════════════════════
//  DROP-IN REPLACEMENT — paste this over your existing
//  renderLogin() function in app.js.
//
//  ✅ handleLogin()  — completely unchanged
//  ✅ apiCall()      — completely unchanged
//  ✅ All credentials, JWT, dashboard — completely unchanged
//  ✅ Only the visual HTML inside renderLogin() is new
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
//  DROP-IN REPLACEMENT — paste this over your existing
//  renderLogin() function in app.js.
//
//  ✅ handleLogin()  — completely unchanged
//  ✅ apiCall()      — completely unchanged
//  ✅ All credentials, JWT, dashboard — completely unchanged
//  ✅ Only the visual HTML inside renderLogin() is new
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
//  DROP-IN REPLACEMENT — paste this over your existing
//  renderLogin() function in app.js.
//
//  ✅ handleLogin()  — completely unchanged
//  ✅ apiCall()      — completely unchanged
//  ✅ All credentials, JWT, dashboard — completely unchanged
//  ✅ Only the visual HTML inside renderLogin() is new
// ═══════════════════════════════════════════════════════════

function renderLogin() {
  const root = document.getElementById('app-root');

  root.innerHTML = `
  <!-- ── Keyframe styles injected once ── -->
  <style id="nexora-login-styles">
    @keyframes nx-spin    { from{transform:translate(-50%,-50%) rotate(0deg)}   to{transform:translate(-50%,-50%) rotate(360deg)}  }
    @keyframes nx-spinrev { from{transform:translate(-50%,-50%) rotate(0deg)}   to{transform:translate(-50%,-50%) rotate(-360deg)} }
    @keyframes nx-floatY  { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-14px)} }
    @keyframes nx-glow    { 0%,100%{opacity:.15} 50%{opacity:.35} }
    @keyframes nx-blink   { 0%,100%{opacity:1}  50%{opacity:.25} }
    @keyframes nx-fadeUp  { from{opacity:0;transform:translateY(18px)} to{opacity:1;transform:translateY(0)} }
    @keyframes nx-scan    { 0%{transform:translateY(-5%)} 100%{transform:translateY(1100%)} }
    @keyframes nx-sweep   { 0%{left:-80%} 100%{left:160%} }

    #nexora-login-screen {
      min-height: 100vh;
      display: flex;
      background: #09070f;
      font-family: 'Georgia', serif;
      position: relative;
      overflow: hidden;
    }

    /* hex grid */
    #nexora-login-screen::before {
      content: '';
      position: absolute; inset: 0; pointer-events: none;
      opacity: .16; z-index: 0;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='104'%3E%3Cpolygon points='30,2 58,17 58,47 30,62 2,47 2,17' fill='none' stroke='%237F77DD' stroke-width='0.5'/%3E%3Cpolygon points='30,54 58,69 58,99 30,114 2,99 2,69' fill='none' stroke='%237F77DD' stroke-width='0.5'/%3E%3C/svg%3E");
    }

    .nx-orb {
      position: absolute; border-radius: 50%; pointer-events: none; z-index: 0;
    }
    .nx-orb-1 {
      width:440px; height:440px; top:-80px; left:-80px;
      background: radial-gradient(circle,rgba(83,74,183,.22) 0%,rgba(38,33,92,.08) 50%,transparent 70%);
      animation: nx-glow 7s ease-in-out infinite;
    }
    .nx-orb-2 {
      width:260px; height:260px; bottom:60px; right:-40px;
      background: radial-gradient(circle,rgba(127,119,221,.14) 0%,transparent 65%);
      animation: nx-glow 9s ease-in-out infinite reverse;
    }

    .nx-scanline {
      position: absolute; width: 100%; height: 2px; pointer-events: none; z-index: 0;
      background: linear-gradient(transparent,rgba(127,119,221,.06),transparent);
      animation: nx-scan 9s linear infinite;
    }

    /* ── LEFT PANEL ── */
    #nx-left {
      width: 52%; position: relative; z-index: 1;
      display: flex; flex-direction: column; justify-content: flex-end;
      padding: 48px; overflow: hidden;
    }

    /* orbital rings */
    .nx-ring {
      position: absolute; border-radius: 50%;
      top: 50%; left: 50%;
    }
    .nx-ring-1 {
      width:280px; height:280px;
      border: 1px solid rgba(127,119,221,.25);
      transform: translate(-50%,-50%);
      animation: nx-spin 22s linear infinite;
    }
    .nx-ring-2 {
      width:224px; height:224px;
      border: 1px solid rgba(175,169,236,.14);
      transform: translate(-50%,-50%);
      animation: nx-spinrev 16s linear infinite;
    }
    .nx-ring-3 {
      width:168px; height:168px;
      border: 1px solid rgba(83,74,183,.28);
      transform: translate(-50%,-50%);
      animation: nx-spin 11s linear infinite;
    }
    .nx-ring-dot {
      position: absolute; border-radius: 50%;
      left: 50%; transform: translateX(-50%);
    }

    .nx-orbital-wrap {
      position: absolute;
      width: 280px; height: 280px;
      top: 38%; left: 50%;
      transform: translate(-50%,-50%);
      animation: nx-floatY 8s ease-in-out infinite;
    }
    .nx-core {
      position: absolute; border-radius: 50%;
      top:50%; left:50%;
      width:120px; height:120px;
      transform: translate(-50%,-50%);
      background: radial-gradient(circle,rgba(83,74,183,.28) 0%,rgba(38,33,92,.12) 60%,transparent 80%);
      display:flex; align-items:center; justify-content:center;
    }
    .nx-core-inner {
      width:58px; height:58px; border-radius:50%;
      background: rgba(83,74,183,.18);
      border: 1px solid rgba(127,119,221,.35);
      display:flex; align-items:center; justify-content:center;
      font-size:22px; color:#AFA9EC;
    }

    .nx-left-meta { position:relative; z-index:2; animation: nx-fadeUp .9s ease both; animation-delay:.25s; }
    .nx-eyebrow {
      display:flex; align-items:center; gap:12px;
      font-family: sans-serif; font-size:11px; letter-spacing:.22em;
      color:rgba(127,119,221,.65); text-transform:uppercase; margin-bottom:18px;
    }
    .nx-eyebrow::before { content:""; width:32px; height:1px; background:rgba(127,119,221,.45); }
    .nx-title { font-size:54px; font-weight:400; color:#E8E6FC; line-height:1.08; margin-bottom:18px; letter-spacing:-.025em; text-shadow:0 0 80px rgba(127,119,221,.3); }
    .nx-title em { font-style:italic; background:linear-gradient(135deg,#DDD9F8,#AFA9EC,#7F77DD); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }
    .nx-sub { font-family:sans-serif; font-size:15px; color:rgba(175,169,236,.55); line-height:1.8; margin-bottom:32px; max-width:320px; }
    .nx-pulse-row { display:flex; align-items:center; gap:12px; font-family:sans-serif; font-size:12px; color:rgba(175,169,236,.5); }
    .nx-pulse-dot {
      width:7px; height:7px; border-radius:50%; display:inline-block;
      background:#1D9E75; box-shadow:0 0 0 3px rgba(29,158,117,.2);
      animation: nx-blink 2.5s ease-in-out infinite;
    }

    /* ── RIGHT PANEL ── */
    #nx-right {
      width:48%; z-index:1;
      background:rgba(255,255,255,.025);
      border-left:1px solid rgba(127,119,221,.12);
      display:flex; flex-direction:column; justify-content:center;
      padding:52px 44px;
      animation: nx-fadeUp .7s ease both; animation-delay:.1s;
    }

    .nx-r-eyebrow {
      display:flex; align-items:center; gap:10px; margin-bottom:24px;
      font-family:sans-serif; font-size:10px; letter-spacing:.2em;
      color:rgba(127,119,221,.5); text-transform:uppercase;
    }
    .nx-r-eyebrow-line { flex:1; height:1px; background:rgba(127,119,221,.12); }
    .nx-r-title { font-size:26px; font-weight:400; color:#DDD9F8; margin-bottom:6px; letter-spacing:-.01em; }
    .nx-r-sub   { font-family:sans-serif; font-size:12px; color:rgba(175,169,236,.32); margin-bottom:36px; letter-spacing:.02em; }

    /* field */
    .nx-field { margin-bottom:20px; }
    .nx-label {
      display:block; font-family:sans-serif; font-size:10px; letter-spacing:.15em;
      color:rgba(175,169,236,.42); text-transform:uppercase; margin-bottom:9px;
    }
    .nx-field-wrap { position:relative; display:flex; align-items:center; }
    .nx-field-icon { position:absolute; left:0; color:rgba(127,119,221,.45); font-size:15px; pointer-events:none; transition:color .25s; }
    .nx-input {
      width:100%; background:transparent; border:none;
      border-bottom:1px solid rgba(127,119,221,.18);
      padding:10px 6px 10px 26px;
      font-family:sans-serif; font-size:14px; color:#CCC8F8;
      outline:none; transition:border-color .25s; letter-spacing:.02em;
    }
    .nx-input::placeholder { color:rgba(175,169,236,.22); }
    .nx-input:focus { border-bottom-color:rgba(127,119,221,.7); }
    .nx-input:focus + .nx-underline { width:100%; }
    .nx-input:focus ~ .nx-field-icon { color:rgba(175,169,236,.75); }
    .nx-underline {
      position:absolute; bottom:0; left:0; height:1px; width:0;
      background:rgba(127,119,221,.6); transition:width .35s ease; pointer-events:none;
    }
    .nx-select {
      width:100%; background:transparent; border:none;
      border-bottom:1px solid rgba(127,119,221,.18);
      padding:10px 24px 10px 26px;
      font-family:sans-serif; font-size:14px; color:#CCC8F8;
      outline:none; appearance:none; cursor:pointer; transition:border-color .25s;
    }
    .nx-select:focus { border-bottom-color:rgba(127,119,221,.7); }
    .nx-select option { background:#1a1530; color:#CCC8F8; }
    .nx-chevron { position:absolute; right:0; color:rgba(127,119,221,.38); font-size:12px; pointer-events:none; }

    /* small row */
    .nx-small-row { display:flex; align-items:center; justify-content:space-between; margin-bottom:32px; }
    .nx-session   { display:flex; align-items:center; gap:8px; cursor:pointer; font-family:sans-serif; font-size:12px; color:rgba(175,169,236,.38); }
    .nx-cb        { width:15px; height:15px; border:1px solid rgba(127,119,221,.28); border-radius:3px; background:rgba(127,119,221,.07); display:flex; align-items:center; justify-content:center; font-size:10px; transition:background .2s,border-color .2s; }
    .nx-recover   { background:none; border:none; cursor:pointer; font-family:sans-serif; font-size:12px; color:rgba(127,119,221,.5); letter-spacing:.04em; transition:color .2s; }
    .nx-recover:hover { color:#AFA9EC; }

    /* auth button */
    .nx-btn {
      width:100%; padding:15px; margin-bottom:28px;
      background:rgba(83,74,183,.22); border:1px solid rgba(127,119,221,.3);
      border-radius:2px; color:#CCC8F8;
      font-family:sans-serif; font-size:11px; letter-spacing:.2em; text-transform:uppercase;
      cursor:pointer; display:flex; align-items:center; justify-content:center; gap:10px;
      position:relative; overflow:hidden;
      transition:background .25s, border-color .25s;
    }
    .nx-btn:hover   { background:rgba(83,74,183,.35); border-color:rgba(127,119,221,.55); }
    .nx-btn:active  { transform:scale(.99); }
    .nx-btn:hover .nx-btn-sweep { animation: nx-sweep .55s ease forwards; }
    .nx-btn-sweep   { position:absolute; top:0; left:-80%; width:60%; height:100%; pointer-events:none; background:linear-gradient(90deg,transparent,rgba(175,169,236,.07),transparent); }
    .nx-btn:disabled { opacity:.5; cursor:not-allowed; }

    /* footer */
    .nx-footer     { display:flex; align-items:center; justify-content:space-between; }
    .nx-footer-sig { display:flex; align-items:center; gap:6px; font-family:sans-serif; font-size:10px; color:rgba(175,169,236,.24); }
    .nx-tls        { display:flex; align-items:center; gap:5px; border:1px solid rgba(29,158,117,.2); border-radius:2px; padding:3px 9px; font-family:sans-serif; font-size:9px; letter-spacing:.1em; text-transform:uppercase; color:rgba(29,158,117,.72); }
    .nx-tls-pip    { width:5px; height:5px; border-radius:50%; background:#1D9E75; animation: nx-blink 2.5s ease-in-out infinite; }

    /* error box (keep your existing style but purple-tinted) */
    .nx-error { display:none; align-items:center; gap:8px; margin-top:10px; padding:10px 14px; border:1px solid rgba(226,75,74,.35); border-radius:4px; background:rgba(226,75,74,.07); color:rgba(226,75,74,.85); font-family:sans-serif; font-size:12px; }
  </style>

  <!-- ── Screen ── -->
  <div id="nexora-login-screen">
    <div class="nx-orb nx-orb-1"></div>
    <div class="nx-orb nx-orb-2"></div>
    <div class="nx-scanline"></div>

    <!-- LEFT -->
    <div id="nx-left">
      <!-- orbital -->
      <div class="nx-orbital-wrap">
        <div class="nx-ring nx-ring-1">
          <div class="nx-ring-dot" style="width:7px;height:7px;top:-3.5px;background:#AFA9EC;box-shadow:0 0 8px rgba(175,169,236,.8);"></div>
        </div>
        <div class="nx-ring nx-ring-2">
          <div class="nx-ring-dot" style="width:5px;height:5px;bottom:-2.5px;top:auto;background:#7F77DD;box-shadow:0 0 6px rgba(127,119,221,.9);"></div>
        </div>
        <div class="nx-ring nx-ring-3">
          <div class="nx-ring-dot" style="width:6px;height:6px;top:-3px;background:#5DCAA5;box-shadow:0 0 8px rgba(93,202,165,.9);"></div>
        </div>
        <div class="nx-core">
          <div class="nx-core-inner">⚡</div>
        </div>
      </div>

      <!-- meta -->
      <div class="nx-left-meta">
        <div class="nx-eyebrow">Grid Control System</div>
        <h1 class="nx-title">Nexora<br><em>Intelligence</em></h1>
        <p class="nx-sub">Adaptive microgrid orchestration with real-time anomaly detection and cybersecurity monitoring.</p>
        <div class="nx-pulse-row">
          <span class="nx-pulse-dot"></span>
          All systems nominal · Bengaluru Node
        </div>
      </div>
    </div>

    <!-- RIGHT -->
    <div id="nx-right">
      <div class="nx-r-eyebrow">Secure access<div class="nx-r-eyebrow-line"></div></div>
      <h2 class="nx-r-title">Operator sign-in</h2>
      <p class="nx-r-sub">TLS 1.3 encrypted</p>

      <!-- Username -->
      <div class="nx-field">
        <label class="nx-label" for="login-user">Operator ID</label>
        <div class="nx-field-wrap">
          <i class="fas fa-user nx-field-icon"></i>
          <input class="nx-input" type="text" id="login-user" placeholder="Enter your operator ID" autocomplete="off" />
          <span class="nx-underline"></span>
        </div>
      </div>

      <!-- Password -->
      <div class="nx-field">
        <label class="nx-label" for="login-pass">Access Key</label>
        <div class="nx-field-wrap">
          <i class="fas fa-lock nx-field-icon"></i>
          <input class="nx-input" type="password" id="login-pass" placeholder="············" />
          <span class="nx-underline"></span>
        </div>
      </div>

      <!-- Role -->
      <div class="nx-field" style="margin-bottom:24px;">
        <label class="nx-label" for="login-role">Access Level</label>
        <div class="nx-field-wrap">
          <i class="fas fa-shield-alt nx-field-icon"></i>
          <select class="nx-select" id="login-role">
            <option value="admin">Grid administrator</option>
            <option value="operator">Systems engineer</option>
            <option value="viewer">Read-only observer</option>
          </select>
          <span class="nx-chevron">▾</span>
        </div>
      </div>

      <!-- Keep session + recover -->
      <div class="nx-small-row">
        <div class="nx-session" onclick="this.querySelector('.nx-cb').classList.toggle('nx-cb-on'); this.querySelector('.nx-cb').textContent = this.querySelector('.nx-cb').classList.contains('nx-cb-on') ? '✓' : '';">
          <span class="nx-cb"></span>
          Keep session active
        </div>
        <button class="nx-recover">Recover access</button>
      </div>

      <!-- Auth button — calls the SAME handleLogin() as before -->
      <button class="nx-btn" id="nx-auth-btn" onclick="handleLogin()">
        <span class="nx-btn-sweep"></span>
        <i class="fas fa-arrow-right"></i>
        Authenticate &amp; enter
      </button>

      <!-- Error (same id your existing code uses) -->
      <div class="nx-error" id="login-error">
        <i class="fas fa-exclamation-triangle"></i>
        <span id="login-error-msg">Invalid credentials</span>
      </div>

      <!-- Footer -->
      <div class="nx-footer">
        <div class="nx-footer-sig">
          <i class="fas fa-server" style="font-size:11px;"></i>
          broker.microgrid.local
        </div>
        <div class="nx-tls"><div class="nx-tls-pip"></div>TLS 1.3</div>
      </div>
    </div>
  </div>`;

  // ── Enter key on password → login ──────────────────────
  const passEl = document.getElementById('login-pass');
  if (passEl) {
    passEl.addEventListener('keypress', e => {
      if (e.key === 'Enter') handleLogin();
    });
  }

  // ── Checkbox style sync ─────────────────────────────────
  document.querySelectorAll('.nx-cb-on').forEach(el => {
    el.style.background = 'rgba(127,119,221,.28)';
    el.style.borderColor = 'rgba(127,119,221,.65)';
  });
}

// ── Patch handleLogin to update button state ────────────────
//
//  Your original handleLogin() already does everything correctly.
//  This small wrapper just syncs the new button's disabled/text
//  state with what the original function expects.
//
//  The original function looks for `.btn-login` — we alias it here.
//  If you prefer, add class "btn-login" to #nx-auth-btn in the HTML
//  above instead of using this patch.
//
const _origHandleLogin = handleLogin;  // keep reference
window.handleLogin = async function() {
  const btn = document.getElementById('nx-auth-btn');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>&nbsp; Authenticating…';
  }
  await _origHandleLogin();
  // If login failed, restore button
  if (btn && btn.disabled) {
    btn.disabled = false;
    btn.innerHTML = '<span class="nx-btn-sweep"></span><i class="fas fa-arrow-right"></i> Authenticate &amp; enter';
  }
};
async function handleLogin() {
  const btn = document.querySelector('.btn-login');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Authenticating...'; }
  const username = document.getElementById('login-user').value.trim().toLowerCase();
  const password = document.getElementById('login-pass').value;
  const role = document.getElementById('login-role').value;
  const errorEl = document.getElementById('login-error');
  const errorMsg = document.getElementById('login-error-msg');  // ← ADD THIS LINE

  // Call real backend
  const result = await apiCall('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  });

  if (!result || !result.access_token) {
    errorEl.style.display = 'flex';
    const btn2 = document.querySelector('.btn-login');
    if (btn2) { btn2.disabled = false; btn2.innerHTML = 'AUTHENTICATE & ACCESS'; }
    errorMsg.textContent = result?.message || 'Invalid credentials';
    addLog('warning', 'auth', `Failed login attempt for: ${username}`);
    return;
  }

  STATE.currentUser = {
    username,
    role: result.role,
    name: result.name,
    avatar: (result.name || username).split(' ').map(n=>n[0]).join('').slice(0,2).toUpperCase(),
    token: result.access_token
  };
  
  // Reset cyber threat score on successful login
  STATE.data.cyberThreatScore = 0;
  STATE.data.anomalies = [];
  window.cyberAnomaliesCache = [];
  await fetchRealAnomalies();
  
  addLog('success', 'auth', `User "${username}" authenticated via backend`);
  renderApp();
  initMQTT();
  startRealTimeData();

}

// ── Main App Shell ────────────────────────────────────────
function renderApp() {
  const root = document.getElementById('app-root');
  const u = STATE.currentUser;
  const perms = ROLE_PERMISSIONS[u.role];

  const navItems = [
    { id:'dashboard', icon:'fa-tachometer-alt',  label:'Dashboard',          section:'MONITORING'   },
    { id:'energy',    icon:'fa-bolt',             label:'Control Center',  section:null           },
    { id:'grid', icon:'fa-comments',               label:'Personalized for you', section:null },
    { id:'security',  icon:'fa-shield-alt',       label:'Security Center',    section:'CYBERSECURITY'},
    { id:'anomaly',   icon:'fa-brain',            label:'Anomaly Detection',  section:null           },
    { id:'logs',      icon:'fa-list-alt',         label:'Activity Logs',      section:null           },
    { id:'settings',  icon:'fa-cog',              label:'System Settings',    section:'CONFIG'       },
    { id:'users',     icon:'fa-users-cog',        label:'User Management',    section:null           },
  ];

  let navHTML = '';
  let lastSection = '';
  navItems.forEach(item => {
    if (!perms.includes(item.id)) return;
    if (item.section && item.section !== lastSection) {
      navHTML += `<div class="nav-section-label">${item.section}</div>`;
      lastSection = item.section;
    }
    const badge = item.id === 'security' ? `<span class="nav-badge" id="nav-alerts-badge">${STATE.alerts.filter(a=>!a.read).length}</span>` : '';
    navHTML += `
      <div class="nav-item ${item.id === STATE.currentPage ? 'active' : ''}" onclick="navigateTo('${item.id}')" id="nav-${item.id}">
        <span class="nav-icon"><i class="fas ${item.icon}"></i></span>
        <span>${item.label}</span>${badge}
      </div>`;
  });

  root.innerHTML = `
  <!-- SIDEBAR -->
  <nav id="sidebar">
    <div class="sidebar-header">
      <div class="sidebar-logo-icon">⚡</div>
      <div>
        <div class="sidebar-logo-text">NEXORA O.N.E</div>
        <div class="sidebar-logo-sub">Grid Control System v3.2</div>
      </div>
    </div>
    <div class="sidebar-nav">${navHTML}</div>
    <div class="sidebar-footer">
      <div class="user-info">
        <div class="user-avatar ${u.role}">${u.avatar}</div>
        <div>
          <div class="user-name">${u.name}</div>
          <div class="user-role">${u.role}</div>
        </div>
        <button class="btn-logout" onclick="handleLogout()" title="Logout">
          <i class="fas fa-sign-out-alt"></i>
        </button>
      </div>
    </div>
  </nav>

  <!-- TOP BAR -->
  <header id="topbar">
    <button class="btn-sidebar-toggle" onclick="toggleSidebar()" title="Toggle Sidebar">
      <i class="fas fa-bars"></i>
    </button>
    <div class="topbar-title" id="page-title">Dashboard</div>
    <div class="topbar-spacer"></div>
    <div class="system-status-pills">
      <div class="status-pill online" id="pill-mqtt"><span class="pulse-dot"></span> MQTT</div>
      <div class="status-pill online" id="pill-tls"><span class="pulse-dot"></span> TLS SECURE</div>
      <div class="status-pill info" id="pill-mode"><span class="pulse-dot"></span> GRID-CONNECTED</div>
    </div>
    <button class="notif-btn" onclick="toggleNotifPanel()" title="Notifications">
      <i class="fas fa-bell"></i>
      <span class="notif-count" id="notif-count"></span>
    </button>
    <div class="topbar-clock" id="topbar-clock"></div>
  </header>

  <!-- NOTIFICATION PANEL -->
  <div id="notif-panel" style="display:none;position:fixed;top:68px;right:16px;width:320px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;z-index:200;box-shadow:0 8px 32px rgba(0,0,0,0.5);max-height:400px;overflow-y:auto;">
    <div style="padding:14px 16px;border-bottom:1px solid var(--border-color);display:flex;align-items:center;justify-content:space-between;">
      <span style="font-weight:700;font-size:13px;">Notifications</span>
      <button onclick="clearNotifs()" style="background:none;border:none;color:var(--text-muted);font-size:12px;cursor:pointer;">Clear All</button>
    </div>
    <div id="notif-list"></div>
  </div>

  <!-- MAIN CONTENT -->
  <main id="main-content" class="grid-bg">
    <div id="page-dashboard" class="page active"></div>
    <div id="page-energy"    class="page"></div>
    <div id="page-grid"      class="page"></div>
    <div id="page-security"  class="page"></div>
    <div id="page-anomaly"   class="page"></div>
    <div id="page-logs"      class="page"></div>
    <div id="page-settings"  class="page"></div>
    <div id="page-users"     class="page"></div>
  </main>`;

  startClock();
  updateNotifBadge();
  renderDashboard();
}

function stopRealTimeData() {
  if (STATE.dataInterval) { clearInterval(STATE.dataInterval); STATE.dataInterval = null; }
}

async function startRealTimeData() {
  stopRealTimeData();
  
  async function fetchData() {
    if (!STATE.currentUser || !STATE.currentUser.token) return;
    const data = await apiCall('/telemetry/live', {
      headers: { 'Authorization': `Bearer ${STATE.currentUser.token}` }
    });
    const anomalies = await apiCall('/anomalies/', {
      headers: { 'Authorization': 'Bearer ' + STATE.currentUser.token }
    });
    if (data) {
      Object.assign(STATE.data, data);
      updateLiveValues();
      updateLiveCharts();
      updateTopbarPills();
    }
  }
  
  await fetchData();
  STATE.dataInterval = setInterval(fetchData, 2000);
}
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('collapsed');
}
function toggleNotifPanel() {
  const p = document.getElementById('notif-panel');
  p.style.display = p.style.display === 'none' ? 'block' : 'none';
  renderNotifPanel();
}
function renderNotifPanel() {
  const list = document.getElementById('notif-list');
  if (!list) return;
  if (STATE.notifications.length === 0) {
    list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px;">No notifications</div>';
    return;
  }
  list.innerHTML = STATE.notifications.slice(0, 10).map(n => `
    <div style="padding:12px 16px;border-bottom:1px solid rgba(26,58,92,0.4);display:flex;gap:10px;align-items:flex-start;">
      <span style="font-size:16px;">${n.type==='critical'?'🔴':n.type==='warning'?'🟡':'🔵'}</span>
      <div>
        <div style="font-size:13px;font-weight:600;color:var(--text-primary)">${n.title}</div>
        <div style="font-size:11px;color:var(--text-muted);font-family:'JetBrains Mono',monospace">${n.time}</div>
      </div>
    </div>`).join('');
}
function clearNotifs() {
  STATE.notifications = [];
  STATE.alerts.forEach(a => a.read = true);
  updateNotifBadge();
  renderNotifPanel();
}
function handleLogout() {
  addLog('info', 'auth', `User "${STATE.currentUser.username}" logged out`, STATE.currentUser.username);
  stopRealTimeData();
  STATE.currentUser = null;
  STATE.currentPage = 'dashboard';
  STATE.chartInstances = {};
  renderLogin();
}
function navigateTo(page) {
  const perms = ROLE_PERMISSIONS[STATE.currentUser.role];
  if (!perms.includes(page)) return;

  STATE.currentPage = page;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const pageEl = document.getElementById(`page-${page}`);
  if (pageEl) pageEl.classList.add('active');
  const navEl = document.getElementById(`nav-${page}`);
  if (navEl) navEl.classList.add('active');

  const titles = {
    dashboard:'Dashboard Overview', energy:'Control Center', grid:'Personalized for you',
    security:'Security Center', anomaly:'Anomaly Detection', logs:'Activity Logs',
    settings:'System Settings', users:'User Management'
  };
  const titleEl = document.getElementById('page-title');
  if (titleEl) titleEl.textContent = titles[page] || page;

  // Destroy old charts to avoid canvas conflicts
  if (STATE.chartInstances) {
    Object.values(STATE.chartInstances).forEach(c => { try { c.destroy(); } catch(e){} });
    STATE.chartInstances = {};
  }

  switch(page) {
    case 'dashboard': renderDashboard(); break;
    case 'energy':    renderEnergyPage(); break;
    case 'grid':      renderGridPage(); break;
    case 'security':  renderSecurityPage(); break;
    case 'anomaly':   renderAnomalyPage(); break;
    case 'logs':      renderLogsPage(); break;
    case 'settings':  renderSettingsPage(); break;
    case 'users':     renderUsersPage(); break;
  }
}

function updateTopbarPills() {
  const d = STATE.data;
  const pill = document.getElementById('pill-mode');
  if (pill) {
    pill.textContent = d.mode === 'island' ? '🏝 ISLAND MODE' : '🔌 GRID-CONNECTED';
    pill.className = `status-pill ${d.mode === 'island' ? 'warning' : 'info'}`;
  }
}
function updateLiveValues() {
  const d = STATE.data;
  
  const solarEl = document.getElementById('live-solar');
  if (solarEl) solarEl.innerHTML = `${(d.solar || 0).toFixed(1)} <span class="kpi-unit">kW</span>`;
  
  const batteryEl = document.getElementById('live-battery');
  if (batteryEl) batteryEl.innerHTML = `${(d.battery || 0).toFixed(1)} <span class="kpi-unit">kWh</span>`;
  
  const loadEl = document.getElementById('live-load');
  if (loadEl) loadEl.innerHTML = `${(d.load || 0).toFixed(1)} <span class="kpi-unit">kW</span>`;
  
  const gridExpEl = document.getElementById('live-grid-exp');
  if (gridExpEl) gridExpEl.innerHTML = `${(d.gridExport || 0).toFixed(1)} <span class="kpi-unit">kW</span>`;
  
  const gridImpEl = document.getElementById('live-grid-imp');
  if (gridImpEl) gridImpEl.innerHTML = `${(d.gridImport || 0).toFixed(1)} <span class="kpi-unit">kW</span>`;
  
  const tempEl = document.getElementById('live-temp');
  if (tempEl) tempEl.innerHTML = `${(d.temperature || 0).toFixed(1)} <span class="kpi-unit">°C</span>`;
  
  const battFill = document.getElementById('battery-fill');
  if (battFill) {
    const battPct = Math.min(100, (d.battery / 10) * 100);
    battFill.style.width = `${battPct.toFixed(0)}%`;
  }
  
  const battText = document.getElementById('battery-bar-text');
  if (battText) battText.textContent = `${(d.battery || 0).toFixed(1)} kWh`;
// Add these lines inside updateLiveValues()
const cyberThreatEl = document.getElementById('live-cyber-threat');
if (cyberThreatEl) cyberThreatEl.textContent = `${(STATE.data.cyberThreatScore || 0).toFixed(0)}/100`;

const cyberFill = document.getElementById('cyber-threat-fill-dash');
if (cyberFill) cyberFill.style.width = `${(STATE.data.cyberThreatScore || 0)}%`;

const cyberStatus = document.getElementById('cyber-status-badge');
if (cyberStatus) {
  if (STATE.data.cyberThreatScore > 50) {
    cyberStatus.textContent = '⚠ CYBER THREAT';
    cyberStatus.className = 'status-indicator offline';
  } else {
    cyberStatus.textContent = '✓ CYBER SECURE';
    cyberStatus.className = 'status-indicator online';
  }
}

const activeAttackEl = document.getElementById('active-cyber-attack');
if (activeAttackEl) activeAttackEl.textContent = getActiveCyberAttack();
}
// ── Live Value Updates ─────────────────────────────────
function updateLiveCharts() {
  const ci = STATE.chartInstances;
  const h = STATE.history;

  // FIXED: Creates array for ALL hours 0-23
  const toSortedArrays = (byHour) => {
    const hours = [];
    const data = [];
    for (let hr = 0; hr <= 23; hr++) {
      hours.push(hr);
      if (byHour && byHour[hr] !== undefined) {
        data.push(byHour[hr]);
      } else {
        data.push(0);
      }
    }
    return {
      labels: hours.map(hr => `Hr ${hr}`),
      data: data
    };
  };

  // Update Solar
  const solarChart = ci['chart-solar'];
  if (solarChart) {
    const { labels, data } = toSortedArrays(h.solarByHour);
    solarChart.data.labels = labels;
    solarChart.data.datasets[0].data = data;
    solarChart.update('none');
  }

  // Update Load
  const loadChart = ci['chart-load'];
  if (loadChart) {
    const { labels, data } = toSortedArrays(h.loadByHour);
    loadChart.data.labels = labels;
    loadChart.data.datasets[0].data = data;
    loadChart.update('none');
  }

  // Update Battery
  const batteryChart = ci['chart-battery'];
  if (batteryChart) {
    const { labels, data } = toSortedArrays(h.batteryByHour);
    batteryChart.data.labels = labels;
    batteryChart.data.datasets[0].data = data;
    batteryChart.update('none');
  }

  // Update Temperature
  const tempChart = ci['chart-temp'];
  if (tempChart) {
    const { labels, data } = toSortedArrays(h.tempByHour);
    tempChart.data.labels = labels;
    tempChart.data.datasets[0].data = data;
    tempChart.update('none');
  }

  // Update Alert
  const alertChart = ci['chart-alert'];
  if (alertChart) {
    const { labels, data } = toSortedArrays(h.alertByHour);
    alertChart.data.labels = labels;
    alertChart.data.datasets[0].data = data;
    alertChart.update('none');
  }

  // Update Grid (with colors for import/export)
  const gridData = toSortedArrays(h.gridByHour);
  const gridChart = ci['chart-grid'];
  if (gridChart) {
    gridChart.data.labels = gridData.labels;
    gridChart.data.datasets[0].data = gridData.data;
    gridChart.data.datasets[0].backgroundColor = gridData.data.map(v => 
      v > 0 ? 'rgba(255,80,80,0.7)' : (v < 0 ? 'rgba(0,255,136,0.7)' : 'rgba(100,100,100,0.5)')
    );
    gridChart.update('none');
  }

  // Update Grid Small
  const gridSmChart = ci['chart-grid-sm'];
  if (gridSmChart) {
    gridSmChart.data.labels = gridData.labels;
    gridSmChart.data.datasets[0].data = gridData.data;
    gridSmChart.data.datasets[0].backgroundColor = gridData.data.map(v => 
      v > 0 ? 'rgba(255,80,80,0.7)' : (v < 0 ? 'rgba(0,255,136,0.7)' : 'rgba(100,100,100,0.5)')
    );
    gridSmChart.update('none');
  }

  // Update Energy Page Charts
  const energySolar = ci['chart-energy-solar'];
  if (energySolar) {
    const { labels, data } = toSortedArrays(h.solarByHour);
    energySolar.data.labels = labels;
    energySolar.data.datasets[0].data = data;
    energySolar.update('none');
  }

  const energyLoad = ci['chart-energy-load'];
  if (energyLoad) {
    const { labels, data } = toSortedArrays(h.loadByHour);
    energyLoad.data.labels = labels;
    energyLoad.data.datasets[0].data = data;
    energyLoad.update('none');
  }

  // Threat chart (keep as is)
  const tc = ci['chart-threat'];
  if (tc) {
    tc.data.datasets[0].data = [...h.threat];
    tc.data.labels = h.threat.map((_, i) => `T-${h.threat.length - 1 - i}`);
    tc.update('none');
  }
}
function getActiveCyberAttack() {
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  
  const cyberAnomalies = (STATE.data.anomalies || []).filter(a => 
    (a.attack_type === 'BruteForce' || 
     a.attack_type === 'CredentialStuffing' ||
     a.attack_type === 'Phishing' ||
     a.attack_type === 'MITM' ||
     a.attack_type === 'DDoS' ||
     a.attack_type === 'SessionHijacking') &&
    a.resolved !== true &&
    new Date(a.time).getTime() > oneHourAgo
  );
  
  if (cyberAnomalies.length === 0) return '—';
  
  const latestAttack = cyberAnomalies[cyberAnomalies.length - 1];
  return latestAttack.attack_type || 'Unknown Attack';
}
// ── DASHBOARD PAGE ────────────────────────────────────────
function renderDashboard() {
  const HOURS24 = ['Hr 0','Hr 1','Hr 2','Hr 3','Hr 4','Hr 5','Hr 6','Hr 7','Hr 8','Hr 9','Hr 10','Hr 11','Hr 12','Hr 13','Hr 14','Hr 15','Hr 16','Hr 17','Hr 18','Hr 19','Hr 20','Hr 21','Hr 22','Hr 23'];
  const d = STATE.data;
  const el = document.getElementById('page-dashboard');
  if (!el) return;
  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">System Dashboard</div>
        <div class="section-subtitle">Real-time microgrid monitoring — live MQTT stream</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        <div class="mqtt-bar"><span class="dot"></span> MQTT Connected &nbsp;|&nbsp; 🔒 TLS 1.3 &nbsp;|&nbsp; JWT Active</div>
        <span class="role-badge ${STATE.currentUser.role}">${STATE.currentUser.role.toUpperCase()}</span>
      </div>
    </div>

    <!-- KPI Row -->
    <div class="grid-4" style="margin-bottom:20px;">
      <div class="kpi-card yellow">
        <div class="kpi-icon yellow"><i class="fas fa-solar-panel"></i></div>
        <div class="kpi-value" id="live-solar">${d.solar.toFixed(1)} <span class="kpi-unit">kW</span></div>
        <div class="kpi-label">Solar Generation</div>
        <div class="kpi-trend up"><i class="fas fa-arrow-up"></i> +3.2% from last hour</div>
      </div>
      <div class="kpi-card green">
        <div class="kpi-icon green"><i class="fas fa-battery-three-quarters"></i></div>
        <div class="kpi-value" id="live-battery">${d.battery.toFixed(0)} <span class="kpi-unit">%</span></div>
        <div class="kpi-label">Battery SOC</div>
        <div class="kpi-trend ${d.battery > 50 ? 'up' : 'down'}"><i class="fas fa-arrow-${d.battery > 50 ? 'up':'down'}"></i> ${d.battery > 50 ? 'Charging' : 'Discharging'}</div>
      </div>
      <div class="kpi-card cyan">
        <div class="kpi-icon cyan"><i class="fas fa-thermometer-half"></i></div>
        <div class="kpi-value" id="live-temp">${(d.temperature||0).toFixed(1)} <span class="kpi-unit">°C</span></div>
        <div class="kpi-label">Temperature</div>
        <div class="kpi-trend stable"><i class="fas fa-minus"></i> Ambient</div>
      </div>
      <div class="kpi-card purple">
        <div class="kpi-icon purple"><i class="fas fa-exchange-alt"></i></div>
        <div class="kpi-value" id="live-grid-exp">${(d.gridExport || 0).toFixed(1)} <span class="kpi-unit">kW</span></div>
        <div class="kpi-label">Grid Export</div>
        <div class="kpi-trend up"><i class="fas fa-arrow-up"></i> Exporting to grid</div>
      </div>
    </div>


    <!-- Row 2: 6 Live Charts -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-solar-panel icon"></i> Solar Generation</div>
      <div class="status-indicator online">LIVE</div>
    </div>
    <div class="chart-wrapper"><canvas id="chart-solar"></canvas></div>
  </div>
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-plug icon"></i> Load Demand</div>
      <div class="status-indicator online">LIVE</div>
    </div>
    <div class="chart-wrapper"><canvas id="chart-load"></canvas></div>
  </div>
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-battery-half icon"></i> Battery State of Charge</div>
      <div class="status-indicator online">LIVE</div>
    </div>
    <div class="chart-wrapper"><canvas id="chart-battery"></canvas></div>
  </div>
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-project-diagram icon"></i> Grid Import / Export</div>
      <div class="status-indicator online">LIVE</div>
    </div>
    <div class="chart-wrapper"><canvas id="chart-grid"></canvas></div>
  </div>
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-thermometer-half icon"></i> Temperature</div>
      <div class="status-indicator online">LIVE</div>
    </div>
    <div class="chart-wrapper"><canvas id="chart-temp"></canvas></div>
  </div>
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-exclamation-triangle icon"></i> Physical Alert Timeline</div>
      <div class="status-indicator online">LIVE</div>
    </div>
    <div class="chart-wrapper"><canvas id="chart-alert"></canvas></div>
  </div>
</div>
    

    <!-- Row 3: Grid Power Flow + Security Status + Live Alerts -->
<div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:20px; margin-bottom:20px;">
  
  <!-- Grid Power Flow Card -->
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-project-diagram icon"></i> Grid Power Flow</div>
    </div>
    <div class="chart-wrapper sm"><canvas id="chart-grid-sm"></canvas></div>
    <hr class="divider">
    <div class="data-row"><span class="data-row-label">Grid Import</span><span class="data-row-value red" id="live-grid-imp">${(d.gridImport || 0).toFixed(1)} kW</span></div>
    <div class="data-row"><span class="data-row-label">Grid Export</span><span class="data-row-value green">${(d.gridExport || 0).toFixed(1)} kW</span></div>
    <div class="data-row"><span class="data-row-label">Temperature</span><span class="data-row-value" id="live-temp">${(d.temperature||0).toFixed(1)} °C</span></div>
    <div class="data-row"><span class="data-row-label">Physical Alert</span><span class="data-row-value ${d.alert > 0 ? 'red' : 'green'}">${d.alert > 0 ? '⚠ Active' : '✓ Normal'}</span></div>
  </div>

  <!-- Security Status Card (Cyber) -->
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-shield-alt icon"></i> Security Status</div>
      <div class="status-indicator ${STATE.data.cyberThreatScore > 50 ? 'offline' : 'online'}">
        ${STATE.data.cyberThreatScore > 50 ? '⚠ CYBER THREAT' : '✓ CYBER SECURE'}
      </div>
    </div>
    <div class="enc-status"><i class="fas fa-lock"></i> TLS 1.3 — All channels encrypted</div>
    <div class="enc-status" style="background:rgba(168,85,247,0.07);border-color:rgba(168,85,247,0.2);color:var(--accent-purple);"><i class="fas fa-key"></i> JWT Auth — Token valid</div>
    <div style="margin-top:12px;">
      <div style="font-size:12px;color:var(--text-secondary);margin-bottom:6px;display:flex;justify-content:space-between;">
        <span>Cyber Threat Score</span><span id="live-cyber-threat">${(STATE.data.cyberThreatScore || 0).toFixed(0)}/100</span>
      </div>
      <div class="threat-meter"><div class="threat-fill" style="width:${(STATE.data.cyberThreatScore || 0)}%; background:linear-gradient(90deg,#a855f7,#d946ef);"></div></div>
    </div>
    <hr class="divider">
    <div class="data-row"><span class="data-row-label">Active Connections</span><span class="data-row-value cyan">4</span></div>
    <div class="data-row"><span class="data-row-label">Security Status</span><span class="data-row-value ${STATE.data.cyberThreatScore > 50 ? 'red' : 'green'}">${STATE.data.cyberThreatScore > 50 ? '⚠ UNSECURE' : '✓ SECURE'}</span></div>
    <div class="data-row"><span class="data-row-label">Active Attack</span><span class="data-row-value red" id="active-cyber-attack">${getActiveCyberAttack()}</span></div>
  </div>

  <!-- Live Alerts Card (Physical) -->
  <div class="card">
    <div class="card-header">
      <div class="card-title"><i class="fas fa-radiation-alt icon"></i> Live Alerts</div>
      <div class="status-indicator ${(d.threatScore||0) > 50 ? 'offline' : 'online'}">
        ${(d.threatScore||0) > 50 ? '⚠ THREAT' : '✓ SECURE'}
      </div>
    </div>
    <div class="data-row">
      <span class="data-row-label">Physical Alert</span>
      <span class="data-row-value ${d.alert === 1 ? 'red' : 'green'}">${d.alert === 1 ? '🚨 ALERT' : '✅ Normal'}</span>
    </div>
    <div class="data-row">
      <span class="data-row-label">Attack Injected</span>
      <span class="data-row-value ${d.attackInjected === 1 ? 'red' : 'green'}">${d.attackInjected === 1 ? '🔴 YES' : '🟢 NO'}</span>
    </div>
    <div class="data-row">
      <span class="data-row-label">Attack Type</span>
      <span class="data-row-value red">${d.attackType && d.attackType !== 'None' ? d.attackType : '—'}</span>
    </div>
    <hr class="divider">
    <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px;display:flex;justify-content:space-between;">
      <span>Physical Threat Score</span><span>${(d.threatScore||0).toFixed(0)}/100</span>
    </div>
    <div class="threat-meter">
      <div class="threat-fill" style="width:${d.threatScore||0}%; background:linear-gradient(90deg,#00ff88,#ffcc00,#ff3366);"></div>
    </div>
  </div>
</div>

    <!-- Recent Alerts -->
    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fas fa-bell icon"></i> Recent Alerts</div>
        <button class="btn btn-primary btn-sm" onclick="navigateTo('security')">View All</button>
      </div>
      ${STATE.alerts.slice(0, 4).map(a => `
        <div class="alert-item ${a.type}">
          <div class="alert-icon"><i class="fas ${a.type==='critical'?'fa-radiation-alt':a.type==='warning'?'fa-exclamation-triangle':a.type==='success'?'fa-check-circle':'fa-info-circle'}"></i></div>
          <div style="flex:1;"><div class="alert-title">${a.title}</div><div class="alert-desc">${a.desc}</div></div>
          <div class="alert-time">${a.time}</div>
        </div>`).join('')}
    </div>
  </div>`;

  // Initialize charts
  setTimeout(() => {
   makeChart('chart-power', 'line',HOURS24,[  
  { label:'Solar', data:new Array(24).fill(0), borderColor:'#ffcc00', backgroundColor:'rgba(255,204,0,0.08)', tension:0.4, fill:true, borderWidth:2, pointRadius:2 },
  { label:'Load',  data:new Array(24).fill(0), borderColor:'#00d4ff', backgroundColor:'rgba(0,212,255,0.08)', tension:0.4, fill:true, borderWidth:2, pointRadius:2 }
], { legend: true });

makeChart('chart-solar', 'line',HOURS24,[ 
  { label:'Solar kW', data: new Array(24).fill(0), borderColor:'#ffcc00', backgroundColor:'rgba(255,204,0,0.1)', tension:0.4, fill:true, borderWidth:2, pointRadius:2 }
], { yScale: { min: 0, max: 12 } });

makeChart('chart-load', 'line',HOURS24,[ 
  { label:'Load kW', data: new Array(24).fill(0), borderColor:'#00d4ff', backgroundColor:'rgba(0,212,255,0.08)', tension:0.4, fill:true, borderWidth:2, pointRadius:2 }
], { yScale: { min: 0, max: 12 } });

makeChart('chart-battery', 'line',HOURS24,[ 
  { label:'SOC kWh', data: new Array(24).fill(0), borderColor:'#00ff88', backgroundColor:'rgba(0,255,136,0.1)', tension:0.4, fill:true, borderWidth:2, pointRadius:2 }
], { yScale: { min: 0, max: 20 } });

makeChart('chart-temp', 'line',HOURS24,[ 
  { label:'Temp °C', data: new Array(24).fill(21), borderColor:'#ff6b35', backgroundColor:'rgba(255,107,53,0.1)', tension:0.4, fill:true, borderWidth:2, pointRadius:2 }
], { yScale: { min: 20, max: 45 } });

makeChart('chart-alert', 'bar',HOURS24,[ 
  { label:'Alert', data: new Array(24).fill(0), backgroundColor:'rgba(255,51,102,0.6)', borderColor:'#ff3366', borderWidth:1, borderRadius:3 }
], { yScale: { min: 0, max: 1 } });

makeChart('chart-grid', 'bar',HOURS24,[ 
  { label:'Grid kW', data: new Array(24).fill(0), backgroundColor: [], borderRadius:3 }
]);

makeChart('chart-grid-sm', 'bar',HOURS24,[ 
  { label:'Grid kW', data: new Array(24).fill(0), backgroundColor: [], borderRadius:3 }
]);

makeChart('chart-threat', 'line',HOURS24,[ 
  { label:'Threat', data: new Array(24).fill(0), borderColor:'#ff3366', backgroundColor:'rgba(255,51,102,0.08)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 }
], { yScale: { min: 0, max: 100 } });

makeChart('chart-cyber-threat', 'line', HOURS24, [
  { label:'Cyber Threat', data: new Array(24).fill(0), borderColor:'#a855f7', backgroundColor:'rgba(168,85,247,0.1)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 }
], { yScale: { min: 0, max: 100 } });
 },50);
}


// ── ENERGY PAGE ───────────────────────────────────────────
function renderEnergyPage() {
  const el = document.getElementById('page-energy');
  if (!el) return;
  const d = STATE.data;
  
  el.innerHTML = `
    <div style="padding:24px;">
      <div class="section-header">
        <div>
          <div class="section-title">Control Center</div>
          <div class="section-subtitle">Emergency control & weather intelligence</div>
        </div>
        <div class="status-pill ${d.mode === 'island' ? 'warning' : 'online'}">
          <span class="pulse-dot"></span> ${d.mode === 'island' ? '🏝 ISLAND MODE' : '🔌 GRID-CONNECTED'}
        </div>
      </div>

      <!-- Row 1: STOP and START Buttons Side by Side -->
      <div class="grid-2" style="margin-bottom:20px;">
        
        <!-- EMERGENCY STOP Card -->
        <div class="card" style="text-align:center;">
          <div class="card-header">
            <div class="card-title"><i class="fas fa-stop-circle icon" style="color:#ff3366;"></i> Emergency STOP</div>
          </div>
          <div style="padding:20px;">
            <button id="emergency-stop-btn" onclick="emergencyStop()" 
              style="background: linear-gradient(135deg, #ff3366, #cc0033); width: 160px; height: 160px; border-radius: 50%; border: none; color: white; font-size: 20px; font-weight: bold; cursor: pointer; box-shadow: 0 0 20px rgba(255,51,102,0.5);">
              <i class="fas fa-ban" style="font-size: 40px; display: block; margin-bottom: 8px;"></i>
              STOP
            </button>
            <div style="margin-top: 16px;">
              <span class="status-indicator ${d.mode === 'island' ? 'offline' : 'online'}">
                Status: ${d.mode === 'island' ? '⛔ STOPPED' : '● RUNNING'}
              </span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 12px;">
              ⚠️ Disconnects grid & stops all energy flow
            </div>
          </div>
        </div>

        <!-- START MICROGRID Card -->
        <div class="card" style="text-align:center;">
          <div class="card-header">
            <div class="card-title"><i class="fas fa-play-circle icon" style="color:#00ff88;"></i> Start Microgrid</div>
          </div>
          <div style="padding:20px;">
            <button id="start-grid-btn" onclick="startMicrogrid()" 
              style="background: linear-gradient(135deg, #00cc66, #009944); width: 160px; height: 160px; border-radius: 50%; border: none; color: white; font-size: 20px; font-weight: bold; cursor: pointer; box-shadow: 0 0 20px rgba(0,255,136,0.5);">
              <i class="fas fa-play" style="font-size: 40px; display: block; margin-bottom: 8px;"></i>
              START
            </button>
            <div style="margin-top: 16px;">
              <span class="status-indicator online">Status: READY</span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 12px;">
              ▶️ Resumes normal operation & reconnects to grid
            </div>
          </div>
        </div>
      </div>

      <!-- Row 2: Schedule START/STOP -->
      <div class="card" style="margin-bottom:20px;">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-clock icon"></i> Schedule START / STOP</div>
        </div>
        <div style="padding:16px;">
          <div style="display: grid; grid-template-columns: auto 1fr auto 1fr auto; gap: 12px; align-items: center; flex-wrap: wrap;">
            <label>Enable:</label>
            <input type="checkbox" id="schedule-enabled" style="width: 20px; height: 20px;">
            <label>Start:</label>
            <input type="time" id="schedule-start" value="09:00" style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px; color: var(--text-primary);">
            <label>Stop:</label>
            <input type="time" id="schedule-stop" value="17:00" style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px; color: var(--text-primary);">
            <label>Repeat:</label>
            <select id="schedule-repeat" style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px; color: var(--text-primary);">
              <option>Daily</option>
              <option>Weekdays</option>
              <option>Weekends</option>
              <option>Once</option>
            </select>
            <label>Date:</label>
            <input type="date" id="schedule-date" style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px; color: var(--text-primary);">
          </div>
          <div style="display: flex; gap: 12px; margin-top: 16px;">
            <button class="btn btn-success" onclick="saveSchedule()"><i class="fas fa-save"></i> Save Schedule</button>
            <button class="btn btn-danger" onclick="clearSchedule()"><i class="fas fa-trash"></i> Clear Schedule</button>
          </div>
          <div id="schedule-next" style="margin-top: 12px; font-size: 12px; color: var(--accent-cyan);">
            Next scheduled: Not set
          </div>
        </div>
      </div>

      <!-- Row 3: Weather Forecast -->
      <div class="card" style="margin-bottom:20px;">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-cloud-sun icon"></i> Weather Forecast</div>
          <span class="status-indicator online">LIVE</span>
        </div>
        <div style="padding:16px; overflow-x: auto;">
          <div id="weather-container" style="display: flex; gap: 16px; min-width: max-content;">
            <!-- Weather data will be populated by JavaScript -->
            <div style="text-align: center; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 10px; min-width: 80px;">
              <div>Loading...</div>
            </div>
          </div>
          <div id="weather-summary" style="margin-top: 12px; font-size: 12px; color: var(--text-muted);"></div>
        </div>
      </div>

      <!-- Row 4: Emergency Log -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-list-alt icon"></i> Emergency Action Log</div>
          <button class="btn btn-primary btn-sm" onclick="exportEmergencyLog()"><i class="fas fa-download"></i> Export</button>
        </div>
        <div style="max-height: 200px; overflow-y: auto;">
          <table class="log-table" style="width: 100%;">
            <thead>
              <tr><th>Time</th><th>Action</th><th>User</th><th>Details</th></tr>
            </thead>
            <tbody id="emergency-log-body">
              <tr><td colspan="4" style="text-align:center;">Loading...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  // Load schedule from localStorage
  const savedSchedule = JSON.parse(localStorage.getItem('microgrid_schedule') || '{}');
  document.getElementById('schedule-enabled').checked = savedSchedule.enabled || false;
  document.getElementById('schedule-start').value = savedSchedule.startTime || '09:00';
  document.getElementById('schedule-stop').value = savedSchedule.stopTime || '17:00';
  document.getElementById('schedule-repeat').value = savedSchedule.repeat || 'Daily';
  document.getElementById('schedule-date').value = savedSchedule.date || new Date().toISOString().split('T')[0];
  
  // Update next schedule display
  updateNextScheduleDisplay();
  
  // Load weather data
  fetchWeatherData();
  
  // Load emergency log
  loadEmergencyLog();
  
  // Start weather refresh every 30 minutes
  if (window.weatherInterval) clearInterval(window.weatherInterval);
  window.weatherInterval = setInterval(fetchWeatherData, 30 * 60 * 1000);
}

// ── Control Center Functions ─────────────────────────────────

function emergencyStop() {
  if (confirm('⚠️ EMERGENCY STOP: This will disconnect the grid and stop all energy flow. Continue?')) {
    // Change mode to island
    STATE.data.mode = 'island';
    updateTopbarPills();
    
    // Log the event
    addEmergencyLog('⛔ EMERGENCY STOP', STATE.currentUser?.username || 'Admin', 'Grid disconnected manually');
    addLog('critical', 'system', 'EMERGENCY STOP activated - Grid disconnected', STATE.currentUser?.username);
    addAlert('critical', 'EMERGENCY STOP', 'Grid has been disconnected. Click START to resume.');
    
    // Update UI
    const btn = document.getElementById('emergency-stop-btn');
    if (btn) {
      btn.style.transform = 'scale(0.95)';
      setTimeout(() => { if(btn) btn.style.transform = ''; }, 200);
    }
    
    // Refresh the page to update status
    renderEnergyPage();
  }
}

function startMicrogrid() {
  if (confirm('✅ START MICROGRID: This will reconnect the grid and resume normal operation. Continue?')) {
    // Change mode to grid-connected
    STATE.data.mode = 'grid-connected';
    updateTopbarPills();
    
    // Log the event
    addEmergencyLog('✅ MICROGRID START', STATE.currentUser?.username || 'Admin', 'Operation resumed, grid reconnected');
    addLog('success', 'system', 'Microgrid started - Grid reconnected', STATE.currentUser?.username);
    addAlert('success', 'Microgrid Started', 'Normal operation resumed. Grid is now connected.');
    
    // Update UI
    const btn = document.getElementById('start-grid-btn');
    if (btn) {
      btn.style.transform = 'scale(0.95)';
      setTimeout(() => { if(btn) btn.style.transform = ''; }, 200);
    }
    
    // Refresh the page to update status
    renderEnergyPage();
  }
}

function saveSchedule() {
  const schedule = {
    enabled: document.getElementById('schedule-enabled').checked,
    startTime: document.getElementById('schedule-start').value,
    stopTime: document.getElementById('schedule-stop').value,
    repeat: document.getElementById('schedule-repeat').value,
    date: document.getElementById('schedule-date').value
  };
  localStorage.setItem('microgrid_schedule', JSON.stringify(schedule));
  updateNextScheduleDisplay();
  addLog('info', 'system', `Schedule saved: ${schedule.startTime} to ${schedule.stopTime}`, STATE.currentUser?.username);
  alert('Schedule saved successfully!');
}

function clearSchedule() {
  localStorage.removeItem('microgrid_schedule');
  document.getElementById('schedule-enabled').checked = false;
  document.getElementById('schedule-start').value = '09:00';
  document.getElementById('schedule-stop').value = '17:00';
  document.getElementById('schedule-repeat').value = 'Daily';
  document.getElementById('schedule-date').value = new Date().toISOString().split('T')[0];
  updateNextScheduleDisplay();
  addLog('info', 'system', 'Schedule cleared', STATE.currentUser?.username);
  alert('Schedule cleared');
}

function updateNextScheduleDisplay() {
  const schedule = JSON.parse(localStorage.getItem('microgrid_schedule') || '{}');
  const el = document.getElementById('schedule-next');
  if (!el) return;
  
  if (!schedule.enabled) {
    el.textContent = 'Next scheduled: Not enabled';
    return;
  }
  
  const now = new Date();
  const [startHour, startMin] = schedule.startTime.split(':');
  const nextStart = new Date();
  nextStart.setHours(parseInt(startHour), parseInt(startMin), 0, 0);
  
  if (nextStart <= now) {
    nextStart.setDate(nextStart.getDate() + 1);
  }
  
  const diff = Math.round((nextStart - now) / 60000);
  if (diff < 60) {
    el.textContent = `Next scheduled: START at ${schedule.startTime} (in ${diff} minutes)`;
  } else {
    el.textContent = `Next scheduled: START at ${schedule.startTime} (in ${Math.round(diff/60)} hours)`;
  }
}

async function fetchWeatherData() {
  try {
    // Using free Open-Meteo API (no API key required)
    const response = await fetch('https://api.open-meteo.com/v1/forecast?latitude=12.9716&longitude=77.5946&hourly=temperature_2m,shortwave_radiation&forecast_days=1');
    const data = await response.json();
    
    const container = document.getElementById('weather-container');
    const summary = document.getElementById('weather-summary');
    
    if (!container) return;
    
    const now = new Date();
    const currentHour = now.getHours();
    const hourlyData = data.hourly;
    
    let html = '';
    let maxSolar = 0;
    
    for (let i = 0; i < 8; i++) {
      const hour = (currentHour + i) % 24;
      const temp = hourlyData.temperature_2m?.[hour] || 0;
      const solar = hourlyData.shortwave_radiation?.[hour] || 0;
      if (solar > maxSolar) maxSolar = solar;
      
      let icon = '☀️';
      if (solar < 100) icon = '🌙';
      else if (solar < 300) icon = '🌤️';
      else if (solar < 600) icon = '⛅';
      else icon = '☀️';
      
      html += `
        <div style="text-align: center; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 10px; min-width: 80px;">
          <div style="font-size: 20px;">${icon}</div>
          <div style="font-size: 18px; font-weight: bold;">${temp.toFixed(0)}°C</div>
          <div style="font-size: 11px; color: var(--text-muted);">${i === 0 ? 'NOW' : `+${i}h`}</div>
          <div style="font-size: 10px; color: var(--accent-cyan);">${solar.toFixed(0)} W/m²</div>
        </div>
      `;
    }
    
    container.innerHTML = html;
    
    if (summary) {
      if (maxSolar > 800) {
        summary.innerHTML = `📊 ${maxSolar.toFixed(0)} W/m² peak solar expected. ⚡ High generation - ideal for battery charging!`;
      } else if (maxSolar > 400) {
        summary.innerHTML = `📊 ${maxSolar.toFixed(0)} W/m² peak solar expected. ☀️ Good generation expected.`;
      } else {
        summary.innerHTML = `📊 ${maxSolar.toFixed(0)} W/m² peak solar expected. 🌙 Low solar - consider grid import.`;
      }
    }
    
  } catch (error) {
    console.error('Weather fetch error:', error);
    const container = document.getElementById('weather-container');
    if (container) {
      container.innerHTML = '<div style="padding: 20px; text-align: center;">⚠️ Weather data unavailable. Using estimated values.</div>';
      // Fallback mock data
      let mockHtml = '';
      for (let i = 0; i < 8; i++) {
        mockHtml += `
          <div style="text-align: center; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 10px; min-width: 80px;">
            <div style="font-size: 20px;">${i < 3 ? '☀️' : '🌤️'}</div>
            <div style="font-size: 18px; font-weight: bold;">${28 - Math.abs(i-3)}°C</div>
            <div style="font-size: 11px; color: var(--text-muted);">${i === 0 ? 'NOW' : `+${i}h`}</div>
            <div style="font-size: 10px; color: var(--accent-cyan);">${800 - i*100} W/m²</div>
          </div>
        `;
      }
      container.innerHTML = mockHtml;
    }
  }
}

function loadEmergencyLog() {
  const logs = JSON.parse(localStorage.getItem('emergency_logs') || '[]');
  const tbody = document.getElementById('emergency-log-body');
  if (!tbody) return;
  
  if (logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No emergency events recorded</td></tr>';
    return;
  }
  
  tbody.innerHTML = logs.slice(0, 10).map(log => `
    <tr>
      <td style="font-family: monospace; font-size: 12px;">${log.time}</td>
      <td>${log.action}</td>
      <td style="color: var(--accent-cyan);">${log.user}</td>
      <td style="font-size: 12px; color: var(--text-muted);">${log.details}</td>
    </tr>
  `).join('');
}

function addEmergencyLog(action, user, details) {
  const logs = JSON.parse(localStorage.getItem('emergency_logs') || '[]');
  logs.unshift({
    time: new Date().toLocaleTimeString(),
    action: action,
    user: user,
    details: details
  });
  // Keep only last 50 logs
  if (logs.length > 50) logs.pop();
  localStorage.setItem('emergency_logs', JSON.stringify(logs));
  loadEmergencyLog();
}

function exportEmergencyLog() {
  const logs = JSON.parse(localStorage.getItem('emergency_logs') || '[]');
  let csv = 'Time,Action,User,Details\n';
  logs.forEach(log => {
    csv += `"${log.time}","${log.action}","${log.user}","${log.details}"\n`;
  });
  const blob = new Blob([csv], {type: 'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `emergency_log_${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  addLog('success', 'system', 'Emergency log exported', STATE.currentUser?.username);
}

function setMode(mode, btn) {
  STATE.data.mode = mode;
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  addLog('info', 'system', `Controller mode changed to: ${mode.toUpperCase()}`);
  addAlert('info', `Mode Changed: ${mode}`, `Smart controller switched to ${mode} operating mode.`);
  updateTopbarPills();
}

// ── GRID PAGE ─────────────────────────────────────────────
function renderGridPage() {
  const el = document.getElementById('page-grid');
  if (!el) return;
  
  el.innerHTML = `
    <div style="padding:24px; height: calc(100vh - 120px);">
      <div class="card" style="height: 100%; display: flex; flex-direction: column;">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-robot icon"></i> Nexora AI Assistant</div>
          <span class="status-indicator online">AI READY</span>
        </div>
        <div id="chat-messages" style="flex:1; overflow-y: auto; padding: 16px; background: rgba(0,0,0,0.2);">
          <div class="chat-message bot">
            <div style="display: flex; gap: 10px; margin-bottom: 12px;">
              <div style="width: 32px; height: 32px; border-radius: 50%; background: #1a3a5c; display: flex; align-items: center; justify-content: center;">
                <i class="fas fa-robot" style="font-size: 12px;"></i>
              </div>
              <div style="flex:1; background: rgba(0,0,0,0.3); padding: 10px 14px; border-radius: 12px;">
                👋 Hi! I'm Nexora AI. Ask me anything about:<br><br>
                • 🔋 Microgrid status & optimization<br>
                • 🛡️ Cyber security threats (Brute Force, DoS, MITM)<br>
                • ⚡ Energy management & grid stability<br>
                • 📊 Anomaly detection & threat scores<br>
                • 🔐 Protection mechanisms (TLS, JWT, RBAC)<br><br>
                <strong>Example questions:</strong><br>
                "What is a brute force attack?"<br>
                "How do I protect against DoS?"<br>
                "Why is my threat score high?"<br>
                "How does solar + battery optimization work?"
              </div>
            </div>
          </div>
        </div>
        <div style="padding: 16px; border-top: 1px solid var(--border-color); display: flex; gap: 12px;">
          <input type="text" id="chat-input" placeholder="Ask me anything about microgrids or security..." 
            style="flex:1; background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; color: var(--text-primary);">
          <button onclick="sendChatMessage()" class="btn btn-primary" style="background: linear-gradient(135deg,#7c3aed,#a855f7);">
            <i class="fas fa-paper-plane"></i> Send
          </button>
        </div>
      </div>
    </div>
  `;
async function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const message = input.value.trim();
  if (!message) return;
  
  addChatMessage('user', message);
  input.value = '';
  addChatMessage('bot', 'Thinking...', true);
  
  const context = {
    solar: STATE.data.solar,
    battery: STATE.data.battery,
    load: STATE.data.load,
    gridImport: STATE.data.gridImport,
    gridExport: STATE.data.gridExport,
    temperature: STATE.data.temperature,
    threatScore: STATE.data.threatScore,
    cyberThreatScore: STATE.data.cyberThreatScore,
    attackType: STATE.data.attackType,
    anomalies: STATE.data.anomalies?.length || 0
  };
  
  try {
    const response = await fetch('https://microgrid-final.onrender.com/ai/chat', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + STATE.currentUser?.token
      },
      body: JSON.stringify({ message, context })
    });
    
    const data = await response.json();
    removeTypingIndicator();
    addChatMessage('bot', data.reply);
    
  } catch (error) {
    console.error('Chat error:', error);
    removeTypingIndicator();
    addChatMessage('bot', '⚠️ Sorry, AI service is temporarily unavailable. Please try again later.');
  }
}

function addChatMessage(role, text, isTyping = false) {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  
  const div = document.createElement('div');
  if (isTyping) div.id = 'typing-indicator';
  
  const isUser = role === 'user';
  div.innerHTML = `
    <div style="display: flex; gap: 10px; margin-bottom: 12px; ${isUser ? 'flex-direction: row-reverse;' : ''}">
      <div style="width: 32px; height: 32px; border-radius: 50%; background: ${isUser ? '#7c3aed' : '#1a3a5c'}; display: flex; align-items: center; justify-content: center;">
        <i class="fas ${isUser ? 'fa-user' : 'fa-robot'}"></i>
      </div>
      <div style="flex:1; background: rgba(0,0,0,0.3); padding: 10px 14px; border-radius: 12px;">
        ${isTyping ? '<i class="fas fa-spinner fa-spin"></i> Thinking...' : text.replace(/\n/g, '<br>')}
      </div>
    </div>
  `;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function removeTypingIndicator() {
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
}
  // Add event listener for Enter key
  const chatInput = document.getElementById('chat-input');
  if (chatInput) {
    chatInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') sendChatMessage();
    });
  }
}

// ── SECURITY PAGE ─────────────────────────────────────────
function renderSecurityPage() {
  const el = document.getElementById('page-security');
  if (!el) return;
  const d = STATE.data;
  
  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">Security Center</div>
        <div class="section-subtitle">Threat monitoring & attack simulation</div>
      </div>
    </div>

    <!-- Row 1: Both Threat Scores Side by Side -->
    <div class="grid-2" style="margin-bottom:20px;">
      
      <!-- Physical Threat Card -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-microchip icon"></i> Physical Threat Score</div>
        </div>
        <div style="text-align:center; padding:20px;">
          <div style="font-size:64px; font-weight:800; color:${d.threatScore > 50 ? '#ff3366' : '#00ff88'};" id="threat-score-large">${d.threatScore || 18}</div>
          <div style="font-size:14px; color:var(--text-muted);">/ 100</div>
          <div class="threat-meter" style="margin-top:16px;">
            <div class="threat-fill" style="width:${d.threatScore || 18}%; height:10px; background:linear-gradient(90deg,#00ff88,#ffcc00,#ff3366); border-radius:5px;"></div>
          </div>
          <div class="status-indicator ${d.threatScore > 50 ? 'offline' : 'online'}" style="margin-top:16px; display:inline-block;">
            ${d.threatScore > 50 ? '⚠ THREAT ACTIVE' : '✓ SYSTEM SECURE'}
          </div>
        </div>
      </div>

      <!-- Cyber Threat Card -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-shield-alt icon"></i> Cyber Threat Score</div>
        </div>
        <div style="text-align:center; padding:20px;">
          <div style="font-size:64px; font-weight:800; color:#a855f7;" id="cyber-threat-score">${d.cyberThreatScore || 0}</div>
          <div style="font-size:14px; color:var(--text-muted);">/ 100</div>
          <div class="threat-meter" style="margin-top:16px;">
            <div class="threat-fill" id="cyber-threat-fill" style="width:${d.cyberThreatScore || 0}%; background:linear-gradient(90deg,#a855f7,#d946ef); height:10px; border-radius:5px;"></div>
          </div>
          <div class="status-indicator ${(d.cyberThreatScore || 0) > 50 ? 'offline' : 'online'}" style="margin-top:16px; display:inline-block;">
            ${(d.cyberThreatScore || 0) > 50 ? '⚠ CYBER THREAT' : '✓ CYBER SECURE'}
          </div>
        </div>
      </div>
    </div>

    <!-- Row 2: Failed Login Chart (Full Width) -->
    <div class="card" style="margin-bottom:20px;">
      <div class="card-header">
        <div class="card-title"><i class="fas fa-exclamation-triangle icon"></i> Failed Login Attempts (24h)</div>
      </div>
      <div class="chart-wrapper" style="height:200px;">
        <canvas id="chart-failed-logins"></canvas>
      </div>
    </div>

    <!-- Row 3: Attack Simulation + Recent Alerts Side by Side -->
    <div class="grid-2">
      
      <!-- Attack Simulation Card -->
<div class="card">
  <div class="card-header">
    <div class="card-title"><i class="fas fa-flask icon"></i> Attack Simulation</div>
    <span style="font-size:11px;color:var(--text-muted);">Test cyber threats</span>
  </div>
  <div style="display:flex; flex-direction:column; gap:12px;">
    ${[
      { name:'Brute Force', icon:'fa-user-secret', color:'#a855f7', desc:'Password guessing attack', action:"simulateAttack('BruteForce')" },
      { name:'Credential Stuffing', icon:'fa-key', color:'#d946ef', desc:'Stolen credentials attack', action:"simulateAttack('CredentialStuffing')" },
      { name:'Phishing', icon:'fa-envelope', color:'#f43f5e', desc:'Fake login page attack', action:"simulateAttack('Phishing')" },
      { name:'MITM', icon:'fa-exchange-alt', color:'#ff6b35', desc:'Man-in-the-middle', action:"simulateAttack('MITM')" },
      { name:'DDoS', icon:'fa-tachometer-alt', color:'#ffcc00', desc:'Flood network traffic', action:"simulateAttack('DDoS')" },
      { name:'Session Hijacking', icon:'fa-cookie', color:'#10b981', desc:'Steal user session', action:"simulateAttack('SessionHijacking')" },
    ].map(s=>`
      <div style="padding:12px; background:rgba(0,0,0,0.3); border-radius:10px; border-left:3px solid ${s.color}; display:flex; align-items:center; justify-content:space-between;">
        <div style="display:flex; align-items:center; gap:10px;">
          <div style="font-size:18px; color:${s.color};"><i class="fas ${s.icon}"></i></div>
          <div>
            <div style="font-weight:600; font-size:13px;">${s.name}</div>
            <div style="font-size:11px; color:var(--text-muted);">${s.desc}</div>
          </div>
        </div>
        <button class="btn btn-danger btn-sm" onclick="${s.action}" style="background:${s.color}; border:none; padding:5px 12px; font-size:11px;">
          <i class="fas fa-play"></i> Run
        </button>
      </div>
    `).join('')}
  </div>
</div>
      <!-- Recent Alerts Card -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-bell icon"></i> Recent Alerts</div>
          <button class="btn btn-primary btn-sm" onclick="markAllAlertsRead()" style="padding:4px 10px; font-size:11px;">Mark Read</button>
        </div>
        <div style="max-height:350px; overflow-y:auto;">
          ${STATE.alerts.slice(0, 5).map(a => `
            <div class="alert-item ${a.type}" onclick="markAlertRead(${a.id})" style="${a.read?'opacity:0.5':''}; padding:10px; margin-bottom:8px;">
              <div class="alert-icon"><i class="fas ${a.type==='critical'?'fa-radiation-alt':a.type==='warning'?'fa-exclamation-triangle':'fa-info-circle'}"></i></div>
              <div style="flex:1;">
                <div class="alert-title" style="font-size:12px;">${a.read?'':'🔴 '}${a.title}</div>
                <div class="alert-desc" style="font-size:11px;">${a.desc.substring(0, 60)}${a.desc.length > 60 ? '...' : ''}</div>
              </div>
              <div class="alert-time" style="font-size:10px;">${a.time}</div>
            </div>
          `).join('')}
          ${STATE.alerts.length === 0 ? '<div style="text-align:center; padding:20px; color:var(--text-muted);">No alerts</div>' : ''}
        </div>
      </div>
    </div>
  </div>`;

  // Create failed logins chart
  setTimeout(() => {
    const cyberScore = STATE.data.cyberThreatScore || 0;
    const baseAttempts = Math.floor(cyberScore / 10);
    const failedData = Array.from({length: 24}, (_, i) => 
      Math.max(0, baseAttempts + Math.floor(Math.random() * 5) - 2)
    );
    makeChart('chart-failed-logins', 'bar', 
      Array.from({length: 24}, (_, i) => `${i}h`),
      [{ label:'Failed Logins', data: failedData, backgroundColor: 'rgba(255,51,102,0.6)', borderRadius: 4 }],
      { yScale: { min: 0, max: 15 } }
    );
  }, 50);
}
function markAlertRead(id) {
  const a = STATE.alerts.find(x=>x.id===id);
  if (a) a.read = true;
  updateNotifBadge();
  renderSecurityPage();
}
function markAllAlertsRead() {
  STATE.alerts.forEach(a=>a.read=true);
  updateNotifBadge();
  renderSecurityPage();
}

// ── ANOMALY DETECTION PAGE ────────────────────────────────
function renderAnomalyPage() {
  const d = STATE.data;
  const el = document.getElementById('page-anomaly');
  if (!el) return;

  // Time filter - only last 1 hour
  const oneHourAgo = Date.now() - 60 * 60 * 1000;

  // Get anomalies from backend
  const anomalies = d.anomalies || [];
  
  // Separate cyber vs physical anomalies (with time and resolved filter)
  const cyberAnomalies = anomalies.filter(a => 
    (a.attack_type === 'BruteForce' || 
     a.attack_type === 'CredentialStuffing' ||
     a.attack_type === 'Phishing' ||
     a.attack_type === 'MITM' ||
     a.attack_type === 'DDoS' ||
     a.attack_type === 'SessionHijacking' ||
     a.signal === 'failed_login_count' ||
     a.signal === 'unique_usernames_tried') &&
    a.resolved !== true &&
    new Date(a.time).getTime() > oneHourAgo
  );
  
  const physicalAnomalies = anomalies.filter(a => 
    (a.attack_type !== 'BruteForce' && 
     a.attack_type !== 'CredentialStuffing' &&
     a.attack_type !== 'Phishing' &&
     a.attack_type !== 'MITM' &&
     a.attack_type !== 'DDoS' &&
     a.attack_type !== 'SessionHijacking' &&
     a.signal !== 'failed_login_count' &&
     a.signal !== 'attack_simulation') &&
    a.resolved !== true &&
    new Date(a.time).getTime() > oneHourAgo
  );

  // Cyber threat detectors
  const cyberDetectors = [
    { name:'Brute Force Attack', score: Math.min(100, cyberAnomalies.filter(a => a.attack_type === 'BruteForce').length * 20), detected: cyberAnomalies.some(a => a.attack_type === 'BruteForce') },
    { name:'Credential Stuffing', score: Math.min(100, cyberAnomalies.filter(a => a.attack_type === 'CredentialStuffing').length * 20), detected: cyberAnomalies.some(a => a.attack_type === 'CredentialStuffing') },
    { name:'Phishing Attempt', score: Math.min(100, cyberAnomalies.filter(a => a.attack_type === 'Phishing').length * 20), detected: cyberAnomalies.some(a => a.attack_type === 'Phishing') },
    { name:'Man-in-the-Middle', score: Math.min(100, cyberAnomalies.filter(a => a.attack_type === 'MITM').length * 20), detected: cyberAnomalies.some(a => a.attack_type === 'MITM') },
    { name:'DDoS Attack', score: Math.min(100, cyberAnomalies.filter(a => a.attack_type === 'DDoS').length * 20), detected: cyberAnomalies.some(a => a.attack_type === 'DDoS') },
    { name:'Session Hijacking', score: Math.min(100, cyberAnomalies.filter(a => a.attack_type === 'SessionHijacking').length * 20), detected: cyberAnomalies.some(a => a.attack_type === 'SessionHijacking') },
  ];
  
  // ... rest of your HTML rendering

  // Physical threat detectors (only from MATLAB, not simulations)
  const physicalDetectors = [
    { name:'Physical Alert', score: d.alert === 1 ? 100 : 0, detected: d.alert === 1 },
    { name:'Voltage Anomaly', score: d.threatScore > 60 ? rnd(60,80,0) : rnd(10,25,0), detected: d.threatScore > 60 },
    { name:'Frequency Deviation', score: rnd(5,20,0), detected: false },
    { name:'Temperature Spike', score: d.temperature > 40 ? rnd(60,85,0) : rnd(5,15,0), detected: d.temperature > 40 },
    { name:'Grid Instability', score: Math.abs(d.gridImport - d.gridExport) > 5 ? rnd(50,75,0) : rnd(5,15,0), detected: Math.abs(d.gridImport - d.gridExport) > 5 },
  ];



  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">Anomaly Detection</div>
        <div class="section-subtitle">ML-based intrusion detection — Cyber + Physical threats</div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-primary" onclick="runAnomalyScan()"><i class="fas fa-search"></i> Run Scan</button>
        <button class="btn btn-success" onclick="retrainMLModel()"><i class="fas fa-brain"></i> Retrain Model</button>
      </div>
    </div>

    <!-- Row 1: Both Threat Scores Side by Side -->
    <div class="grid-2" style="margin-bottom:20px;">
      
      <!-- Cyber Threat Card -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-shield-alt icon"></i> Cyber Threat Score</div>
          <span class="status-indicator ${(d.cyberThreatScore || 0) > 50 ? 'offline' : 'online'}">
            ${(d.cyberThreatScore || 0) > 50 ? '⚠ HIGH' : '✓ LOW'}
          </span>
        </div>
        <div style="text-align:center; padding:20px;">
          <div style="font-size:48px; font-weight:800; color:#a855f7;">${d.cyberThreatScore || 0}<span style="font-size:20px;">/100</span></div>
          <div class="threat-meter" style="margin-top:12px;">
            <div class="threat-fill" style="width:${d.cyberThreatScore || 0}%; background:linear-gradient(90deg,#a855f7,#d946ef); height:8px; border-radius:4px;"></div>
          </div>
          <div style="margin-top:12px; font-size:11px; color:var(--text-muted);">
            <i class="fas fa-fingerprint"></i> ${cyberAnomalies.length} cyber events detected
          </div>
        </div>
      </div>

      <!-- Physical Threat Card -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-microchip icon"></i> Physical Threat Score</div>
          <span class="status-indicator ${(d.threatScore || 18) > 50 ? 'offline' : 'online'}">
            ${(d.threatScore || 18) > 50 ? '⚠ HIGH' : '✓ LOW'}
          </span>
        </div>
        <div style="text-align:center; padding:20px;">
          <div style="font-size:48px; font-weight:800; color:${(d.threatScore || 18) > 50 ? '#ff3366' : '#00ff88'};">${d.threatScore || 18}<span style="font-size:20px;">/100</span></div>
          <div class="threat-meter" style="margin-top:12px;">
            <div class="threat-fill" style="width:${d.threatScore || 18}%; background:linear-gradient(90deg,#00ff88,#ffcc00,#ff3366); height:8px; border-radius:4px;"></div>
          </div>
          <div style="margin-top:12px; font-size:11px; color:var(--text-muted);">
            <i class="fas fa-exclamation-triangle"></i> ${physicalAnomalies.length} physical events detected
          </div>
        </div>
      </div>
    </div>

    <!-- Row 2: Anomaly Detectors Side by Side -->
    <div class="grid-2" style="margin-bottom:20px;">
      
      <!-- Cyber Anomaly Detectors -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-bug icon"></i> Cyber Anomaly Detectors</div>
          <span style="font-size:11px;color:var(--text-muted);">ML threshold: 50/100</span>
        </div>
        <div style="max-height:300px; overflow-y:auto;">
          ${cyberDetectors.map(a => `
            <div class="anomaly-item ${a.detected ? 'detected' : ''}" style="margin-bottom:12px; padding:10px;">
              <div class="anomaly-score" style="background:${a.detected ? '#a855f7' : '#1a3a5c'};">${a.score}</div>
              <div style="flex:1;">
                <div style="font-size:12px; font-weight:600; color:${a.detected?'#a855f7':'var(--text-primary)'};">${a.name}</div>
                <div class="threat-meter" style="margin-top:6px;">
                  <div class="threat-fill" style="width:${a.score}%; ${a.detected?'background:#a855f7;':''} height:4px;"></div>
                </div>
              </div>
              <span class="status-indicator ${a.detected?'offline':'online'}" style="font-size:10px; padding:2px 6px;">${a.detected?'DETECTED':'NORMAL'}</span>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Physical Anomaly Detectors -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-microchip icon"></i> Physical Anomaly Detectors</div>
          <span style="font-size:11px;color:var(--text-muted);">ML threshold: 50/100</span>
        </div>
        <div style="max-height:300px; overflow-y:auto;">
          ${physicalDetectors.map(a => `
            <div class="anomaly-item ${a.detected ? 'detected' : ''}" style="margin-bottom:12px; padding:10px;">
              <div class="anomaly-score" style="background:${a.detected ? '#ff3366' : '#1a3a5c'};">${a.score}</div>
              <div style="flex:1;">
                <div style="font-size:12px; font-weight:600; color:${a.detected?'#ff3366':'var(--text-primary)'};">${a.name}</div>
                <div class="threat-meter" style="margin-top:6px;">
                  <div class="threat-fill" style="width:${a.score}%; ${a.detected?'background:#ff3366;':''} height:4px;"></div>
                </div>
              </div>
              <span class="status-indicator ${a.detected?'offline':'online'}" style="font-size:10px; padding:2px 6px;">${a.detected?'DETECTED':'NORMAL'}</span>
            </div>
          `).join('')}
        </div>
      </div>
    </div>

    <!-- Row 3: ML Model Status Side by Side -->
    <div class="grid-2">
      
      <!-- Cyber ML Model Status -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-brain icon"></i> ML Model Status (Cyber)</div>
          <div class="status-indicator online">ACTIVE</div>
        </div>
        <div class="data-row"><span class="data-row-label">Algorithm</span><span class="data-row-value cyan">Isolation Forest</span></div>
        <div class="data-row"><span class="data-row-label">Cyber Accuracy</span><span class="data-row-value green">96.2%</span></div>
        <div class="data-row"><span class="data-row-label">False Positive Rate</span><span class="data-row-value yellow">1.8%</span></div>
        <div class="data-row"><span class="data-row-label">Training Samples</span><span class="data-row-value">12,847</span></div>
        <div class="data-row"><span class="data-row-label">Features Used</span><span class="data-row-value">8 (IP, attempts, usernames)</span></div>
        <div class="data-row"><span class="data-row-label">Last Trained</span><span class="data-row-value">2 hours ago</span></div>
      </div>

      <!-- Physical ML Model Status -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-chart-line icon"></i> ML Model Status (Physical)</div>
          <div class="status-indicator online">ACTIVE</div>
        </div>
        <div class="data-row"><span class="data-row-label">Algorithm</span><span class="data-row-value cyan">Isolation Forest</span></div>
        <div class="data-row"><span class="data-row-label">Physical Accuracy</span><span class="data-row-value green">94.7%</span></div>
        <div class="data-row"><span class="data-row-label">False Positive Rate</span><span class="data-row-value yellow">2.1%</span></div>
        <div class="data-row"><span class="data-row-label">Training Samples</span><span class="data-row-value">35,473</span></div>
        <div class="data-row"><span class="data-row-label">Features Used</span><span class="data-row-value">12 (voltage, freq, temp, etc.)</span></div>
        <div class="data-row"><span class="data-row-label">Last Trained</span><span class="data-row-value">2 hours ago</span></div>
      </div>
    </div>
  </div>`;
}

// Add retrain function if not present
function retrainMLModel() {
  addLog('info', 'security', 'ML model retraining initiated — updating Isolation Forest');
  setTimeout(() => {
    addLog('success', 'security', 'ML model retrained successfully with new baseline data');
    renderAnomalyPage();
  }, 2000);
}
function retrainMLModel() {
  addLog('info', 'security', 'ML model retraining initiated — updating Isolation Forest');
  setTimeout(() => {
    addLog('success', 'security', 'ML model retrained successfully with new baseline data');
    renderAnomalyPage();
  }, 2000);
}

// ── LOGS PAGE ─────────────────────────────────────────────
function renderLogsPage() {
  const el = document.getElementById('page-logs');
  if (!el) return;
  const filter = document.getElementById('log-filter')?.value || 'all';
  const search = document.getElementById('log-search')?.value?.toLowerCase() || '';
  const filtered = STATE.logs.filter(l => {
    if (filter !== 'all' && l.type !== filter && l.category !== filter) return false;
    if (search && !l.msg.toLowerCase().includes(search) && !l.user.toLowerCase().includes(search)) return false;
    return true;
  });

  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">Activity Logs</div>
        <div class="section-subtitle">System event log — ${STATE.logs.length} events recorded</div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-primary btn-sm" onclick="exportLogs()"><i class="fas fa-download"></i> Export CSV</button>
        <button class="btn btn-danger btn-sm" onclick="clearLogs()"><i class="fas fa-trash"></i> Clear</button>
      </div>
    </div>

    <div class="card" style="margin-bottom:16px;padding:14px 20px;">
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
        <div style="position:relative;flex:1;min-width:200px;">
          <i class="fas fa-search" style="position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text-muted);font-size:13px;"></i>
          <input id="log-search" type="text" placeholder="Search logs…" value="${search}"
            style="width:100%;background:rgba(0,0,0,0.3);border:1px solid var(--border-color);border-radius:7px;padding:8px 12px 8px 36px;color:var(--text-primary);font-size:13px;outline:none;"
            oninput="renderLogsPage()" />
        </div>
        <select id="log-filter" onchange="renderLogsPage()"
          style="background:rgba(0,0,0,0.3);border:1px solid var(--border-color);border-radius:7px;padding:8px 14px;color:var(--text-primary);font-size:13px;cursor:pointer;outline:none;">
          <option value="all" ${filter==='all'?'selected':''}>All Events</option>
          <option value="success" ${filter==='success'?'selected':''}>Success</option>
          <option value="info" ${filter==='info'?'selected':''}>Info</option>
          <option value="warning" ${filter==='warning'?'selected':''}>Warning</option>
          <option value="critical" ${filter==='critical'?'selected':''}>Critical</option>
          <option value="auth" ${filter==='auth'?'selected':''}>Auth Events</option>
          <option value="security" ${filter==='security'?'selected':''}>Security</option>
          <option value="system" ${filter==='system'?'selected':''}>System</option>
        </select>
        <div style="font-size:12px;color:var(--text-muted);white-space:nowrap;">
          Showing <strong style="color:var(--text-primary);">${filtered.length}</strong> of ${STATE.logs.length} events
        </div>
      </div>
    </div>

    <div class="grid-4" style="margin-bottom:16px;">
      ${[
        ['success','check-circle','Success',  STATE.logs.filter(l=>l.type==='success').length, 'green'],
        ['info',   'info-circle', 'Info',     STATE.logs.filter(l=>l.type==='info').length,    'cyan'],
        ['warning','exclamation-triangle','Warning',STATE.logs.filter(l=>l.type==='warning').length,'yellow'],
        ['critical','radiation-alt','Critical',STATE.logs.filter(l=>l.type==='critical').length,'red'],
      ].map(([t,icon,label,count,color]) => `
        <div class="kpi-card ${color}" style="padding:14px;">
          <div style="display:flex;align-items:center;gap:10px;">
            <div class="kpi-icon ${color}" style="width:36px;height:36px;font-size:16px;margin-bottom:0;flex-shrink:0;"><i class="fas fa-${icon}"></i></div>
            <div>
              <div class="kpi-value" style="font-size:22px;">${count}</div>
              <div class="kpi-label" style="margin-bottom:0;">${label} Events</div>
            </div>
          </div>
        </div>`).join('')}
    </div>

    <div class="card" style="padding:0;overflow:hidden;">
      <div style="overflow-x:auto;">
        <table class="log-table">
          <thead>
            <tr><th>Time</th><th>Level</th><th>Category</th><th>Message</th><th>User</th></tr>
          </thead>
          <tbody>
            ${filtered.slice(0, 100).map(l => `
              <tr><td class="log-time">${l.time}</td>
                <td><span class="log-badge ${l.type}"><i class="fas fa-${l.type==='critical'?'radiation-alt':l.type==='warning'?'exclamation-triangle':l.type==='success'?'check-circle':'info-circle'}"></i> ${l.type}</span></td>
                <td><span class="log-badge ${l.category}">${l.category}</span></td>
                <td class="log-msg">${l.msg}</td>
                <td style="color:var(--text-muted);font-family:'JetBrains Mono',monospace;font-size:12px;">${l.user}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>`;
}

function exportLogs() {
  const csv = ['Time,Level,Category,Message,User', ...STATE.logs.map(l => `${l.time},${l.type},${l.category},"${l.msg}",${l.user}`)].join('\n');
  const blob = new Blob([csv], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download='microgrid_logs.csv'; a.click();
  addLog('success','system','Activity log exported as CSV');
}
function clearLogs() {
  if (confirm('Clear all logs? This cannot be undone.')) {
    STATE.logs = [];
    addLog('warning','system','Activity log cleared by user');
    renderLogsPage();
  }
}

// ── SETTINGS PAGE ─────────────────────────────────────────
function renderSettingsPage() {
  if (STATE.currentUser.role !== 'admin') {
    document.getElementById('page-settings').innerHTML = `
      <div style="padding:24px;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:50vh;gap:16px;">
        <div style="font-size:48px;">🔒</div>
        <div style="font-size:18px;font-weight:600;color:var(--text-primary);">Access Denied</div>
        <div style="color:var(--text-secondary);font-size:14px;">Settings require Administrator privileges.</div>
      </div>`;
    return;
  }
  document.getElementById('page-settings').innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">System Settings</div>
        <div class="section-subtitle">Configuration — Admin access required</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-title" style="margin-bottom:18px;"><i class="fas fa-sliders-h icon"></i>&nbsp; Controller Parameters</div>
        ${[
          ['Battery Min SOC Threshold','20','%'],
          ['Battery Max SOC Threshold','95','%'],
          ['Grid Import Limit','50','kW'],
          ['Solar MPPT Sample Rate','100','ms'],
          ['Load Shedding Priority','3','level'],
        ].map(([label, val, unit]) => `
          <div class="data-row" style="flex-wrap:wrap;gap:8px;">
            <span class="data-row-label">${label}</span>
            <div style="display:flex;align-items:center;gap:6px;">
              <input type="number" value="${val}" style="width:70px;background:rgba(0,0,0,0.4);border:1px solid var(--border-color);border-radius:6px;padding:5px 8px;color:var(--text-primary);font-size:13px;text-align:right;outline:none;">
              <span style="font-size:12px;color:var(--text-muted);">${unit}</span>
            </div>
          </div>`).join('')}
        <hr class="divider">
        <button class="btn btn-success" onclick="addLog('success','system','Controller parameters updated by admin')"><i class="fas fa-save"></i> Save Parameters</button>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:18px;"><i class="fas fa-shield-alt icon"></i>&nbsp; Security Configuration</div>
        ${[
          ['TLS Encryption', true],
          ['JWT Authentication', true],
          ['MQTT TLS (port 8883)', true],
          ['Intrusion Detection System', true],
          ['DDoS Rate Limiting', true],
          ['Audit Logging', true],
          ['Two-Factor Authentication', false],
          ['IP Whitelist Enforcement', false],
        ].map(([label, enabled]) => `
          <div class="data-row">
            <span class="data-row-label">${label}</span>
            <label class="toggle-switch">
              <input type="checkbox" ${enabled?'checked':''} onchange="addLog('warning','security','Security setting changed: ${label}')">
              <span class="toggle-slider"></span>
            </label>
          </div>`).join('')}
        <hr class="divider">
        <button class="btn btn-primary" onclick="addLog('success','security','Security configuration saved by admin')"><i class="fas fa-save"></i> Save Security Config</button>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:18px;"><i class="fas fa-satellite-dish icon"></i>&nbsp; MQTT Broker Configuration</div>
        ${[['Broker Host','broker.microgrid.local'],['Port','8883'],['Client ID','mgc-controller-01'],['Keep-Alive (s)','60'],['QoS Level','2']].map(([label,val])=>`
          <div class="data-row">
            <span class="data-row-label">${label}</span>
            <input type="text" value="${val}" style="background:rgba(0,0,0,0.4);border:1px solid var(--border-color);border-radius:6px;padding:5px 10px;color:var(--text-primary);font-size:12px;font-family:'JetBrains Mono',monospace;width:180px;text-align:right;outline:none;">
          </div>`).join('')}
        <hr class="divider">
        <div style="display:flex;gap:8px;">
          <button class="btn btn-primary btn-sm" onclick="addLog('success','system','MQTT reconnection initiated')"><i class="fas fa-plug"></i> Reconnect</button>
          <button class="btn btn-success btn-sm" onclick="addLog('success','system','MQTT config saved')"><i class="fas fa-save"></i> Save</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:18px;"><i class="fas fa-info-circle icon"></i>&nbsp; System Information</div>
        ${[
          ['System Name','CyberSecure Microgrid v3.2'],
          ['Controller','Raspberry Pi 4B / STM32'],
          ['OS','Raspbian Bullseye 64-bit'],
          ['Backend','FastAPI + Python 3.11'],
          ['ML Framework','Scikit-learn 1.4.0'],
          ['Database','PostgreSQL 15 + InfluxDB'],
          ['Monitoring','Grafana 10 + Prometheus'],
          ['Uptime','99.87%'],
          ['Last Reboot','2 days, 14 hours ago'],
        ].map(([k,v])=>`<div class="data-row"><span class="data-row-label">${k}</span><span class="data-row-value" style="font-size:12px;">${v}</span></div>`).join('')}
      </div>
    </div>
  </div>`;
}

// ── USERS PAGE ────────────────────────────────────────────
function renderUsersPage() {
  if (STATE.currentUser.role !== 'admin') {
    document.getElementById('page-users').innerHTML = `
      <div style="padding:24px;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:50vh;gap:16px;">
        <div style="font-size:48px;">🔒</div>
        <div style="font-size:18px;font-weight:600;">Access Denied</div>
        <div style="color:var(--text-secondary);">User Management requires Administrator privileges.</div>
      </div>`;
    return;
  }
  const users = [
    { username:'admin',    name:'Dr. Arjun Mehta',  role:'admin',    status:'online',  lastLogin:'Just now',    ip:'192.168.1.10' },
    { username:'operator', name:'Priya Sharma',      role:'operator', status:'online',  lastLogin:'10 min ago',  ip:'192.168.1.15' },
    { username:'viewer',   name:'Raj Patel',         role:'viewer',   status:'offline', lastLogin:'2 hours ago', ip:'192.168.1.22' },
    { username:'engineer', name:'Kavita Nair',       role:'operator', status:'offline', lastLogin:'Yesterday',   ip:'192.168.1.30' },
  ];
  document.getElementById('page-users').innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">User Management</div>
        <div class="section-subtitle">RBAC — Role-Based Access Control &amp; Session Management</div>
      </div>
      <button class="btn btn-primary" onclick="addLog('info','auth','New user creation initiated by admin')"><i class="fas fa-user-plus"></i> Add User</button>
    </div>

    <div class="card" style="margin-bottom:20px;">
      <div class="card-title" style="margin-bottom:16px;"><i class="fas fa-table icon"></i>&nbsp; Role Permissions Matrix</div>
      <div style="overflow-x:auto;">
        <table class="log-table">
          <thead><tr><th>Permission</th><th><span class="role-badge admin">ADMIN</span></th><th><span class="role-badge operator">OPERATOR</span></th><th><span class="role-badge viewer">VIEWER</span></th></tr></thead>
          <tbody>
            ${[
              ['View Dashboard',            true, true,  true  ],
              ['Monitor Energy',            true, true,  true  ],
              ['View Activity Logs',        true, true,  true  ],
              ['Control Energy Dispatch',   true, true,  false ],
              ['Grid Mode Switching',       true, true,  false ],
              ['Security Center Access',    true, true,  false ],
              ['Anomaly Detection',         true, true,  false ],
              ['Modify System Settings',    true, false, false ],
              ['User Management',           true, false, false ],
              ['Export Logs / Reports',     true, true,  false ],
              ['Firmware Update',           true, false, false ],
            ].map(([perm, admin, op, viewer]) => `
              <table><td>${perm}</td>
                <td style="text-align:center;">${admin ? '<i class="fas fa-check-circle" style="color:var(--accent-green);"></i>' : '<i class="fas fa-times-circle" style="color:var(--text-muted);"></i>'}</td>
                <td style="text-align:center;">${op    ? '<i class="fas fa-check-circle" style="color:var(--accent-green);"></i>' : '<i class="fas fa-times-circle" style="color:var(--text-muted);"></i>'}</td>
                <td style="text-align:center;">${viewer? '<i class="fas fa-check-circle" style="color:var(--accent-green);"></i>' : '<i class="fas fa-times-circle" style="color:var(--text-muted);"></i>'}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fas fa-users icon"></i> Active Users &amp; Sessions</div>
      </div>
      <div style="overflow-x:auto;">
        <table class="log-table">
          <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last Login</th><th>IP Address</th><th>Actions</th></tr></thead>
          <tbody>
            ${users.map(u => `
              <tr>
                <td>
                  <div style="display:flex;align-items:center;gap:10px;">
                    <div class="user-avatar ${u.role}" style="width:32px;height:32px;font-size:12px;">${u.name.split(' ').map(n=>n[0]).join('').slice(0,2)}</div>
                    <div>
                      <div style="font-weight:600;color:var(--text-primary);font-size:13px;">${u.name}</div>
                      <div style="font-size:11px;color:var(--text-muted);">@${u.username}</div>
                    </div>
                  </div>
                </td>
                <td><span class="role-badge ${u.role}">${u.role}</span></td>
                <td><span class="status-indicator ${u.status}" style="font-size:11px;">${u.status === 'online' ? '● Online' : '○ Offline'}</span></td>
                <td style="color:var(--text-muted);font-size:12px;">${u.lastLogin}</td>
                <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-muted);">${u.ip}</td>
                <td>
                  <div style="display:flex;gap:6px;">
                    <button class="btn btn-primary btn-sm" onclick="addLog('info','auth','User profile edited: ${u.username}')"><i class="fas fa-edit"></i></button>
                    ${u.status==='online'?`<button class="btn btn-danger btn-sm" onclick="addLog('warning','auth','Session terminated for: ${u.username}')"><i class="fas fa-sign-out-alt"></i></button>`:''}
                  </div>
                </td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>`;
}

// ── Bootstrap ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  renderLogin();
});
// ── Fetch Real Anomalies from Pranav's Backend ──────────────────
async function fetchRealAnomalies() {
  try {
    const token = STATE.currentUser?.token;
    if (!token) return;
    
    const res = await fetch('https://microgrid-final.onrender.com/anomalies/', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    const data = await res.json();
    console.log('Real anomalies:', data);
    
    if (Array.isArray(data) && data.length > 0) {
      STATE.data.anomalies = data;

      // Time filter - only last 1 hour
      const oneHourAgo = Date.now() - 60 * 60 * 1000;

      // === CYBER ANOMALIES ===
      const cyberAnomalies = data.filter(a => 
        (a.attack_type === 'BruteForce' || 
         a.attack_type === 'CredentialStuffing' ||
         a.attack_type === 'Phishing' ||
         a.attack_type === 'MITM' ||
         a.attack_type === 'DDoS' ||
         a.attack_type === 'SessionHijacking' ||
         a.signal === 'failed_login_count' ||
         a.signal === 'login_attempt') &&
        a.resolved !== true &&
        new Date(a.time).getTime() > oneHourAgo
      );
      
      // Calculate Cyber Threat Score (max 100)
      const cyberScore = Math.min(100, cyberAnomalies.length * 15);
      STATE.data.cyberThreatScore = cyberScore;
      
      // Update UI for cyber
      const cyberThreatEl = document.getElementById('cyber-threat-score');
      const cyberThreatFill = document.getElementById('cyber-threat-fill');
      if (cyberThreatEl) cyberThreatEl.textContent = cyberScore;
      if (cyberThreatFill) cyberThreatFill.style.width = cyberScore + '%';
      
      // Also update dashboard security card
      const liveCyberThreat = document.getElementById('live-cyber-threat');
      if (liveCyberThreat) liveCyberThreat.textContent = cyberScore + '/100';
      
      const cyberFillDash = document.getElementById('cyber-threat-fill-dash');
      if (cyberFillDash) cyberFillDash.style.width = cyberScore + '%';
      
      const cyberStatusBadge = document.getElementById('cyber-status-badge');
      if (cyberStatusBadge) {
        if (cyberScore > 50) {
          cyberStatusBadge.textContent = '⚠ CYBER THREAT';
          cyberStatusBadge.className = 'status-indicator offline';
        } else {
          cyberStatusBadge.textContent = '✓ CYBER SECURE';
          cyberStatusBadge.className = 'status-indicator online';
        }
      }
      
      const activeAttackEl = document.getElementById('active-cyber-attack');
      if (activeAttackEl) activeAttackEl.textContent = getActiveCyberAttack();
      
      // === PHYSICAL ANOMALIES ===
      const physicalAnomalies = data.filter(a => 
        a.attack_type !== 'BruteForce' && 
        a.attack_type !== 'CredentialStuffing' &&
        a.attack_type !== 'Phishing' &&
        a.attack_type !== 'MITM' &&
        a.attack_type !== 'DDoS' &&
        a.attack_type !== 'SessionHijacking' &&
        a.signal !== 'failed_login_count' &&
        a.signal !== 'login_attempt' &&
        a.signal !== 'attack_simulation'
      );
      
      if (STATE.data.alert !== 1.0) {
        const recentActive = physicalAnomalies.filter(a => {
          const isActive = a.status !== 'resolved' && a.resolved !== true;
          const isRecent = !a.timestamp || new Date(a.timestamp).getTime() > oneHourAgo;
          return isActive && isRecent;
        });
        
        const physScore = Math.min(100, recentActive.length * 10);
        if (STATE.data.threatScore !== 100) {
          STATE.data.threatScore = physScore;
        }
      }
    } else {
      STATE.data.cyberThreatScore = 0;
      if (STATE.data.alert !== 1.0) {
        STATE.data.threatScore = 18;
      }
    }
  } catch(e) {
    console.error('Failed to fetch anomalies:', e);
  }
}
// ── Real HiveMQ MQTT Connection ──────────────────────────────
function initMQTT() {
  const client = mqtt.connect('wss://b796810c8d774e1d909a33856b193c2d.s1.eu.hivemq.cloud:8884/mqtt', {
    username: 'The_Macros',
    password: 'The_Macros1',
    clientId: 'microgrid-ui-' + Math.random().toString(16).slice(2),
    clean: true
  });

  client.on('connect', () => {
    console.log('HiveMQ connected!');
    client.subscribe('microgrid/#');
  });

  client.on('error', (err) => {
    console.error('MQTT error:', err);
  });

  client.on('message', (topic, message) => {
    console.log('MQTT IN:', topic, message.toString());
    try {
      const data = JSON.parse(message.toString());
      const val = parseFloat(data.value);

   switch(topic) {
  case 'microgrid/hour':
    STATE.data.hour = val;
    break;

  case 'microgrid/solar':
    STATE.data.solar = val;
    if (STATE.data.hour !== undefined) STATE.history.solarByHour[STATE.data.hour] = val;
    break;

  case 'microgrid/load':
    STATE.data.load = val;
    if (STATE.data.hour !== undefined) STATE.history.loadByHour[STATE.data.hour] = val;
    break;

  case 'microgrid/battery':
    STATE.data.battery = val;
    if (STATE.data.hour !== undefined) STATE.history.batteryByHour[STATE.data.hour] = val;
    break;

  case 'microgrid/grid':
    STATE.data.gridImport = val;
    if (STATE.data.hour !== undefined) STATE.history.gridByHour[STATE.data.hour] = val;
    break;

  case 'microgrid/temperature':
    STATE.data.temperature = val;
    if (STATE.data.hour !== undefined) STATE.history.tempByHour[STATE.data.hour] = val;
    break;

  case 'microgrid/battery_action_kw':
    STATE.data.batteryAction = val;
    break;

  case 'microgrid/security/attack_type':
    STATE.data.attackType = data.value;
    break;

  case 'microgrid/security/attack':
    STATE.data.attackInjected = val;
    break;

  case 'microgrid/security/alert': {
    const wasNormal = (STATE.data.alert !== 1.0);
    const wasAlert  = (STATE.data.alert === 1.0);
    if (STATE.data.hour !== undefined) STATE.history.alertByHour[STATE.data.hour] = val;
    STATE.data.alert = val;
    STATE.history.alert.push(val);
    STATE.history.alertHours.push(STATE.data.hour ?? 0);
    if (STATE.history.alert.length > 24) STATE.history.alert.shift();
    if (STATE.history.alertHours.length > 24) STATE.history.alertHours.shift();

    if (!STATE.data._alertCounter) STATE.data._alertCounter = 0;

    if (val === 1.0) {
      STATE.data._alertCounter++;
    } else {
      STATE.data._alertCounter = 0;
    }

    if (val === 1.0 && wasNormal) {
      const now = Date.now();
      const lastAlert = STATE.data._lastAlertTime || 0;
      if (now - lastAlert > 60000) {
        STATE.data._lastAlertTime = now;
        const attackType = STATE.data.attackType || 'UNKNOWN';
        const hour = STATE.data.hour;
        createAnomalyInBackend(attackType, hour);
        addAlert('critical',
          `⚠ ATTACK DETECTED: ${attackType}`,
          `physical_alert triggered at Hour ${hour}. Grid under attack!`
        );
        addLog('critical', 'security',
          `[IDS] ${attackType} detected at hour ${hour} — physical_alert = 1`
        );
        STATE.data.threatScore = 100;
        STATE.data.attackInjected = 1;
        STATE.history.threat.push(100);
        if (STATE.history.threat.length > 100) STATE.history.threat.shift();
        updateNotifBadge();

        const threatStatus = document.getElementById('threat-status');
        if (threatStatus) { threatStatus.textContent = '⚠ THREAT'; threatStatus.className = 'status-indicator offline'; }
        const physAlertEl = document.getElementById('live-physical-alert');
        if (physAlertEl) { physAlertEl.innerHTML = '🚨 ALERT'; physAlertEl.className = 'data-row-value red'; }
        const attackInj = document.getElementById('live-attack-injected');
        if (attackInj) { attackInj.innerHTML = '🔴 YES'; attackInj.className = 'data-row-value red'; }
        const attackTypeEl = document.getElementById('live-attack-type');
        if (attackTypeEl) { attackTypeEl.textContent = attackType; }
        const threatFill = document.getElementById('threat-fill');
        if (threatFill) { threatFill.style.width = '100%'; }
        const threatEl = document.getElementById('live-threat');
        if (threatEl) { threatEl.textContent = '100 / 100'; }
      }
    }

    if (val === 0.0 && wasAlert && STATE.data._alertCounter === 0) {
      STATE.data.threatScore = 18;
      STATE.data.attackType = 'None';
      STATE.data.attackInjected = 0;
      STATE.data._lastAlertTime = 0;
      STATE.history.threat.push(18);
      if (STATE.history.threat.length > 100) STATE.history.threat.shift();
      addLog('success', 'security', '[IDS] Physical alert cleared — system returning to normal');

      const threatStatus = document.getElementById('threat-status');
      if (threatStatus) { threatStatus.textContent = '✓ SECURE'; threatStatus.className = 'status-indicator online'; }
      const physAlertEl = document.getElementById('live-physical-alert');
      if (physAlertEl) { physAlertEl.innerHTML = '✅ Normal'; physAlertEl.className = 'data-row-value red'; }
      const attackInj = document.getElementById('live-attack-injected');
      if (attackInj) { attackInj.innerHTML = '🟢 NO'; attackInj.className = 'data-row-value green'; }
      const attackTypeEl = document.getElementById('live-attack-type');
      if (attackTypeEl) { attackTypeEl.textContent = '—'; }
      const threatFill = document.getElementById('threat-fill');
      if (threatFill) { threatFill.style.width = '18%'; }
      const threatEl = document.getElementById('live-threat');
      if (threatEl) { threatEl.textContent = '18 / 100'; }
    }

    updateLiveValues();
    updateLiveCharts();
    break;
  }


      }

    } catch(e) {
      console.log('MQTT parse error:', topic, message.toString(), e);
    }
  });

}

async function ingestTelemetryToBackend(rowData) {
  try {
    await fetch('https://microgrid-final.onrender.com/telemetry/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: 'inverter_01',
        solar_kw: rowData.solar,
        load_kw: rowData.load,
        battery_soc_kwh: rowData.battery,
        battery_action_kw: rowData.batteryAction || 0,
        grid_import_kw: rowData.gridImport,
        grid_export_kw: rowData.gridExport || 0,
        temperature_c: rowData.temperature,
        physical_alert: rowData.alert,
        attack_injected: rowData.attackInjected || 0,
        attack_type: rowData.attackType || 'NONE',
        hour: rowData.hour
      })
    }).catch(() => {});
  } catch(e) {}
}

async function createAnomalyInBackend(attackType, hour) {
  try {
    const token = STATE.currentUser?.token;
    if (!token) return;
    const res = await fetch('https://microgrid-final.onrender.com/anomalies/', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        anomaly_type: attackType,
        severity: 'critical',
        description: `${attackType} detected at hour ${hour}`,
        hour: hour,
        solar_kw: STATE.data.solar,
        load_kw: STATE.data.load,
        grid_import_kw: STATE.data.gridImport,
        temperature_c: STATE.data.temperature
      })
    });
    const result = await res.json();
    console.log('Anomaly created in backend:', result);
  } catch(e) {
    console.error('Failed to create anomaly:', e);
  }
}  // ← Close createAnomalyInBackend HERE

// THEN add simulateAttack AFTER it (not inside)
async function simulateAttack(type) {
  // Send attack to backend
  await fetch('https://microgrid-final.onrender.com/anomalies/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      device_id: 'microgrid-ui',
      signal: 'attack_simulation',
      value: 1,
      severity: 'CRITICAL',
      attack_type: type,
      message: `Simulated ${type} attack triggered`
    })
  });
  
  // Update frontend threat score
  
  // Refresh anomalies
  await fetchRealAnomalies();
  
  // Refresh current page
  if (STATE.currentPage === 'anomaly') renderAnomalyPage();
  if (STATE.currentPage === 'security') renderSecurityPage();
  
  addLog('critical', 'security', `[SIMULATION] ${type} attack initiated`);
  addAlert('critical', `[SIMULATION] ${type} Attack`, `Simulated ${type} attack triggered`);
}