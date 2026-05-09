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
    solar: 42.5, wind: 12.3, battery: 68, load: 38.7,
    gridImport: 0, gridExport: 4.1, voltage: 230.4,
    frequency: 50.01, temperature: 34.2, humidity: 62,
    mode: 'grid-connected', securityLevel: 'normal',
    threatScore: 18, encryptionStatus: true,
    activeConnections: 4, failedLogins: 0,
    mqttStatus: 'connected', tlsStatus: true,
    anomalies: [], powerFlow: []
  },
  history: { solar: [], load: [], battery: [], grid: [], threat: [] },
  loginAttempts: {},
  notifications: [],
};

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

// Prepopulate history arrays
for (let i = 0; i < 20; i++) {
  STATE.history.solar.push(+(20 + Math.random() * 35).toFixed(1));
  STATE.history.load.push(+(30 + Math.random() * 20).toFixed(1));
  STATE.history.battery.push(+(55 + Math.random() * 30).toFixed(1));
  STATE.history.grid.push(+(Math.random() * 10 - 5).toFixed(1));
  STATE.history.threat.push(+(5 + Math.random() * 30).toFixed(0));
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
function renderLogin() {
  const root = document.getElementById('app-root');
  root.innerHTML = `
  <div id="login-screen" class="grid-bg">
    <div class="scan-effect" style="position:fixed"></div>
    <div class="login-card">
      <div style="text-align:center;margin-bottom:24px;">
        <div style="width:64px;height:64px;background:linear-gradient(135deg,#004466,#007799);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:28px;border:2px solid rgba(0,212,255,0.4);box-shadow:0 0 30px rgba(0,212,255,0.2);">
          🔐
        </div>
      </div>
      <div class="login-logo">GRID CONTROL SYSTEM v3.2</div>
      <div class="login-title">CyberSecure<br>Microgrid Controller</div>
      <div class="login-subtitle">Secure access required — TLS 1.3 encrypted</div>

      <div class="input-group">
        <label>Username</label>
        <i class="fas fa-user input-icon"></i>
        <input type="text" id="login-user" placeholder="Enter username" autocomplete="off" />
      </div>
      <div class="input-group">
        <label>Password</label>
        <i class="fas fa-lock input-icon"></i>
        <input type="password" id="login-pass" placeholder="Enter password" />
      </div>
      <div class="input-group">
        <label>Access Role</label>
        <i class="fas fa-id-badge input-icon"></i>
        <select id="login-role">
          <option value="admin">Administrator</option>
          <option value="operator">Operator</option>
          <option value="viewer">Viewer</option>
        </select>
      </div>
      <button class="btn-login" onclick="handleLogin()">
        <i class="fas fa-shield-alt"></i> &nbsp; AUTHENTICATE &amp; ACCESS
      </button>
      <div class="login-error" id="login-error">
        <i class="fas fa-exclamation-triangle"></i>
        <span id="login-error-msg">Invalid credentials</span>
      </div>
      <div class="demo-creds">
        <div style="font-size:11px;font-weight:700;margin-bottom:6px;color:var(--accent-cyan);letter-spacing:1px;">DEMO CREDENTIALS</div>
        <div>👑 <strong>admin</strong> / secret— Full access</div>
        <div>⚙️ <strong>operator</strong> / secret— Monitoring + control</div>
        <div>👁 <strong>viewer</strong> / secret— Read-only access</div>
      </div>
      <div class="mqtt-bar" style="margin-top:16px;">
        <span class="dot"></span>
        <span>MQTT: broker.microgrid.local:8883</span>
        <span style="margin-left:auto;">🔒 TLS</span>
      </div>
    </div>
  </div>`;

  document.getElementById('login-pass').addEventListener('keypress', e => {
    if (e.key === 'Enter') handleLogin();
  });
}

async function handleLogin() {
  const btn = document.querySelector('.btn-login');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Authenticating...'; }
  const username = document.getElementById('login-user').value.trim().toLowerCase();
  const password = document.getElementById('login-pass').value;
  const role     = document.getElementById('login-role').value;
  const errorEl  = document.getElementById('login-error');
  // Report failed login to Pranav's backend
  if (!USERS[username] || USERS[username].password !== password) {
    fetch('https://microgrid-final.onrender.com/anomalies/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: 'microgrid-ui',
        signal: 'login_attempt',
        value: 1,
        expected_min: 0,
        expected_max: 0,
        anomaly_score: 85,
        severity: 'high',
        attack_type: 'BruteForce',
        message: `Failed login attempt for user: ${username}`
      })
    }).catch(e => console.error('Anomaly report failed:', e));
  }
  const errorMsg = document.getElementById('login-error-msg');

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
  
  addLog('success', 'auth', `User "${username}" authenticated via backend`);
  renderApp();
  startRealTimeData();
}

// ── Main App Shell ────────────────────────────────────────
function renderApp() {
  const root = document.getElementById('app-root');
  const u = STATE.currentUser;
  const perms = ROLE_PERMISSIONS[u.role];

  const navItems = [
    { id:'dashboard', icon:'fa-tachometer-alt',  label:'Dashboard',          section:'MONITORING'   },
    { id:'energy',    icon:'fa-bolt',             label:'Energy Management',  section:null           },
    { id:'grid',      icon:'fa-project-diagram',  label:'Grid & Topology',    section:null           },
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
        <div class="sidebar-logo-text">MicroGrid</div>
        <div class="sidebar-logo-sub">CyberSecure v3.2</div>
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
    dashboard:'Dashboard Overview', energy:'Energy Management', grid:'Grid & Topology',
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

// ── Live Value Updates ─────────────────────────────────
function updateLiveValues() {
  const d = STATE.data;
  const sets = {
    'live-solar':    `${d.solar.toFixed(1)} <span class="kpi-unit">kW</span>`,
    'live-wind':     `${(d.wind || 12.3).toFixed(1)} <span class="kpi-unit">kW</span>`,
    'live-battery':  `${d.battery.toFixed(0)} <span class="kpi-unit">%</span>`,
    'live-load':     `${d.load.toFixed(1)} <span class="kpi-unit">kW</span>`,
    'live-grid-exp': `${(d.gridExport || 0).toFixed(1)} <span class="kpi-unit">kW</span>`,
    'live-grid-imp': `${(d.gridImport || 0).toFixed(1)} <span class="kpi-unit">kW</span>`,
    'live-voltage':  `${d.voltage.toFixed(1)} <span class="kpi-unit">V</span>`,
    'live-freq':     `${d.frequency.toFixed(2)} <span class="kpi-unit">Hz</span>`,
    'live-temp':     `${(d.temperature || 34.2).toFixed(1)} <span class="kpi-unit">°C</span>`,
    'live-threat':   `${(d.threatScore || 18).toFixed(0)} <span class="kpi-unit">/100</span>`,
  };
  Object.entries(sets).forEach(([id, val]) => {
    const el = document.getElementById(id);
    if (el) { el.innerHTML = val; el.classList.add('updating'); setTimeout(() => el.classList.remove('updating'), 500); }
  });
  // Battery bar
  const fill = document.getElementById('battery-fill');
  if (fill) {
    fill.style.width = `${d.battery.toFixed(0)}%`;
    fill.className = `battery-fill ${d.battery >= 50 ? 'high' : d.battery >= 25 ? 'mid' : 'low'}`;
  }
  const battText = document.getElementById('battery-bar-text');
  if (battText) battText.textContent = `${d.battery.toFixed(0)}%`;

  // Threat bar
  const threatFill = document.getElementById('threat-fill');
  if (threatFill) threatFill.style.width = `${(d.threatScore || 18)}%`;

  // Topo node values
  const topoSolar = document.getElementById('topo-solar-val');   if(topoSolar) topoSolar.textContent = `${d.solar.toFixed(1)} kW`;
  const topoBatt  = document.getElementById('topo-batt-val');    if(topoBatt)  topoBatt.textContent  = `${d.battery.toFixed(0)}%`;
  const topoLoad  = document.getElementById('topo-load-val');    if(topoLoad)  topoLoad.textContent  = `${d.load.toFixed(1)} kW`;
  const topoGrid  = document.getElementById('topo-grid-val');    if(topoGrid)  topoGrid.textContent  = `${(d.gridExport || 0).toFixed(1)} kW`;
}

function updateLiveCharts() {
  const labels = Array.from({length: 20}, (_, i) => `T-${20-i}`);
  const update = (id, datasets) => {
    const c = STATE.chartInstances[id];
    if (!c) return;
    c.data.labels = labels;
    datasets.forEach((ds, i) => { if (c.data.datasets[i]) c.data.datasets[i].data = ds; });
    c.update('none');
  };
  update('chart-power', [STATE.history.solar, STATE.history.load]);
  update('chart-battery', [STATE.history.battery]);
  update('chart-grid', [STATE.history.grid]);
  update('chart-threat', [STATE.history.threat]);
  update('chart-energy-solar', [STATE.history.solar]);
  update('chart-energy-load', [STATE.history.load]);
}

// ── Chart Factory ─────────────────────────────────────────
function makeChart(id, type, labels, datasets, opts = {}) {
  const canvas = document.getElementById(id);
  if (!canvas) return null;
  if (STATE.chartInstances[id]) { try { STATE.chartInstances[id].destroy(); } catch(e){} }
  const chart = new Chart(canvas, {
    type,
    data: { labels, datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 400 },
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

const CHART_LABELS = Array.from({length: 20}, (_, i) => `T-${20-i}`);

// ── DASHBOARD PAGE ────────────────────────────────────────
function renderDashboard() {
  const d = STATE.data;
  const el = document.getElementById('page-dashboard');
  if (!el) return;
  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">System Dashboard</div>
        <div class="section-subtitle">Real-time microgrid monitoring — auto-refreshes every 2 seconds</div>
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
        <div class="kpi-icon cyan"><i class="fas fa-plug"></i></div>
        <div class="kpi-value" id="live-load">${d.load.toFixed(1)} <span class="kpi-unit">kW</span></div>
        <div class="kpi-label">Load Demand</div>
        <div class="kpi-trend stable"><i class="fas fa-minus"></i> Nominal load</div>
      </div>
      <div class="kpi-card purple">
        <div class="kpi-icon purple"><i class="fas fa-exchange-alt"></i></div>
        <div class="kpi-value" id="live-grid-exp">${(d.gridExport || 0).toFixed(1)} <span class="kpi-unit">kW</span></div>
        <div class="kpi-label">Grid Export</div>
        <div class="kpi-trend up"><i class="fas fa-arrow-up"></i> Exporting to grid</div>
      </div>
    </div>

    <!-- Row 2: Charts + Battery -->
    <div class="grid-2-1" style="margin-bottom:20px;">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-chart-line icon"></i> Power Generation vs Load</div>
          <div class="status-indicator online"><i class="fas fa-circle" style="font-size:8px;"></i> LIVE</div>
        </div>
        <div class="chart-wrapper"><canvas id="chart-power"></canvas></div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-battery-half icon"></i> Battery Status</div>
        </div>
        <div style="margin-bottom:16px;">
          <div class="battery-visual">
            <div class="battery-fill ${d.battery >= 50 ? 'high' : d.battery >= 25 ? 'mid' : 'low'}" id="battery-fill" style="width:${d.battery.toFixed(0)}%"></div>
            <div class="battery-text" id="battery-bar-text">${d.battery.toFixed(0)}%</div>
          </div>
        </div>
        <div class="chart-wrapper sm"><canvas id="chart-battery"></canvas></div>
        <hr class="divider">
        <div class="data-row"><span class="data-row-label">State of Charge</span><span class="data-row-value green">${d.battery.toFixed(0)}%</span></div>
        <div class="data-row"><span class="data-row-label">Capacity</span><span class="data-row-value">200 kWh</span></div>
        <div class="data-row"><span class="data-row-label">Status</span><span class="data-row-value cyan">${d.battery > 50 ? 'Charging' : 'Discharging'}</span></div>
      </div>
    </div>

    <!-- Row 3: Grid Power + Security + System Vitals -->
    <div class="grid-3" style="margin-bottom:20px;">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-project-diagram icon"></i> Grid Power Flow</div>
        </div>
        <div class="chart-wrapper sm"><canvas id="chart-grid"></canvas></div>
        <hr class="divider">
        <div class="data-row"><span class="data-row-label">Grid Import</span><span class="data-row-value red" id="live-grid-imp">${(d.gridImport || 0).toFixed(1)} kW</span></div>
        <div class="data-row"><span class="data-row-label">Grid Export</span><span class="data-row-value green">${(d.gridExport || 0).toFixed(1)} kW</span></div>
        <div class="data-row"><span class="data-row-label">Voltage</span><span class="data-row-value" id="live-voltage">${d.voltage.toFixed(1)} V</span></div>
        <div class="data-row"><span class="data-row-label">Frequency</span><span class="data-row-value" id="live-freq">${d.frequency.toFixed(2)} Hz</span></div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-shield-alt icon"></i> Security Status</div>
          <div class="status-indicator online">SECURE</div>
        </div>
        <div class="enc-status"><i class="fas fa-lock"></i> TLS 1.3 — All channels encrypted</div>
        <div class="enc-status" style="background:rgba(168,85,247,0.07);border-color:rgba(168,85,247,0.2);color:var(--accent-purple);"><i class="fas fa-key"></i> JWT Auth — Token valid</div>
        <div style="margin-top:12px;">
          <div style="font-size:12px;color:var(--text-secondary);margin-bottom:6px;display:flex;justify-content:space-between;">
            <span>Threat Score</span><span id="live-threat">${(d.threatScore || 18).toFixed(0)}/100</span>
          </div>
          <div class="threat-meter"><div class="threat-fill" id="threat-fill" style="width:${(d.threatScore || 18)}%"></div></div>
        </div>
        <hr class="divider">
        <div class="data-row"><span class="data-row-label">Active Connections</span><span class="data-row-value cyan">4</span></div>
        <div class="data-row"><span class="data-row-label">IDS Status</span><span class="data-row-value green">Active</span></div>
        <div class="data-row"><span class="data-row-label">Failed Logins (24h)</span><span class="data-row-value yellow">${STATE.alerts.filter(a=>a.title.includes('Failed')||a.title.includes('Login')).length}</span></div>
        <div class="chart-wrapper sm" style="margin-top:12px;"><canvas id="chart-threat"></canvas></div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-thermometer-half icon"></i> System Vitals</div>
        </div>
        <div class="progress-bar-wrapper">
          <div class="progress-label"><span>Solar Output</span><span>${d.solar.toFixed(1)} / 80 kW</span></div>
          <div class="progress-bar-bg"><div class="progress-bar-fill yellow" style="width:${(d.solar/80*100).toFixed(0)}%"></div></div>
        </div>
        <div class="progress-bar-wrapper">
          <div class="progress-label"><span>Wind Output</span><span>${(d.wind || 12.3).toFixed(1)} / 25 kW</span></div>
          <div class="progress-bar-bg"><div class="progress-bar-fill cyan" style="width:${((d.wind || 12.3)/25*100).toFixed(0)}%"></div></div>
        </div>
        <div class="progress-bar-wrapper">
          <div class="progress-label"><span>Load Utilization</span><span>${d.load.toFixed(1)} / 70 kW</span></div>
          <div class="progress-bar-bg"><div class="progress-bar-fill purple" style="width:${(d.load/70*100).toFixed(0)}%"></div></div>
        </div>
        <div class="progress-bar-wrapper">
          <div class="progress-label"><span>Battery Capacity</span><span>${d.battery.toFixed(0)}%</span></div>
          <div class="progress-bar-bg"><div class="progress-bar-fill green" style="width:${d.battery.toFixed(0)}%"></div></div>
        </div>
        <hr class="divider">
        <div class="data-row"><span class="data-row-label">Temperature</span><span class="data-row-value" id="live-temp">${(d.temperature || 34.2).toFixed(1)} °C</span></div>
        <div class="data-row"><span class="data-row-label">Control Mode</span><span class="data-row-value cyan">GRID-CONNECTED</span></div>
        <div class="data-row"><span class="data-row-label">Uptime</span><span class="data-row-value green">99.8%</span></div>
        <div class="data-row"><span class="data-row-label">Last Sync</span><span class="data-row-value">${now()}</span></div>
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
    makeChart('chart-power', 'line', CHART_LABELS, [
      { label:'Solar', data: STATE.history.solar, borderColor:'#ffcc00', backgroundColor:'rgba(255,204,0,0.08)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 },
      { label:'Load',  data: STATE.history.load,  borderColor:'#00d4ff', backgroundColor:'rgba(0,212,255,0.08)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 }
    ], { legend: true });
    makeChart('chart-battery', 'line', CHART_LABELS, [
      { label:'SOC', data: STATE.history.battery, borderColor:'#00ff88', backgroundColor:'rgba(0,255,136,0.1)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 }
    ], { yScale: { min: 0, max: 100 } });
    makeChart('chart-grid', 'bar', CHART_LABELS, [
      { label:'Net Grid', data: STATE.history.grid, backgroundColor: STATE.history.grid.map(v => v >= 0 ? 'rgba(0,255,136,0.5)' : 'rgba(255,51,102,0.5)'), borderRadius:3 }
    ]);
    makeChart('chart-threat', 'line', CHART_LABELS, [
      { label:'Threat', data: STATE.history.threat, borderColor:'#ff3366', backgroundColor:'rgba(255,51,102,0.08)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 }
    ], { yScale: { min: 0, max: 100 } });
  }, 50);
}

// ── ENERGY PAGE ───────────────────────────────────────────
function renderEnergyPage() {
  const d = STATE.data;
  const el = document.getElementById('page-energy');
  if (!el) return;
  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">Energy Management</div>
        <div class="section-subtitle">Smart control algorithm — renewable integration, storage &amp; dispatch</div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-success" onclick="addLog('success','system','Manual export triggered by operator')"><i class="fas fa-upload"></i> Export</button>
        <button class="btn btn-primary" onclick="addLog('info','system','Load shedding command sent')"><i class="fas fa-sliders-h"></i> Dispatch</button>
      </div>
    </div>

    <!-- Control Mode -->
    <div class="card" style="margin-bottom:20px;">
      <div class="card-title" style="margin-bottom:14px;"><i class="fas fa-cogs icon"></i>&nbsp; Controller Operating Mode</div>
      <div style="display:flex;gap:10px;">
        <button class="mode-btn ${d.mode==='grid-connected'?'active':''}" onclick="setMode('grid-connected',this)">🔌 Grid-Connected</button>
        <button class="mode-btn ${d.mode==='island'?'active':''}" onclick="setMode('island',this)">🏝 Island Mode</button>
        <button class="mode-btn" onclick="setMode('export',this)">📤 Max Export</button>
        <button class="mode-btn" onclick="setMode('charge',this)">🔋 Charge Priority</button>
        <button class="mode-btn" onclick="setMode('eco',this)">🌱 Eco Mode</button>
      </div>
    </div>

    <!-- KPIs -->
    <div class="grid-4" style="margin-bottom:20px;">
      <div class="kpi-card yellow">
        <div class="kpi-icon yellow"><i class="fas fa-solar-panel"></i></div>
        <div class="kpi-value" id="live-solar">${d.solar.toFixed(1)} <span class="kpi-unit">kW</span></div>
        <div class="kpi-label">Solar Generation</div>
        <div class="kpi-trend up"><i class="fas fa-sun"></i> MPPT Active</div>
      </div>
      <div class="kpi-card cyan">
        <div class="kpi-icon cyan"><i class="fas fa-wind"></i></div>
        <div class="kpi-value" id="live-wind">${(d.wind || 12.3).toFixed(1)} <span class="kpi-unit">kW</span></div>
        <div class="kpi-label">Wind Generation</div>
        <div class="kpi-trend stable"><i class="fas fa-wind"></i> Nominal</div>
      </div>
      <div class="kpi-card green">
        <div class="kpi-icon green"><i class="fas fa-battery-full"></i></div>
        <div class="kpi-value" id="live-battery">${d.battery.toFixed(0)} <span class="kpi-unit">%</span></div>
        <div class="kpi-label">Battery SOC</div>
        <div class="kpi-trend ${d.battery>50?'up':'down'}"><i class="fas fa-${d.battery>50?'arrow-up':'arrow-down'}"></i> ${d.battery>50?'Charging':'Discharging'}</div>
      </div>
      <div class="kpi-card red">
        <div class="kpi-icon red"><i class="fas fa-bolt"></i></div>
        <div class="kpi-value" id="live-load">${d.load.toFixed(1)} <span class="kpi-unit">kW</span></div>
        <div class="kpi-label">Total Load</div>
        <div class="kpi-trend stable"><i class="fas fa-minus"></i> Balanced</div>
      </div>
    </div>

    <div class="grid-2" style="margin-bottom:20px;">
      <!-- Energy Mix Doughnut -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-chart-pie icon"></i> Energy Mix</div>
        </div>
        <div class="chart-wrapper" style="height:240px;"><canvas id="chart-mix"></canvas></div>
      </div>
      <!-- Solar Real-time -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-solar-panel icon"></i> Solar Power (Real-time)</div>
          <div class="status-indicator online">MPPT ACTIVE</div>
        </div>
        <div class="chart-wrapper"><canvas id="chart-energy-solar"></canvas></div>
      </div>
    </div>

    <div class="grid-2">
      <!-- Load Profile -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-plug icon"></i> Load Profile</div>
        </div>
        <div class="chart-wrapper"><canvas id="chart-energy-load"></canvas></div>
      </div>
      <!-- Battery Management -->
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-battery-half icon"></i> Energy Storage Management</div>
        </div>
        <div class="battery-visual" style="margin-bottom:16px;">
          <div class="battery-fill ${d.battery>=50?'high':d.battery>=25?'mid':'low'}" id="battery-fill" style="width:${d.battery.toFixed(0)}%"></div>
          <div class="battery-text" id="battery-bar-text">${d.battery.toFixed(0)}%</div>
        </div>
        <div class="data-row"><span class="data-row-label">State of Charge (SOC)</span><span class="data-row-value green">${d.battery.toFixed(0)}%</span></div>
        <div class="data-row"><span class="data-row-label">State of Health (SOH)</span><span class="data-row-value cyan">94.2%</span></div>
        <div class="data-row"><span class="data-row-label">Capacity</span><span class="data-row-value">200 kWh</span></div>
        <div class="data-row"><span class="data-row-label">Charge Rate</span><span class="data-row-value yellow">2.4 C</span></div>
        <div class="data-row"><span class="data-row-label">Cycles</span><span class="data-row-value">482</span></div>
        <div class="data-row"><span class="data-row-label">Est. Backup Time</span><span class="data-row-value">${(d.battery * 2 / d.load).toFixed(1)} hrs</span></div>
        <hr class="divider">
        <div style="display:flex;gap:8px;">
          <button class="btn btn-success" style="flex:1;" onclick="addLog('success','system','Manual charge command sent to BMS')"><i class="fas fa-bolt"></i> Force Charge</button>
          <button class="btn btn-danger" style="flex:1;" onclick="addLog('warning','system','Battery discharge paused by operator')"><i class="fas fa-pause"></i> Pause</button>
        </div>
      </div>
    </div>
  </div>`;

  setTimeout(() => {
    const total = d.solar + (d.wind || 12.3) + (d.gridImport || 0) + 0.1;
    makeChart('chart-mix', 'doughnut', [], [{
      data: [d.solar, d.wind || 12.3, d.gridImport > 0 ? d.gridImport : 0.1, d.battery * 0.3],
      backgroundColor: ['rgba(255,204,0,0.8)','rgba(0,212,255,0.8)','rgba(168,85,247,0.8)','rgba(0,255,136,0.8)'],
      borderColor: ['#ffcc00','#00d4ff','#a855f7','#00ff88'],
      borderWidth: 2, hoverOffset: 8
    }], {
      legend: true,
      extra: { plugins: { legend: { display: true, position: 'bottom', labels: { color:'#7a9cc0', font:{size:11}, padding:16 } } } }
    });
    const mc = STATE.chartInstances['chart-mix'];
    if (mc) { mc.data.labels = ['Solar','Wind','Grid Import','Battery']; mc.update(); }

    makeChart('chart-energy-solar', 'line', CHART_LABELS, [
      { label:'Solar kW', data: STATE.history.solar, borderColor:'#ffcc00', backgroundColor:'rgba(255,204,0,0.1)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 }
    ]);
    makeChart('chart-energy-load', 'line', CHART_LABELS, [
      { label:'Load kW', data: STATE.history.load, borderColor:'#00d4ff', backgroundColor:'rgba(0,212,255,0.08)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 }
    ]);
  }, 50);
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
  const d = STATE.data;
  const el = document.getElementById('page-grid');
  if (!el) return;
  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">Grid &amp; Topology</div>
        <div class="section-subtitle">Power flow visualization — grid synchronization &amp; islanding control</div>
      </div>
      <div class="status-pill online"><span class="pulse-dot"></span> GRID-CONNECTED</div>
    </div>

    <!-- Topology -->
    <div class="card" style="margin-bottom:20px;">
      <div class="card-header">
        <div class="card-title"><i class="fas fa-project-diagram icon"></i> Microgrid Topology — Power Flow</div>
        <div class="status-indicator online">Live</div>
      </div>
      <div class="topology-container" id="topo-container">
        <svg id="topo-canvas" viewBox="0 0 760 300" preserveAspectRatio="xMidYMid meet">
          <line x1="130" y1="80" x2="280" y2="150" stroke="rgba(255,204,0,0.5)" stroke-width="2" stroke-dasharray="8,4"><animate attributeName="stroke-dashoffset" from="0" to="-24" dur="1s" repeatCount="indefinite"/></line>
          <line x1="130" y1="220" x2="280" y2="150" stroke="rgba(0,212,255,0.5)" stroke-width="2" stroke-dasharray="8,4"><animate attributeName="stroke-dashoffset" from="0" to="-24" dur="1.2s" repeatCount="indefinite"/></line>
          <line x1="380" y1="150" x2="480" y2="80" stroke="rgba(0,255,136,0.5)" stroke-width="2" stroke-dasharray="8,4"><animate attributeName="stroke-dashoffset" from="0" to="-24" dur="0.8s" repeatCount="indefinite"/></line>
          <line x1="380" y1="150" x2="480" y2="220" stroke="rgba(168,85,247,0.5)" stroke-width="2" stroke-dasharray="8,4"><animate attributeName="stroke-dashoffset" from="0" to="-24" dur="1.1s" repeatCount="indefinite"/></line>
          <line x1="380" y1="150" x2="620" y2="150" stroke="rgba(255,140,0,0.5)" stroke-width="2" stroke-dasharray="8,4"><animate attributeName="stroke-dashoffset" from="0" to="-24" dur="0.9s" repeatCount="indefinite"/></line>
        </svg>

        <div class="topo-node" style="left:60px;top:40px;">
          <div class="topo-node-icon solar">☀️</div>
          <div class="topo-node-label">Solar PV</div>
          <div class="topo-node-value" id="topo-solar-val">${d.solar.toFixed(1)} kW</div>
        </div>
        <div class="topo-node" style="left:60px;top:185px;">
          <div class="topo-node-icon load" style="border-color:rgba(0,212,255,0.6)">💨</div>
          <div class="topo-node-label">Wind Turbine</div>
          <div class="topo-node-value" id="live-wind">${(d.wind || 12.3).toFixed(1)} kW</div>
        </div>
        <div class="topo-node" style="left:290px;top:108px;">
          <div class="topo-node-icon controller" style="width:80px;height:80px;font-size:32px;border-radius:50%;">⚡</div>
          <div class="topo-node-label">Smart Controller</div>
          <div class="topo-node-value">ACTIVE</div>
        </div>
        <div class="topo-node" style="left:490px;top:40px;">
          <div class="topo-node-icon battery">🔋</div>
          <div class="topo-node-label">Battery Storage</div>
          <div class="topo-node-value" id="topo-batt-val">${d.battery.toFixed(0)}%</div>
        </div>
        <div class="topo-node" style="left:490px;top:185px;">
          <div class="topo-node-icon load">⚙️</div>
          <div class="topo-node-label">Load Center</div>
          <div class="topo-node-value" id="topo-load-val">${d.load.toFixed(1)} kW</div>
        </div>
        <div class="topo-node" style="left:635px;top:108px;">
          <div class="topo-node-icon grid">🏭</div>
          <div class="topo-node-label">Utility Grid</div>
          <div class="topo-node-value" id="topo-grid-val">${(d.gridExport || 0).toFixed(1)} kW</div>
        </div>
      </div>
    </div>

    <div class="grid-3">
      <div class="card">
        <div class="card-title" style="margin-bottom:14px;"><i class="fas fa-wave-square icon"></i>&nbsp; Grid Parameters</div>
        <div class="data-row"><span class="data-row-label">Voltage (L-N)</span><span class="data-row-value cyan" id="live-voltage">${d.voltage.toFixed(1)} V</span></div>
        <div class="data-row"><span class="data-row-label">Frequency</span><span class="data-row-value cyan" id="live-freq">${d.frequency.toFixed(3)} Hz</span></div>
        <div class="data-row"><span class="data-row-label">Power Factor</span><span class="data-row-value green">0.97</span></div>
        <div class="data-row"><span class="data-row-label">THD</span><span class="data-row-value">2.1%</span></div>
        <div class="data-row"><span class="data-row-label">Apparent Power</span><span class="data-row-value">${(d.load * 1.03).toFixed(1)} kVA</span></div>
        <div class="data-row"><span class="data-row-label">Reactive Power</span><span class="data-row-value yellow">3.2 kVAR</span></div>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:14px;"><i class="fas fa-sync-alt icon"></i>&nbsp; Synchronization</div>
        <div class="data-row"><span class="data-row-label">Sync Status</span><span class="data-row-value green">✓ Synchronized</span></div>
        <div class="data-row"><span class="data-row-label">Phase Angle</span><span class="data-row-value">0.3°</span></div>
        <div class="data-row"><span class="data-row-label">Voltage Match</span><span class="data-row-value green">99.8%</span></div>
        <div class="data-row"><span class="data-row-label">Freq. Deviation</span><span class="data-row-value cyan">${(d.frequency-50).toFixed(3)} Hz</span></div>
        <div class="data-row"><span class="data-row-label">PCC Breaker</span><span class="data-row-value green">CLOSED</span></div>
        <div class="data-row"><span class="data-row-label">Sync Timer</span><span class="data-row-value">42 ms</span></div>
        <hr class="divider">
        <div style="display:flex;gap:8px;">
          <button class="btn btn-danger btn-sm" style="flex:1;" onclick="addLog('warning','system','Manual island mode triggered');setMode('island',null)"><i class="fas fa-plug"></i> Island</button>
          <button class="btn btn-success btn-sm" style="flex:1;" onclick="addLog('success','system','Grid reconnection initiated');setMode('grid-connected',null)"><i class="fas fa-link"></i> Reconnect</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:14px;"><i class="fas fa-shield-alt icon"></i>&nbsp; Protection Status</div>
        <div class="data-row"><span class="data-row-label">OVP</span><span class="data-row-value green">Normal</span></div>
        <div class="data-row"><span class="data-row-label">UVP</span><span class="data-row-value green">Normal</span></div>
        <div class="data-row"><span class="data-row-label">OFP</span><span class="data-row-value green">Normal</span></div>
        <div class="data-row"><span class="data-row-label">UFP</span><span class="data-row-value green">Normal</span></div>
        <div class="data-row"><span class="data-row-label">OCP</span><span class="data-row-value green">Normal</span></div>
        <div class="data-row"><span class="data-row-label">Anti-Islanding</span><span class="data-row-value cyan">Active</span></div>
      </div>
    </div>
  </div>`;
}

// ── SECURITY PAGE ─────────────────────────────────────────
function renderSecurityPage() {
  const el = document.getElementById('page-security');
  if (!el) return;
  const unreadCount = STATE.alerts.filter(a=>!a.read).length;
  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">Security Center</div>
        <div class="section-subtitle">Cybersecurity monitoring — IDS, encryption, access control &amp; alerts</div>
      </div>
      <button class="btn btn-primary" onclick="markAllAlertsRead()"><i class="fas fa-check-double"></i> Mark All Read</button>
    </div>

    <div class="grid-4" style="margin-bottom:20px;">
      <div class="kpi-card green">
        <div class="kpi-icon green"><i class="fas fa-lock"></i></div>
        <div class="kpi-value">TLS<span class="kpi-unit"> 1.3</span></div>
        <div class="kpi-label">Encryption Protocol</div>
        <div class="kpi-trend up"><i class="fas fa-check"></i> All channels secured</div>
      </div>
      <div class="kpi-card red">
        <div class="kpi-icon red"><i class="fas fa-exclamation-triangle"></i></div>
        <div class="kpi-value">${unreadCount}<span class="kpi-unit"> open</span></div>
        <div class="kpi-label">Active Alerts</div>
        <div class="kpi-trend ${unreadCount>0?'down':'up'}"><i class="fas fa-bell"></i> ${unreadCount} unread</div>
      </div>
      <div class="kpi-card cyan">
        <div class="kpi-icon cyan"><i class="fas fa-network-wired"></i></div>
        <div class="kpi-value">4<span class="kpi-unit"> conn</span></div>
        <div class="kpi-label">Active Connections</div>
        <div class="kpi-trend stable"><i class="fas fa-users"></i> Monitored</div>
      </div>
      <div class="kpi-card purple">
        <div class="kpi-icon purple"><i class="fas fa-key"></i></div>
        <div class="kpi-value">JWT<span class="kpi-unit"> valid</span></div>
        <div class="kpi-label">Auth Token</div>
        <div class="kpi-trend up"><i class="fas fa-clock"></i> Expires in 23m</div>
      </div>
    </div>

    <div class="grid-2" style="margin-bottom:20px;">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-shield-alt icon"></i> Encryption &amp; Security Modules</div>
          <div class="status-indicator online">ALL SECURE</div>
        </div>
        ${[
          ['TLS 1.3 Transport Layer', true, 'AES-256-GCM'],
          ['JWT Authentication', true, 'HS256 / RS256'],
          ['MQTT over TLS (Port 8883)', true, 'Broker secured'],
          ['Data Integrity Check (HMAC)', true, 'SHA-256'],
          ['Role-Based Access Control', true, 'RBAC enforced'],
          ['Intrusion Detection System', true, 'ML-based IDS'],
          ['DDoS Protection', true, 'Rate limited'],
          ['Firewall Rules', true, '32 rules active'],
        ].map(([name, status, note]) => `
          <div class="enc-status" style="${status?'':'background:rgba(255,51,102,0.07);border-color:rgba(255,51,102,0.2);color:var(--accent-red);'}">
            <i class="fas ${status?'fa-lock':'fa-lock-open'}"></i>
            <span style="flex:1;">${name}</span>
            <span style="font-size:11px;opacity:0.7;">${note}</span>
          </div>`).join('')}
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-bell icon"></i> Security Alerts</div>
          <span style="font-size:12px;color:var(--text-muted);">${STATE.alerts.length} total</span>
        </div>
        <div style="max-height:380px;overflow-y:auto;">
          ${STATE.alerts.map(a => `
            <div class="alert-item ${a.type}" onclick="markAlertRead(${a.id})" style="${a.read?'opacity:0.5':''}">
              <div class="alert-icon"><i class="fas ${a.type==='critical'?'fa-radiation-alt':a.type==='warning'?'fa-exclamation-triangle':a.type==='success'?'fa-check-circle':'fa-info-circle'}"></i></div>
              <div style="flex:1;">
                <div class="alert-title">${a.read?'':'<span style="width:7px;height:7px;background:var(--accent-red);border-radius:50%;display:inline-block;margin-right:6px;"></span>'}${a.title}</div>
                <div class="alert-desc">${a.desc}</div>
              </div>
              <div class="alert-time">${a.time}</div>
            </div>`).join('')}
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fas fa-satellite-dish icon"></i> MQTT Communication &amp; Protocol Security</div>
      </div>
      <div class="grid-3">
        <div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">Broker Status</div>
          <div class="data-row"><span class="data-row-label">Host</span><span class="data-row-value cyan">broker.microgrid.local</span></div>
          <div class="data-row"><span class="data-row-label">Port</span><span class="data-row-value">8883 (TLS)</span></div>
          <div class="data-row"><span class="data-row-label">Protocol</span><span class="data-row-value cyan">MQTT v5.0</span></div>
          <div class="data-row"><span class="data-row-label">Status</span><span class="data-row-value green">✓ Connected</span></div>
        </div>
        <div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">Active Subscriptions</div>
          ${['microgrid/solar/+','microgrid/battery/#','microgrid/grid/status','microgrid/alerts','microgrid/security/ids'].map(t=>`
            <div class="data-row"><span class="data-row-label" style="font-family:'JetBrains Mono',monospace;font-size:12px;">${t}</span><span class="data-row-value green" style="font-size:11px;">QoS 2</span></div>`).join('')}
        </div>
        <div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">Message Statistics</div>
          <div class="data-row"><span class="data-row-label">Msgs Received</span><span class="data-row-value">14,827</span></div>
          <div class="data-row"><span class="data-row-label">Msgs Sent</span><span class="data-row-value">8,392</span></div>
          <div class="data-row"><span class="data-row-label">Dropped</span><span class="data-row-value green">0</span></div>
          <div class="data-row"><span class="data-row-label">Latency</span><span class="data-row-value cyan">12 ms</span></div>
          <div class="data-row"><span class="data-row-label">Uptime</span><span class="data-row-value green">99.97%</span></div>
        </div>
      </div>
    </div>
  </div>`;
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

  const anomalies = [
    { name:'FDIA — False Data Injection', score: (d.threatScore || 18) > 70 ? rnd(75,95,0) : rnd(5,20,0), detected: (d.threatScore || 18) > 70 },
    { name:'DoS / DDoS Attack Pattern',    score: rnd(5,15,0),   detected: false },
    { name:'Man-in-the-Middle Attempt',    score: rnd(3,12,0),   detected: false },
    { name:'Replay Attack Signature',      score: rnd(8,18,0),   detected: false },
    { name:'Voltage Anomaly (sensor)',     score: (d.threatScore || 18) > 60 ? rnd(60,80,0) : rnd(10,25,0), detected: (d.threatScore || 18) > 60 },
    { name:'Unauthorized Device Access',   score: rnd(5,18,0),   detected: false },
  ];

  el.innerHTML = `
  <div style="padding:24px;">
    <div class="section-header">
      <div>
        <div class="section-title">Anomaly Detection</div>
        <div class="section-subtitle">ML-based intrusion detection system — Scikit-learn anomaly classifier</div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn btn-primary" onclick="runAnomalyScan()"><i class="fas fa-search"></i> Run Scan</button>
        <button class="btn btn-success" onclick="addLog('success','security','IDS model retrained with new baseline data')"><i class="fas fa-brain"></i> Retrain Model</button>
      </div>
    </div>

    <div class="card" style="margin-bottom:20px;">
      <div class="card-header">
        <div class="card-title"><i class="fas fa-radiation-alt icon"></i> Threat Level Assessment</div>
        <span class="status-indicator ${(d.threatScore || 18) > 70 ? 'offline' : (d.threatScore || 18) > 40 ? 'warning' : 'online'}">
          ${(d.threatScore || 18) > 70 ? '⚠ HIGH RISK' : (d.threatScore || 18) > 40 ? '! MEDIUM' : '✓ LOW RISK'}
        </span>
      </div>
      <div style="display:flex;align-items:center;gap:20px;">
        <div style="flex:1;">
          <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-secondary);margin-bottom:6px;">
            <span>Threat Score</span>
            <span id="live-threat">${(d.threatScore || 18).toFixed(0)} / 100</span>
          </div>
          <div style="height:16px;background:rgba(0,0,0,0.4);border-radius:8px;overflow:hidden;border:1px solid var(--border-color);">
            <div style="height:100%;width:${(d.threatScore || 18)}%;background:linear-gradient(90deg,#00ff88 0%,#ffcc00 50%,#ff3366 100%);border-radius:8px;transition:width 1s;" id="threat-fill"></div>
          </div>
          <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);margin-top:4px;">
            <span>0 — SAFE</span><span>50 — MODERATE</span><span>100 — CRITICAL</span>
          </div>
        </div>
        <div style="width:140px;">
          <div class="chart-wrapper sm"><canvas id="chart-threat"></canvas></div>
        </div>
      </div>
    </div>

    <div class="grid-2" style="margin-bottom:20px;">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-bug icon"></i> Anomaly Detectors</div>
          <span style="font-size:12px;color:var(--text-muted)">ML threshold: 50/100</span>
        </div>
        ${anomalies.map(a => `
          <div class="anomaly-item ${a.detected ? 'detected' : ''}">
            <div class="anomaly-score">${a.score}</div>
            <div style="flex:1;">
              <div style="font-size:13px;font-weight:600;color:${a.detected?'var(--accent-red)':'var(--text-primary)'};">${a.name}</div>
              <div class="threat-meter" style="margin-top:6px;">
                <div class="threat-fill" style="width:${a.score}%;${a.detected?'background:var(--accent-red);':''}"></div>
              </div>
            </div>
            <span class="status-indicator ${a.detected?'offline':'online'}" style="font-size:11px;padding:3px 8px;">${a.detected?'DETECTED':'NORMAL'}</span>
          </div>`).join('')}
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title"><i class="fas fa-brain icon"></i> ML Model Status</div>
          <div class="status-indicator online">ACTIVE</div>
        </div>
        <div class="data-row"><span class="data-row-label">Algorithm</span><span class="data-row-value cyan">Isolation Forest</span></div>
        <div class="data-row"><span class="data-row-label">Accuracy</span><span class="data-row-value green">94.7%</span></div>
        <div class="data-row"><span class="data-row-label">False Positive Rate</span><span class="data-row-value yellow">2.1%</span></div>
        <div class="data-row"><span class="data-row-label">Training Samples</span><span class="data-row-value">48,320</span></div>
        <div class="data-row"><span class="data-row-label">Features Used</span><span class="data-row-value">12</span></div>
        <div class="data-row"><span class="data-row-label">Last Trained</span><span class="data-row-value">2 hours ago</span></div>
        <div class="data-row"><span class="data-row-label">Framework</span><span class="data-row-value">Scikit-learn 1.4</span></div>
        <div class="data-row"><span class="data-row-label">Next Retrain</span><span class="data-row-value">in 22 hours</span></div>
        <hr class="divider">
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">Feature Importance</div>
        ${[['Voltage deviation','82%','cyan'],['Frequency delta','71%','green'],['Packet rate','65%','yellow'],['Login patterns','58%','purple'],['Load profile','47%','orange']].map(([f,v,c])=>`
          <div class="progress-bar-wrapper">
            <div class="progress-label"><span>${f}</span><span>${v}</span></div>
            <div class="progress-bar-bg"><div class="progress-bar-fill ${c}" style="width:${v}"></div></div>
          </div>`).join('')}
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title"><i class="fas fa-flask icon"></i> Attack Simulation Scenarios</div>
        <span style="font-size:12px;color:var(--text-muted)">For testing purposes only</span>
      </div>
      <div class="grid-3">
        ${[
          { name:'Simulate FDIA', icon:'fa-database', color:'red', desc:'False data injection on voltage sensors', action:"simulateAttack('FDIA')" },
          { name:'Simulate DoS',  icon:'fa-tachometer-alt', color:'yellow', desc:'Flood MQTT broker with fake packets', action:"simulateAttack('DoS')" },
          { name:'Simulate Brute Force', icon:'fa-user-secret', color:'purple', desc:'Automated password attack on API', action:"simulateAttack('BruteForce')" },
        ].map(s=>`
          <div style="padding:16px;background:rgba(0,0,0,0.3);border-radius:10px;border:1px solid var(--border-color);">
            <div style="font-size:20px;margin-bottom:8px;color:var(--accent-${s.color});"><i class="fas ${s.icon}"></i></div>
            <div style="font-size:14px;font-weight:600;margin-bottom:4px;">${s.name}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">${s.desc}</div>
            <button class="btn btn-danger btn-sm" onclick="${s.action}"><i class="fas fa-play"></i> Simulate</button>
          </div>`).join('')}
      </div>
    </div>
  </div>`;

  setTimeout(() => {
    makeChart('chart-threat', 'line', CHART_LABELS, [
      { data: STATE.history.threat, borderColor:'#ff3366', backgroundColor:'rgba(255,51,102,0.1)', tension:0.4, fill:true, borderWidth:2, pointRadius:0 }
    ], { yScale: { min:0, max:100 } });
  }, 50);
}

function runAnomalyScan() {
  addLog('info', 'security', 'Full anomaly scan initiated — IDS running Isolation Forest classifier');
  setTimeout(() => {
    const score = STATE.data.threatScore || 18;
    if (score > 60) {
      addLog('critical', 'security', `Anomaly scan complete — Threat score: ${score.toFixed(0)}/100 — Anomalies detected!`);
      addAlert('critical', 'Anomaly Scan Alert', `IDS detected potential threats. Score: ${score.toFixed(0)}/100`);
    } else {
      addLog('success', 'security', `Anomaly scan complete — No significant threats detected. Score: ${score.toFixed(0)}/100`);
    }
    renderAnomalyPage();
  }, 1500);
}

function simulateAttack(type) {
  STATE.data.threatScore = Math.min(100, (STATE.data.threatScore || 18) + rnd(30,50,0));
  addLog('critical', 'security', `[SIMULATION] ${type} attack initiated — IDS activated`);
  addAlert('critical', `[SIMULATION] ${type} Attack Detected`, `Simulated ${type} attack triggered. IDS countermeasures engaged.`);
  renderAnomalyPage();
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
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc3ODMxNDcyMH0.6af4oaM7ReCp1eawiThaDNYu7t0iHL9MadeKNivgPz4';
    const res = await fetch('https://microgrid-final.onrender.com/anomalies/', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    const data = await res.json();
    console.log('Real anomalies:', data);
    if (Array.isArray(data) && data.length > 0) {
      STATE.data.anomalies = data;
        STATE.data.threatScore = Math.min(100, data.length * 10);
        const threatEl = document.getElementById('live-threat');
        const threatFill = document.getElementById('threat-fill');
        const score = STATE.data.threatScore;
        if (threatEl) threatEl.textContent = score.toFixed(0) + ' / 100';
        if (threatFill) threatFill.style.width = score + '%';
    }
  } catch(e) {
    console.error('Failed to fetch anomalies:', e);
  }
}

document.addEventListener('DOMContentLoaded', () => { fetchRealAnomalies(); setInterval(fetchRealAnomalies, 10000); });

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

  client.on('message', (topic, message) => {
    try {
      const data = JSON.parse(message.toString());
      console.log('MQTT message:', topic, data);
      // Wire real data into app state
      if (topic === 'microgrid/solar')    state.data.solar       = data.value ?? data.power ?? state.data.solar;
      if (topic === 'microgrid/wind')     state.data.wind        = data.value ?? data.power ?? state.data.wind;
      if (topic === 'microgrid/battery')  state.data.battery     = data.value ?? data.soc   ?? state.data.battery;
      if (topic === 'microgrid/load')     state.data.load        = data.value ?? data.power ?? state.data.load;
      if (topic === 'microgrid/grid')     { state.data.gridExport = data.export ?? state.data.gridExport; state.data.gridImport = data.import ?? state.data.gridImport; }
      if (topic === 'microgrid/voltage')  state.data.voltage     = data.value ?? state.data.voltage;
      if (topic === 'microgrid/frequency')state.data.frequency   = data.value ?? state.data.frequency;
      if (topic === 'microgrid/status')   state.data.mode        = data.mode  ?? state.data.mode;
    } catch(e) {
      console.log('MQTT raw:', topic, message.toString());
    }
  });

  client.on('error', (err) => {
    console.error('MQTT error:', err);
  });
}

document.addEventListener('DOMContentLoaded', initMQTT);
