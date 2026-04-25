// ── Auth Enforcement ────────────────────────────────────────────────────────
if (!sessionStorage.getItem('jwt')) {
  window.location.href = '/login/';
}

window.logout = function() {
  sessionStorage.clear();
  window.location.href = '/login/';
};

function syncUserProfile() {
  const username = sessionStorage.getItem('username') || 'Guest';
  const role = sessionStorage.getItem('role') || 'viewer';
  
  const avatar = document.querySelector('.user-profile .avatar');
  const nameEl = document.querySelector('.user-profile div div:first-child');
  const roleEl = document.querySelector('.user-profile div div:last-child');
  
  if (avatar) avatar.textContent = username.charAt(0).toUpperCase();
  if (nameEl) nameEl.textContent = username;
  if (roleEl) roleEl.textContent = role.toUpperCase();

  if (role !== 'admin') {
    const navApis = document.getElementById('nav-apis');
    if (navApis) navApis.style.display = 'none';
    const navSettings = document.getElementById('nav-settings');
    if (navSettings) navSettings.style.display = 'none';
  }
}
document.addEventListener('DOMContentLoaded', syncUserProfile);

// ── Socket.io connection ────────────────────────────────────────────────────
const socket = io('http://localhost:3000');

// ── State ───────────────────────────────────────────────────────────────────
const state = {
  rps: 0, totalReq: 0, failedReq: 0,
  threats: { RATE_LIMIT: 0, RATE_ABUSE: 0, BRUTE_FORCE: 0, DOS_ATTACK: 0, IP_BLOCKED: 0, BLOCKED_IP_ACCESS: 0, BROKEN_AUTH: 0 },
  totalThreats: 0, blocked: 0
};
const statusCounts = { '2xx': 0, '4xx': 0, '5xx': 0 };

// ── DOM refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── View navigation ─────────────────────────────────────────────────────────
function switchView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  
  const viewEl = $(`view-${name}`);
  const navEl = $(`nav-${name}`);
  
  if (viewEl) viewEl.classList.add('active');
  if (navEl) navEl.classList.add('active');
  
  if (name === 'logs') fetchLogs();
  if (name === 'apis') fetchApis();
}

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

// ── Socket.io status ────────────────────────────────────────────────────────
socket.on('connect', () => {
  $('connDot').className   = 'dot connected';
  $('connLabel').textContent = 'Connected';
});
socket.on('disconnect', () => {
  $('connDot').className   = 'dot error';
  $('connLabel').textContent = 'Disconnected';
});

// ── Traffic chart (line) ─────────────────────────────────────────────────────
const trafficCtx = $('trafficChart').getContext('2d');
const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#39ff14';
const tGrad = trafficCtx.createLinearGradient(0, 0, 0, 260);
tGrad.addColorStop(0, accentColor + '55');
tGrad.addColorStop(1, 'transparent');

const trafficChart = new Chart(trafficCtx, {
  type: 'line',
  data: {
    labels:   Array(30).fill(''),
    datasets: [{
      label: 'req/s',
      data:  Array(30).fill(0),
      borderColor: accentColor,
      backgroundColor: tGrad,
      borderWidth: 2.5,
      tension: 0.4,
      fill: true,
      pointRadius: 0,
      pointHoverRadius: 5
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false, animation: { duration: 200 },
    plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
    scales: {
      y: { beginAtZero: true, grid: { color: '#e4e7f0' }, ticks: { font: { family: 'Inter', size: 11 }, color: '#7c859e' } },
      x: { grid: { display: false }, ticks: { display: false } }
    }
  }
});

// ── Status doughnut chart ────────────────────────────────────────────────────
const statusCtx = $('statusChart').getContext('2d');
const statusChart = new Chart(statusCtx, {
  type: 'doughnut',
  data: {
    labels: ['2xx OK', '4xx Error', '5xx Server'],
    datasets: [{ data: [1, 0, 0], backgroundColor: [accentColor, '#f59e0b', '#ef4444'], borderWidth: 0, hoverOffset: 4 }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    cutout: '68%',
    plugins: { legend: { position: 'bottom', labels: { font: { family: 'Inter', size: 11 }, padding: 8 } } }
  }
});

// ── 1-second ticker: push RPS to chart ───────────────────────────────────────
setInterval(() => {
  const data = trafficChart.data.datasets[0].data;
  data.push(state.rps);
  data.shift();
  trafficChart.update();

  $('kRps').textContent = state.rps;
  state.rps = 0;

  // Status doughnut
  statusChart.data.datasets[0].data = [statusCounts['2xx'] || 0, statusCounts['4xx'] || 0, statusCounts['5xx'] || 0];
  statusChart.update();

  // Success rate
  const rate = state.totalReq ? Math.max(0, Math.round((1 - state.failedReq / state.totalReq) * 100)) : 100;
  const kS = $('kSuccess');
  kS.textContent = rate + '%';
  kS.style.color = rate < 90 ? '#ef4444' : rate < 98 ? '#f59e0b' : '';
}, 1000);

// ── Metrics block ─────────────────────────────────────────────────────────────
socket.on('metrics_update', data => {
  const kRegApis = document.getElementById('kRegApis');
  const kDynTraffic = document.getElementById('kDynTraffic');
  if (kRegApis && data.registeredApis !== undefined) {
    kRegApis.textContent = data.registeredApis;
  }
  if (kDynTraffic && data.dynamicTraffic !== undefined) {
    kDynTraffic.textContent = data.dynamicTraffic;
  }
});

// ── Traffic event ─────────────────────────────────────────────────────────────
socket.on('traffic', data => {
  state.rps++;
  state.totalReq++;

  const s = data.status;
  if      (s >= 500) { statusCounts['5xx']++; state.failedReq++; }
  else if (s >= 400) { statusCounts['4xx']++; state.failedReq++; }
  else               { statusCounts['2xx']++; }

  // Update chart chip based on RPS
  const chip = $('chartMode');
  if (state.rps > 30)      { chip.textContent = 'UNDER ATTACK'; chip.className = 'chip danger'; }
  else if (state.rps > 10) { chip.textContent = 'ELEVATED';     chip.className = 'chip warning'; }
  else                     { chip.textContent = 'NORMAL';       chip.className = 'chip'; }
});

// ── Threat event ──────────────────────────────────────────────────────────────
socket.on('threat', data => {
  state.totalThreats++;
  state.threats[data.type] = (state.threats[data.type] || 0) + 1;
  if (data.type === 'IP_BLOCKED') state.blocked++;

  // Update KPIs
  $('kThreats').textContent = state.totalThreats;
  $('kBlocked').textContent = state.blocked;
  
  // Update badge
  const badge = $('threatBadge');
  badge.textContent = state.totalThreats;

  // Update threat type counters
  $('tc-rateLimit').textContent  = state.threats.RATE_LIMIT   || 0;
  $('tc-rateAbuse').textContent  = state.threats.RATE_ABUSE   || 0;
  $('tc-brute').textContent      = state.threats.BRUTE_FORCE  || 0;
  $('tc-dos').textContent        = state.threats.DOS_ATTACK   || 0;
  $('tc-blocked').textContent    = state.blocked;

  // Refresh actual blocked IPs count from gateway
  fetch('http://localhost:3000/api/blocked-ips')
    .then(r => r.json())
    .then(list => { state.blocked = list.length; $('kBlocked').textContent = state.blocked; $('tc-blocked').textContent = state.blocked; })
    .catch(() => {});

  const item = makeEventItem(data);

  // Overview panel (latest 5)
  const oe = $('overviewEvents');
  const emptyOe = oe.querySelector('.empty');
  if (emptyOe) emptyOe.remove();
  oe.insertBefore(item.cloneNode(true), oe.firstChild);
  while (oe.children.length > 5) oe.lastChild.remove();

  // All threats panel
  const at = $('allThreats');
  const emptyAt = at.querySelector('.empty');
  if (emptyAt) emptyAt.remove();
  
  // Give it an ID so we can update it later if it doesn't have one
  const safeId = data.ip ? data.ip.replace(/[^a-zA-Z0-9]/g, '-') : 'unknown';
  const existing = document.getElementById(`live-threat-${safeId}`);
  if (existing) {
     existing.remove(); // Remove old one to bump it to the top
  }
  item.id = `live-threat-${safeId}`;
  
  at.insertBefore(item, at.firstChild);
  while (at.children.length > 200) at.lastChild.remove();
});

// ── Live Score Update (Efficient Real-Time) ──────────────────────────────────
socket.on('score_update', data => {
  const safeId = data.entityId.replace(/[^a-zA-Z0-9]/g, '-');
  let div = document.getElementById(`live-threat-${safeId}`);
  
  if (!div) {
    if (data.finalScore <= 5) return; // Ignore very low noise
    
    // Create new tracking item
    const mockData = {
      type: data.level || 'SUSPICIOUS',
      ip: data.entityId,
      time: Date.now(),
      reason: data.reason || 'Monitoring...',
      status: '---',
      ruleScore: data.ruleScore,
      mlScore: data.mlScore,
      score: data.finalScore
    };
    div = makeEventItem(mockData);
    div.id = `live-threat-${safeId}`;
    
    const at = $('allThreats');
    const emptyAt = at.querySelector('.empty');
    if (emptyAt) emptyAt.remove();
    at.insertBefore(div, at.firstChild);
    while (at.children.length > 50) at.lastChild.remove();
  } else {
    // Efficiently update existing DOM element in-place
    const scoresHtml = `
      <div class="threat-scores">
        <span title="Rule Score" style="color:var(--amber); border:1px solid var(--border); padding:2px 6px; border-radius:4px; font-size:0.62rem;">Rules: ${data.ruleScore}</span>
        <span title="Machine Learning Score" style="color:var(--purple); border:1px solid var(--border); padding:2px 6px; border-radius:4px; font-size:0.62rem;">ML: ${data.mlScore}</span>
        <span title="Final Hybrid Risk Score" style="color:var(--red); font-weight:700; padding:2px 6px; border-radius:4px; font-size:0.65rem; background:rgba(239,68,68,0.1);">Risk: ${data.finalScore}</span>
      </div>
    `;
    const bodyEl = div.querySelector('.event-body');
    const existingScores = bodyEl.querySelector('.threat-scores');
    if (existingScores) existingScores.outerHTML = scoresHtml;
    else bodyEl.insertAdjacentHTML('beforeend', scoresHtml);
    
    if (data.reason) {
      const reasonEl = div.querySelector('.event-body > div:nth-child(2)');
      if (reasonEl) reasonEl.textContent = data.reason;
    }
  }
});

function makeEventItem(data) {
  const div = document.createElement('div');
  div.className = 'event-item';
  const tagClass = data.type || 'RATE_LIMIT';
  const statusColor = data.status >= 500 ? 'status-err' : 'status-lim';
  
  // Format hybrid scores if they exist
  let scoresHtml = '';
  if (data.ruleScore !== undefined) {
    scoresHtml = `
      <div class="threat-scores">
        <span title="Rule Score" style="color:var(--amber); border:1px solid var(--border); padding:2px 6px; border-radius:4px; font-size:0.62rem;">Rules: ${data.ruleScore}</span>
        <span title="Machine Learning Score" style="color:var(--purple); border:1px solid var(--border); padding:2px 6px; border-radius:4px; font-size:0.62rem;">ML: ${data.mlScore}</span>
        <span title="Final Hybrid Risk Score" style="color:var(--red); font-weight:700; padding:2px 6px; border-radius:4px; font-size:0.65rem; background:rgba(239,68,68,0.1);">Risk: ${data.score}</span>
      </div>
    `;
  }

  div.innerHTML = `
    <span class="event-tag ${tagClass}">${data.type.replace(/_/g,' ')}</span>
    <div class="event-body" style="width:100%;">
      <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <div class="event-ip">${data.ip}</div>
        <div class="event-meta" style="font-size:0.6rem;">${new Date(data.time).toLocaleTimeString()}</div>
      </div>
      <div style="font-size:0.7rem; color:var(--muted); margin-top:2px;">${data.reason || 'Suspicious request'}</div>
      ${scoresHtml}
    </div>
    <div class="event-status ${statusColor}">${data.status}</div>
  `;
  return div;
}

// ── Log table ─────────────────────────────────────────────────────────────────
async function fetchLogs() {
  try {
    const res  = await fetch('http://localhost:3000/logs');
    const logs = await res.json();
    const tbody = $('logTableBody');
    if (!logs.length) { tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No logs yet</td></tr>'; return; }
    tbody.innerHTML = logs.map(l => {
      const sc = l.status >= 500 ? 'status-err' : l.status >= 400 ? 'status-lim' : 'status-ok';
      return `<tr>
        <td>${new Date(l.timestamp).toLocaleTimeString()}</td>
        <td style="font-family:monospace">${l.ip}</td>
        <td>${l.method}</td>
        <td>${l.endpoint}</td>
        <td class="${sc}">${l.status}</td>
        <td>${l.threatType !== 'NONE' ? `<span class="event-tag ${l.threatType}">${l.threatType.replace(/_/g,' ')}</span>` : '—'}</td>
      </tr>`;
    }).join('');
  } catch(e) {
    $('logTableBody').innerHTML = '<tr><td colspan="6" class="empty-cell">Could not load logs</td></tr>';
  }
}

// ── Clear threats ─────────────────────────────────────────────────────────────
function clearThreats() {
  $('allThreats').innerHTML = '<div class="empty">No threats detected yet.</div>';
  $('overviewEvents').innerHTML = '<div class="empty">No threats detected yet.</div>';
  state.totalThreats = 0; state.blocked = 0;
  Object.keys(state.threats).forEach(k => state.threats[k] = 0);
  $('kThreats').textContent = 0; $('kBlocked').textContent = 0;
  $('threatBadge').textContent = 0;
  ['tc-rateLimit','tc-rateAbuse','tc-brute','tc-dos','tc-blocked'].forEach(id => $(id).textContent = 0);
}

// ── Dynamic APIs ──────────────────────────────────────────────────────────────
async function fetchApis() {
  try {
    const res = await fetch('http://localhost:3000/admin/list-apis', {
      headers: { 'Authorization': `Bearer ${sessionStorage.getItem('jwt')}` }
    });
    if (!res.ok) throw new Error('Failed to fetch APIs');
    const apis = await res.json();
    
    const list = $('apiList');
    if (!apis.length) {
      list.innerHTML = '<div class="empty">No dynamic APIs registered yet.</div>';
      return;
    }
    
    list.innerHTML = apis.map(api => `
      <div style="border: 1px solid var(--border); border-radius: 8px; padding: 12px; background: var(--bg);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <div style="font-weight: 700; font-size: 0.9rem;">${api.name}</div>
            <div style="font-family: var(--mono); font-size: 0.75rem; color: var(--muted); margin-top: 2px;">Proxy: /api/external/${api.name}</div>
            <div style="font-family: var(--mono); font-size: 0.75rem; color: var(--blue); margin-top: 2px;">Target: ${api.target}</div>
          </div>
          <span class="chip ${api.enabled ? '' : 'danger'}" style="font-size: 0.65rem;">${api.enabled ? 'ACTIVE' : 'DISABLED'}</span>
        </div>
        ${api.hasKey ? '<div style="font-size: 0.7rem; color: var(--green); margin-top: 8px;">✓ API Key Configured</div>' : ''}
      </div>
    `).join('');
  } catch (err) {
    $('apiList').innerHTML = '<div class="empty" style="color:var(--red);">Error loading APIs</div>';
  }
}

async function registerApi(e) {
  e.preventDefault();
  const alertBox = $('apiAlert');
  alertBox.style.display = 'none';
  
  const btn = $('apiSubmitBtn');
  btn.disabled = true;
  btn.textContent = 'Registering...';
  
  const data = {
    name: $('apiName').value.trim(),
    target: $('apiTarget').value.trim(),
    apiKey: $('apiKey').value.trim(),
    headerName: $('apiHeader').value.trim()
  };
  
  try {
    const res = await fetch('http://localhost:3000/admin/register-api', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${sessionStorage.getItem('jwt')}`
      },
      body: JSON.stringify(data)
    });
    
    const result = await res.json();
    if (!res.ok) throw new Error(result.error || 'Failed to register API');
    
    alertBox.style.display = 'block';
    alertBox.style.background = 'var(--green-bg)';
    alertBox.style.color = 'var(--green)';
    alertBox.style.border = '1px solid rgba(16,201,132,.3)';
    alertBox.textContent = '✅ API successfully registered!';
    
    // Clear form
    e.target.reset();
    fetchApis();
  } catch (err) {
    alertBox.style.display = 'block';
    alertBox.style.background = 'var(--red-bg)';
    alertBox.style.color = 'var(--red)';
    alertBox.style.border = '1px solid rgba(239,68,68,.3)';
    alertBox.textContent = '❌ ' + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = '➕ Register API';
  }
}

socket.on('api_registered', (apis) => {
    if ($('view-apis') && $('view-apis').classList.contains('active')) {
    fetchApis();
  }
});

// ── Theme Sync ──
window.addEventListener('storage', (e) => {
  if (e.key === 'theme') {
    location.reload();
  }
});
