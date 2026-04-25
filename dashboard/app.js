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
  $(`view-${name}`).classList.add('active');
  $(`nav-${name}`).classList.add('active');
  if (name === 'logs') fetchLogs();
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
const tGrad = trafficCtx.createLinearGradient(0, 0, 0, 260);
tGrad.addColorStop(0, 'rgba(79,110,247,.35)');
tGrad.addColorStop(1, 'rgba(79,110,247,.00)');

const trafficChart = new Chart(trafficCtx, {
  type: 'line',
  data: {
    labels:   Array(30).fill(''),
    datasets: [{
      label: 'req/s',
      data:  Array(30).fill(0),
      borderColor: '#4f6ef7',
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
    datasets: [{ data: [1, 0, 0], backgroundColor: ['#10c984', '#f59e0b', '#ef4444'], borderWidth: 0, hoverOffset: 4 }]
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
  at.insertBefore(item, at.firstChild);
  while (at.children.length > 200) at.lastChild.remove();
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
