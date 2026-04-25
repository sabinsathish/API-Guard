// ── Socket.io (for receiving demo_status events) ─────────────────────────────
const socket = io();

const GW = 'http://localhost:3000';
const counts = { sent: 0, ok: 0, lim: 0, blocked: 0 };

socket.on('connect', () => { $dot('connDot', 'on'); $text('connText', 'Connected'); });
socket.on('disconnect', () => { $dot('connDot', 'off'); $text('connText', 'Disconnected'); });

// Listen to traffic events to update counters
socket.on('traffic', data => {
  addLine(formatTrafficLine(data), lineClass(data.status));
  counts.sent++;
  if (data.status === 200) counts.ok++;
  else if (data.status === 429) counts.lim++;
  else if (data.status === 403) counts.blocked++;
  updateCounters();
});

// Listen to threat events
socket.on('threat', data => {
  addLine(formatThreatLine(data), threatClass(data.type));
  if (data.type === 'IP_BLOCKED' || data.type === 'BLOCKED_IP_ACCESS') {
    setTimeout(loadBlockedIPs, 300);
  }
});

// Listen to demo phase updates
socket.on('demo_status', data => {
  addLine(`\n◆ ${data.msg}\n`, 'white');
  // Highlight current phase
  document.querySelectorAll('.phase-item').forEach(el => {
    el.classList.remove('active');
    if (el.id === `ph-${data.phase}`) el.classList.add('active');
    if (data.phase === 'COMPLETE') {
      document.querySelectorAll('.phase-item').forEach(p => {
        p.classList.remove('active'); p.classList.add('done');
      });
      document.getElementById('demoBtn').disabled = false;
      document.getElementById('demoBtn').textContent = '▶  Run Full Demo';
    }
  });
});

// ── Attack triggers ───────────────────────────────────────────────────────────
async function attack(mode, body = {}) {
  addLine(`\n> Launching ${mode.toUpperCase()}…`, 'info');
  try {
    const r = await fetch(`${GW}/demo/${mode}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const d = await r.json();
    addLine(`  ✓ Started: ${JSON.stringify(d)}`, 'ok');
  } catch (e) {
    addLine(`  ✗ Error: ${e.message}`, 'err');
  }
}

async function runDemo() {
  const btn = document.getElementById('demoBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Running…';
  document.querySelectorAll('.phase-item').forEach(p => p.classList.remove('done', 'active'));
  addLine('\n════════════════════════════════════════', 'muted');
  addLine('  Starting Full Demo — 5 attack phases  ', 'white');
  addLine('════════════════════════════════════════\n', 'muted');
  try {
    await fetch(`${GW}/demo/run-demo`, { method: 'POST' });
  } catch (e) {
    addLine(`Demo error: ${e.message}`, 'err');
    btn.disabled = false;
    btn.textContent = '▶  Run Full Demo';
  }
}

// ── JWT Token tools ───────────────────────────────────────────────────────────
async function fetchToken(type) {
  const el = document.getElementById('tokenResult');
  el.textContent = 'Fetching…';
  try {
    const r = await fetch(`${GW}/auth/${type}`);
    const d = await r.json();
    el.textContent = `Token: ${d.token}\n\nNote: ${d.note}`;
    document.getElementById('customToken').value = d.token;
    addLine(`> Fetched ${type}: ${d.token.substring(0, 40)}…`, 'orange');
  } catch (e) {
    el.textContent = `Error: ${e.message}`;
  }
}

async function testToken() {
  const token = document.getElementById('customToken').value.trim();
  if (!token) return;
  const el = document.getElementById('tokenResult');
  el.textContent = 'Testing token against /api/posts…';
  addLine(`> Testing token: ${token.substring(0, 40)}…`, 'info');
  try {
    const r = await fetch(`${GW}/api/posts/1`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const d = await r.json();
    if (r.ok) {
      el.textContent = `✅ Token ACCEPTED (${r.status})\n${JSON.stringify(d, null, 2).substring(0, 200)}`;
      addLine(`  ✓ Token accepted (${r.status})`, 'ok');
    } else {
      el.textContent = `❌ Token REJECTED (${r.status})\n${JSON.stringify(d, null, 2)}`;
      addLine(`  ✗ Token rejected: ${d.error} (${r.status})`, 'err');
    }
  } catch (e) {
    el.textContent = `Error: ${e.message}`;
  }
}

// ── Blocked IPs ───────────────────────────────────────────────────────────────
async function loadBlockedIPs() {
  try {
    const r = await fetch(`${GW}/api/blocked-ips`);
    const list = await r.json();
    const el = document.getElementById('blockedList');
    if (!list.length) {
      el.innerHTML = '<span class="empty-blocked">No IPs currently blocked</span>';
      return;
    }
    el.innerHTML = list.map(b =>
      `<div class="blocked-tag">🚫 ${b.ip} <span>${b.remainingSec}s</span></div>`
    ).join('');
  } catch { }
}

// Auto-refresh blocked IPs every 5 seconds
setInterval(loadBlockedIPs, 5000);
loadBlockedIPs();

// ── Terminal helpers ──────────────────────────────────────────────────────────
function addLine(text, cls = '') {
  const term = document.getElementById('terminal');
  const div = document.createElement('div');
  div.className = `terminal-line ${cls}`;
  div.textContent = text;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
  // Keep max 500 lines
  while (term.children.length > 500) term.firstChild.remove();
}

function formatTrafficLine(d) {
  const ts = new Date(d.time).toLocaleTimeString();
  const status = d.status;
  const flag = d.threatType && d.threatType !== 'NONE' ? ` [${d.threatType}]` : '';
  return `[${ts}] ${status} ${d.method} ${d.endpoint}  ← ${d.ip}${flag}  ${d.responseMs}ms`;
}

function formatThreatLine(d) {
  const ts = new Date(d.time).toLocaleTimeString();
  const sub = d.subtype ? ` (${d.subtype})` : '';
  const detail = d.detail ? ` — ${d.detail}` : '';
  return `[${ts}] ⚠ ${d.type}${sub}  IP: ${d.ip}  HTTP ${d.status}${detail}`;
}

function lineClass(status) {
  if (status === 200) return 'ok';
  if (status === 429) return 'warn';
  if (status >= 400) return 'err';
  return '';
}

function threatClass(type) {
  if (['RATE_ABUSE', 'DOS_ATTACK', 'IP_BLOCKED', 'BLOCKED_IP_ACCESS'].includes(type)) return 'err';
  if (['RATE_LIMIT'].includes(type)) return 'warn';
  if (['BRUTE_FORCE'].includes(type)) return 'purple';
  if (['BROKEN_AUTH'].includes(type)) return 'orange';
  return 'info';
}

function updateCounters() {
  document.getElementById('fcSent').textContent = counts.sent;
  document.getElementById('fcOk').textContent = counts.ok;
  document.getElementById('fcLim').textContent = counts.lim;
  document.getElementById('fcBlocked').textContent = counts.blocked;
}

function clearFeed() {
  document.getElementById('terminal').innerHTML =
    '<div class="terminal-line muted"># Feed cleared</div>';
  Object.keys(counts).forEach(k => counts[k] = 0);
  updateCounters();
}

// ── DOM helpers ────────────────────────────────────────────────────────────────
function $dot(id, cls) { const e = document.getElementById(id); e.className = `dot ${cls}`; }
function $text(id, txt) { document.getElementById(id).textContent = txt; }
