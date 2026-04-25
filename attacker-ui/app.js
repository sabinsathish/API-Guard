// ── Socket.io ──────────────────────────────────────────────────────────────────
const socket = io();
socket.on('connect',    () => setConn(true));
socket.on('disconnect', () => setConn(false));

function setConn(on) {
  document.getElementById('dot').className   = `dot ${on ? 'on' : 'off'}`;
  document.getElementById('connLbl').textContent = on ? 'Connected' : 'Disconnected';
}

// ── Live threat tracking via Socket.io ─────────────────────────────────────────
const sc = { s200: 0, s429: 0, s403: 0, s401: 0 };

socket.on('traffic', d => {
  if (d.status === 200) sc.s200++;
  else if (d.status === 429) sc.s429++;
  else if (d.status === 403) sc.s403++;
  else if (d.status === 401) sc.s401++;
  ['s200','s429','s403','s401'].forEach(k => el(k).textContent = sc[k]);
});

socket.on('threat', d => {
  const tl = el('threatList');
  const empty = tl.querySelector('.threat-empty');
  if (empty) empty.remove();
  const row = document.createElement('div');
  row.className = `threat-row ${d.type}`;
  row.textContent = `${new Date(d.time).toLocaleTimeString()}  ${d.type.padEnd(18)}  ${d.ip}  HTTP ${d.status}`;
  tl.insertBefore(row, tl.firstChild);
  while (tl.children.length > 30) tl.lastChild.remove();
  // refresh IP table on block events
  if (d.type === 'IP_BLOCKED' || d.type === 'RATE_ABUSE') setTimeout(loadIPs, 400);
});

// ── Mode selection ─────────────────────────────────────────────────────────────
let selectedMode = 'demo';
function selectMode(btn) {
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  selectedMode = btn.dataset.mode;
}
// Pre-select demo
document.querySelector('[data-mode="demo"]').classList.add('selected');

// ── Run attack.py via SSE ──────────────────────────────────────────────────────
let es = null;  // EventSource

function runAttack() {
  if (es) { es.close(); es = null; }
  const duration = el('duration').value || 15;
  const host     = encodeURIComponent(el('host').value || 'http://localhost:3000');
  const url      = `/demo/run-python?mode=${selectedMode}&duration=${duration}`;

  el('runBtn').disabled  = true;
  el('stopBtn').disabled = false;
  setStatus('running', 'running');
  addLine(`\n▶ Running: python attack.py ${selectedMode} --duration ${duration}\n`, 't-info');

  es = new EventSource(url);
  es.onmessage = (e) => {
    const d = JSON.parse(e.data);
    if (d.type === 'start')  { addLine(d.msg, 't-info'); }
    if (d.type === 'stdout') { addRaw(d.msg); }
    if (d.type === 'stderr') { addLine(d.msg, 't-err'); }
    if (d.type === 'error')  { addLine(`Error: ${d.msg}`, 't-err'); setStatus('error', 'error'); }
    if (d.type === 'done')   {
      addLine(`\n✓ Process exited (code ${d.code})\n`, d.code === 0 ? 't-ok' : 't-err');
      setStatus(d.code === 0 ? 'done' : 'error', 'idle');
      el('runBtn').disabled  = false;
      el('stopBtn').disabled = true;
      es.close(); es = null;
      loadIPs();
    }
  };
  es.onerror = () => {
    addLine('Connection to server lost.', 't-err');
    setStatus('error', 'error');
    el('runBtn').disabled  = false;
    el('stopBtn').disabled = true;
    if (es) { es.close(); es = null; }
  };
}

function stopAttack() {
  if (es) { es.close(); es = null; }
  fetch('/demo/stop-python', { method: 'POST' });
  el('runBtn').disabled  = false;
  el('stopBtn').disabled = true;
  setStatus('stopped', 'idle');
  addLine('\n■ Attack stopped.\n', 't-warn');
}

// ── Dual-Axis Entities Table (polls /demo/active-entities) ───────────────────
async function loadIPs() {
  try {
    const data = await fetch('/demo/active-entities').then(r => r.json());
    
    const renderTable = (list, bodyId, emptyMsg) => {
      const body = el(bodyId);
      if (!list || !list.length) {
        body.innerHTML = `<tr><td colspan="4" class="empty-row">${emptyMsg}</td></tr>`;
        return;
      }
      body.innerHTML = list.map(item => {
        const bad = (item.statuses['429'] || 0) + (item.statuses['403'] || 0) + (item.statuses['401'] || 0) + (item.statuses['500'] || 0);
        const statusHtml = item.blocked
          ? '<span class="status-blocked">BLOCKED</span>'
          : '<span class="status-ok">active</span>';
          
        let scoreColor = 'var(--text)';
        if (item.score >= 70) scoreColor = 'var(--red)';
        else if (item.score >= 30) scoreColor = 'var(--amber)';
        else if (item.score > 0) scoreColor = 'var(--blue)';

        return `<tr class="${item.blocked ? 'ip-blocked-row' : ''}">
          <td>${item.id}</td>
          <td class="badge-err">${bad}</td>
          <td style="color: ${scoreColor}; font-weight:700;">${item.score}</td>
          <td>${statusHtml}</td>
        </tr>`;
      }).join('');
    };

    renderTable(data.ips, 'ipTableBody', 'No network traffic yet…');
    renderTable(data.users, 'userTableBody', 'No authenticated traffic…');

  } catch {}
}

// Auto-refresh IP table while running
setInterval(loadIPs, 3000);
loadIPs();

// ── Terminal helpers ───────────────────────────────────────────────────────────
function addLine(txt, cls = '') {
  const term = el('terminal');
  const span = document.createElement('span');
  span.className = cls;
  span.textContent = txt;
  const br = document.createElement('br');
  term.appendChild(span);
  term.appendChild(br);
  term.scrollTop = term.scrollHeight;
  trim(term, 800);
}

// For raw multi-line streamed output (preserves line breaks, maps keywords to colors)
function addRaw(txt) {
  const term  = el('terminal');
  const lines = txt.split('\n');
  for (const line of lines) {
    if (!line && lines.indexOf(line) === lines.length - 1) continue;
    const span = document.createElement('span');
    span.className = termClass(line);
    span.textContent = line;
    term.appendChild(span);
    term.appendChild(document.createElement('br'));
  }
  term.scrollTop = term.scrollHeight;
  trim(term, 800);
}

function termClass(line) {
  const l = line.toLowerCase();
  if (l.includes('blocked') || l.includes('attack') || l.includes('error') || l.includes('429') || l.includes('403')) return 't-err';
  if (l.includes('success') || l.includes('200') || l.includes('ok') || l.includes('✓') || l.includes('✔')) return 't-ok';
  if (l.includes('brute') || l.includes('forged') || l.includes('expired') || l.includes('weak')) return 't-purple';
  if (l.includes('phase') || l.includes('mode') || l.includes('▶') || l.includes('◆')) return 't-white';
  if (l.includes('sending') || l.includes('attempt') || l.includes('401')) return 't-warn';
  if (l.includes('─') || l.includes('═') || l.includes('╔') || l.includes('╗') || l.includes('║') || l.includes('╝') || l.includes('╚')) return 't-info';
  return 't-sent';
}

function trim(el, max) { while (el.children.length > max * 2) el.firstChild.remove(); }
function clearTerm()   { el('terminal').innerHTML = '<span class="t-dim"># Cleared</span><br>'; }
function setStatus(cls, txt) {
  const s = el('procStatus');
  s.className   = `proc-status ${cls}`;
  s.textContent = txt;
}

function el(id) { return document.getElementById(id); }
