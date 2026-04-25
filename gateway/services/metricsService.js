const { getIo } = require('./socketService');

// ── In-memory metrics store ──────────────────────────────────────────────────
const metrics = {
  totalRequests:    0,
  internalRequests: 0,
  externalRequests: 0,
  blockedRequests:  0,
  threatCount:      0,
  failedLogins:     0,
  routeHits:        {},   // route → count
  attackingIPs:     {},   // ip   → count
  statusCodes:      {},   // code → count
};

// ── Track a request ──────────────────────────────────────────────────────────
function record({ ip, path, status, source }) {
  metrics.totalRequests++;
  if (source === 'internal') metrics.internalRequests++;
  if (source === 'external') metrics.externalRequests++;
  if (status === 401 || status === 403 || status === 429 || status === 503) metrics.blockedRequests++;

  // route hit tracking
  const route = path.split('/').slice(0, 4).join('/') || '/';
  metrics.routeHits[route] = (metrics.routeHits[route] || 0) + 1;
  
  if (source === 'external' && !path.startsWith('/api/external/store')) {
    // If not store / generic jsonplaceholder proxy logic, it's dynamic
    const provider = path.split('/')[3];
    if (provider && provider !== '') {
      metrics.routeHits['/api/external/dynamic'] = (metrics.routeHits['/api/external/dynamic'] || 0) + 1;
    }
  }

  // status code distribution
  metrics.statusCodes[status] = (metrics.statusCodes[status] || 0) + 1;

  // top attacking IPs (non-200 requests)
  if (ip && status !== 200) {
    metrics.attackingIPs[ip] = (metrics.attackingIPs[ip] || 0) + 1;
  }
}

function recordThreat() { metrics.threatCount++; }
function recordFailedLogin() { metrics.failedLogins++; }

// ── Get snapshot ─────────────────────────────────────────────────────────────
function getSnapshot() {
  // get total dynamic apis size gracefully without circular deps or req errors
  let dynamicCount = 0;
  try {
    const fs = require('fs');
    const apis = JSON.parse(fs.readFileSync(require('path').join(__dirname, '../config/apis.json'), 'utf8'));
    dynamicCount = apis.length;
  } catch (e) {}

  return {
    ...metrics,
    registeredApis: dynamicCount,
    dynamicTraffic: metrics.routeHits['/api/external/dynamic'] || 0, // Need to track this cleanly
    topAttackingIPs: Object.entries(metrics.attackingIPs)
      .sort((a, b) => b[1] - a[1]).slice(0, 10)
      .map(([ip, count]) => ({ ip, count })),
    topRoutes: Object.entries(metrics.routeHits)
      .sort((a, b) => b[1] - a[1]).slice(0, 10)
      .map(([route, count]) => ({ route, count })),
  };
}

// ── Emit metrics to dashboard every 3 seconds ─────────────────────────────────
setInterval(() => {
  const io = getIo();
  if (io) io.emit('metrics_update', getSnapshot());
}, 3000);

module.exports = { record, recordThreat, recordFailedLogin, getSnapshot };
