const fs = require('fs');
const path = require('path');

const configPath = path.join(__dirname, '../config/apis.json');

// In-memory cache
let registryCache = {};

function init() {
  if (!fs.existsSync(configPath)) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, '[]');
  }
  loadRegistry();
}

function loadRegistry() {
  try {
    const data = fs.readFileSync(configPath, 'utf8');
    const apis = JSON.parse(data);
    
    registryCache = {};
    for (const api of apis) {
      registryCache[api.name] = api;
    }
  } catch (err) {
    console.error('[Registry] Error parsing config/apis.json:', err.message);
  }
}

function saveRegistry() {
  const arr = Object.values(registryCache);
  fs.writeFileSync(configPath, JSON.stringify(arr, null, 2));
}

function getApiConfig(name) {
  return registryCache[name];
}

function getAllApis() {
  return Object.values(registryCache);
}

function addApi(apiData) {
  // apiData must have: name, target
  // apiKey, headerName, enabled, createdAt
  if (!apiData.name || !apiData.target) {
    throw new Error('Name and Target are required');
  }

  // Sanitize name for clean URL routing
  const safeName = apiData.name.toLowerCase().replace(/[^a-z0-9_-]/g, '');
  if (!safeName) throw new Error('Invalid name format');

  if (registryCache[safeName]) {
    throw new Error(`API provider '${safeName}' is already registered.`);
  }

  // Check duplicate target roughly
  const targetHost = new URL(apiData.target).origin;
  for (const existing of Object.values(registryCache)) {
    if (new URL(existing.target).origin === targetHost) {
      throw new Error(`Target host ${targetHost} already exists under name '${existing.name}'.`);
    }
  }

  const entry = {
    name: safeName,
    target: apiData.target.replace(/\/$/, ''), // remove trailing slash
    apiKey: apiData.apiKey || '',
    headerName: apiData.headerName || '',
    enabled: apiData.enabled !== false,
    createdAt: new Date().toISOString()
  };

  registryCache[safeName] = entry;
  saveRegistry();
  return entry;
}

// init on load
init();

module.exports = {
  getApiConfig,
  getAllApis,
  addApi
};
