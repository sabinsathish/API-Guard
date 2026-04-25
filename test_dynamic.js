const http = require('http');

async function test() {
  console.log("1. Logging in...");
  const loginRes = await fetch('http://localhost:3000/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'password123' })
  }).then(r => r.json());

  const token = loginRes.token;
  console.log("Token acquired:", token ? 'YES' : 'NO');

  console.log("\n2. Registering 'cats' Provider...");
  const regRes = await fetch('http://localhost:3000/admin/register-api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({
      name: 'cats',
      target: 'https://api.thecatapi.com/v1',
      apiKey: 'test-key',
      headerName: 'x-api-key'
    })
  }).then(r => r.json());
  
  console.log("Registration Response:", regRes);

  console.log("\n3. Testing dynamic proxy routing...");
  const proxyRes = await fetch('http://localhost:3000/api/external/cats/images/search', {
    headers: { 'Authorization': `Bearer ${token}` }
  }).then(r => r.json());

  console.log("Cat Proxy Response:", proxyRes);
}

test();
