const http = require('http');

let success = 0, rateLimited = 0, other = 0;

for (let i = 0; i < 65; i++) {
  const req = http.request({
    hostname: 'localhost',
    port: 3000,
    path: '/api/external/posts',
    method: 'GET',
    headers: { 'X-Forwarded-For': '10.0.0.1' }
  }, (res) => {
    if (res.statusCode === 200) success++;
    else if (res.statusCode === 429) rateLimited++;
    else other++;
    console.log(`Req ${i}: ${res.statusCode}`);
  });
  req.end();
}
