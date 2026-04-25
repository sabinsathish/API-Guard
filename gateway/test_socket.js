const io = require('socket.io-client');
const socket = io('http://localhost:3000');

socket.on('connect', () => console.log('Connected'));
socket.on('traffic', (d) => console.log('TRAFFIC:', d.status, d.endpoint));
socket.on('threat', (d) => console.log('THREAT:', d.type));
socket.on('demo_status', (d) => console.log('DEMO:', d.phase));

const http = require('http');
const req = http.request({ hostname: 'localhost', port: 3000, path: '/demo/run-demo', method: 'POST' });
req.end();

setTimeout(() => process.exit(0), 10000);
