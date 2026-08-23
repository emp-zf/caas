#!/usr/bin/env node
const fs = require('fs');
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const runtimeLogs = [];
function recordLog(message) {
  const line = `[${new Date().toISOString()}] ${String(message).trim()}`;
  runtimeLogs.push(line);
  if (runtimeLogs.length > 200) runtimeLogs.shift();
  console.error(line);
}

// Cloudways assigns PORT (normally 3000); 443 is terminated by its HTTPS proxy.
const port = Number(process.env.PORT || 3000);
// Fixed test credentials. Change these before production use.
const uuid = 'bb415533-7734-46e7-a989-74dba131f257';
const suffix = 'zhuofan';
const paths = {
  vless: `/vless_${suffix}`, vmess: `/vmess_${suffix}`,
  trojan: `/trojan-ws_${suffix}`, ss: `/ss-ws_${suffix}`
};
const inboundDefinitions = [
  ['vless', 14016, { decryption: 'none', clients: [{ id: uuid }] }],
  ['vmess', 23456, { clients: [{ id: uuid, alterId: 0 }] }],
  ['trojan', 25432, { clients: [{ password: uuid }] }],
  ['shadowsocks', 30300, { clients: [{ method: 'aes-128-gcm', password: uuid }] }]
];
const config = {
  log: { access: '/dev/stdout', error: '/dev/stderr', loglevel: process.env.XRAY_LOGLEVEL || 'warning' },
  inbounds: inboundDefinitions.map(([protocol, port, settings]) => ({
    listen: '127.0.0.1', port, protocol, settings,
    streamSettings: { network: 'ws', security: 'none', wsSettings: { path: paths[protocol === 'shadowsocks' ? 'ss' : protocol] } }
  })),
  outbounds: [{ protocol: 'freedom', settings: {} }, { protocol: 'blackhole', settings: {}, tag: 'blocked' }],
  routing: { rules: [{ type: 'field', ip: ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '::1/128', 'fc00::/7', 'fe80::/10'], outboundTag: 'blocked' }, { type: 'field', outboundTag: 'blocked', protocol: ['bittorrent'] }] }
};

const configPath = path.join('/tmp', `xray-${process.pid}.json`);
const xrayPath = process.env.XRAY_BIN || path.join(__dirname, 'bin', 'xray');
fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
let xray;
if (!fs.existsSync(xrayPath)) {
  recordLog(`Xray binary missing at ${xrayPath}; attempting runtime installation`);
  const install = spawnSync(process.execPath, [path.join(__dirname, 'build-xray.js')], {
    env: process.env, encoding: 'utf8'
  });
  if (install.stdout) recordLog(`Xray install: ${install.stdout}`);
  if (install.stderr) recordLog(`Xray install error: ${install.stderr}`);
}
if (fs.existsSync(xrayPath)) {
  const validation = spawnSync(xrayPath, ['run', '-test', '-config', configPath], { encoding: 'utf8' });
  if (validation.stdout) recordLog(`Xray test: ${validation.stdout}`);
  if (validation.stderr) recordLog(`Xray test error: ${validation.stderr}`);
  if (validation.status !== 0) {
    recordLog(`Xray configuration test failed with exit code ${validation.status}`);
    process.exit(validation.status || 1);
  }
  xray = spawn(xrayPath, ['run', '-config', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  xray.stdout.on('data', data => recordLog(`Xray: ${data}`));
  xray.stderr.on('data', data => recordLog(`Xray error: ${data}`));
  xray.on('error', error => recordLog(`Xray process error: ${error.stack || error}`));
  xray.on('exit', (code, signal) => { recordLog(`Xray exited: code=${code}, signal=${signal}`); if (!shuttingDown) process.exit(code || 1); });
} else recordLog(`Xray binary not found at ${xrayPath}`);

const targets = { [paths.vless]: 14016, [paths.vmess]: 23456, [paths.trojan]: 25432, [paths.ss]: 30300 };
function forwardHttp(req, res, targetPort) {
  const upstream = http.request({ hostname: '127.0.0.1', port: targetPort, path: req.url, method: req.method, headers: req.headers, timeout: 3600000 }, upstreamRes => {
    res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
    upstreamRes.pipe(res);
  });
  upstream.on('timeout', () => upstream.destroy());
  upstream.on('error', error => { recordLog(`Proxy error: ${error.message}`); if (!res.headersSent) res.writeHead(502); res.end('Bad gateway'); });
  req.pipe(upstream);
}
const server = http.createServer((req, res) => {
  const requestPath = req.url.split('?')[0];
  if (requestPath === '/') return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Made by Zhuo Fan</title></head><body style="background:#1c1c1c;color:white;font:28px Arial;text-align:center;padding-top:20vh"><p>Made by</p><h1>Zhuo Fan</h1></body></html>');
  if (requestPath === '/pass') {
    if (process.env.EXPOSE_PASS !== 'true') return res.writeHead(404).end('Not found');
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    return res.end(`UUID: ${uuid}\nPATH_SUFFIX: ${suffix}\nVLESS_PATH: ${paths.vless}\nVMESS_PATH: ${paths.vmess}\nTROJAN_PATH: ${paths.trojan}\nSS_PATH: ${paths.ss}\n`);
  }
  if (requestPath === '/logs') {
    if (process.env.DEBUG_LOGS !== 'true') return res.writeHead(404).end('Not found');
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    return res.end(runtimeLogs.join('\n') || 'No runtime logs yet.');
  }
  if (targets[requestPath]) return forwardHttp(req, res, targets[requestPath]);
  res.writeHead(404).end('Not found');
});
server.on('upgrade', (req, socket, head) => {
  const targetPort = targets[req.url.split('?')[0]];
  if (!targetPort) return socket.destroy();
  const upstream = net.connect(targetPort, '127.0.0.1', () => {
    let request = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) request += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
    upstream.write(`${request}\r\n`);
    if (head.length) upstream.write(head);
    socket.pipe(upstream).pipe(socket);
  });
  upstream.setTimeout(3600000);
  upstream.on('error', error => { recordLog(`WebSocket proxy error: ${error.message}`); socket.destroy(); });
  socket.on('error', () => upstream.destroy());
});

let shuttingDown = false;
function shutdown(signal) { shuttingDown = true; server.close(() => { if (xray) xray.kill('SIGTERM'); fs.rmSync(configPath, { force: true }); process.exit(0); }); setTimeout(() => process.exit(1), 10000).unref(); console.log(`Received ${signal}; shutting down`); }
process.on('SIGTERM', () => shutdown('SIGTERM')); process.on('SIGINT', () => shutdown('SIGINT'));
server.listen(port, '0.0.0.0', () => { console.log(`Listening on ${port}`); console.log(`UUID=${uuid}`); console.log(`PATH_SUFFIX=${suffix}`); Object.entries(paths).forEach(([name, value]) => console.log(`${name.toUpperCase()}_PATH=${value}`)); });
