#!/usr/bin/env node
const fs = require('fs');
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const QRCode = require('qrcode');

const runtimeLogs = [];
const sessions = new Map();
const port = Number(process.env.PORT || 3000);
const defaultUuid = 'bb415533-7734-46e7-a989-74dba131f257';
const configFile = process.env.GATEWAY_CONFIG_FILE || path.join(__dirname, 'data', 'gateway-config.json');
const dashboardUser = process.env.DASHBOARD_USERNAME || 'admin';
const dashboardPassword = process.env.DASHBOARD_PASSWORD;

function recordLog(message) {
  const line = `[${new Date().toISOString()}] ${String(message).trim()}`;
  runtimeLogs.push(line);
  if (runtimeLogs.length > 200) runtimeLogs.shift();
  console.error(line);
}

function validUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function validPath(value) {
  return typeof value === 'string' && /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,180}$/.test(value) && !value.includes('//');
}

function loadGatewayConfig() {
  try {
    const saved = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    if (validUuid(saved.uuid) && saved.paths && Object.values(saved.paths).every(validPath)) return saved;
  } catch (error) {
    if (error.code !== 'ENOENT') recordLog(`Configuration load error: ${error.message}`);
  }
  return {
    uuid: defaultUuid,
    paths: { vless: '/vless_zhuofan', vmess: '/vmess_zhuofan', trojan: '/trojan-ws_zhuofan', ss: '/ss-ws_zhuofan' }
  };
}

let gatewayConfig = loadGatewayConfig();
function saveGatewayConfig(next) {
  fs.mkdirSync(path.dirname(configFile), { recursive: true });
  const temporary = `${configFile}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(next, null, 2), { mode: 0o600 });
  fs.renameSync(temporary, configFile);
}

function xrayConfig() {
  const inbounds = [
    ['vless', 14016, { decryption: 'none', clients: [{ id: gatewayConfig.uuid }] }],
    ['vmess', 23456, { clients: [{ id: gatewayConfig.uuid, alterId: 0 }] }],
    ['trojan', 25432, { clients: [{ password: gatewayConfig.uuid }] }],
    ['shadowsocks', 30300, { clients: [{ method: 'aes-128-gcm', password: gatewayConfig.uuid }] }]
  ];
  return {
    log: { access: '', error: '', loglevel: process.env.XRAY_LOGLEVEL || 'warning' },
    inbounds: inbounds.map(([protocol, inboundPort, settings]) => ({
      listen: '127.0.0.1', port: inboundPort, protocol, settings,
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: gatewayConfig.paths[protocol === 'shadowsocks' ? 'ss' : protocol] } }
    })),
    outbounds: [{ protocol: 'freedom', settings: {} }, { protocol: 'blackhole', settings: {}, tag: 'blocked' }],
    routing: { rules: [{ type: 'field', ip: ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '::1/128', 'fc00::/7', 'fe80::/10'], outboundTag: 'blocked' }, { type: 'field', outboundTag: 'blocked', protocol: ['bittorrent'] }] }
  };
}

const configPath = path.join('/tmp', `xray-${process.pid}.json`);
const xrayPath = process.env.XRAY_BIN || path.join(__dirname, 'bin', 'xray');
let xray;
function startXray() {
  fs.writeFileSync(configPath, JSON.stringify(xrayConfig(), null, 2), { mode: 0o600 });
  if (!fs.existsSync(xrayPath)) {
    recordLog(`Xray binary missing at ${xrayPath}; attempting runtime installation`);
    const install = spawnSync(process.execPath, [path.join(__dirname, 'build-xray.js')], { env: process.env, encoding: 'utf8' });
    if (install.stdout) recordLog(`Xray install: ${install.stdout}`);
    if (install.stderr) recordLog(`Xray install error: ${install.stderr}`);
  }
  if (!fs.existsSync(xrayPath)) return recordLog(`Xray binary not found at ${xrayPath}`);
  const validation = spawnSync(xrayPath, ['run', '-test', '-config', configPath], { encoding: 'utf8' });
  if (validation.stdout) recordLog(`Xray test: ${validation.stdout}`);
  if (validation.stderr) recordLog(`Xray test error: ${validation.stderr}`);
  if (validation.status !== 0) return recordLog(`Xray configuration test failed with exit code ${validation.status}; keeping Node diagnostics online`);
  xray = spawn(xrayPath, ['run', '-config', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  xray.stdout.on('data', data => recordLog(`Xray: ${data}`));
  xray.stderr.on('data', data => recordLog(`Xray error: ${data}`));
  xray.on('error', error => recordLog(`Xray process error: ${error.stack || error}`));
  xray.on('exit', (code, signal) => { recordLog(`Xray exited: code=${code}, signal=${signal}`); xray = null; });
}
function restartXray() {
  if (xray) xray.kill('SIGTERM');
  xray = null;
  startXray();
}
startXray();

function publicHost(req) {
  return (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(',')[0].trim().split(':')[0];
}
function buildUris(req) {
  const host = publicHost(req);
  const encoded = value => encodeURIComponent(value);
  const label = 'Xray Gateway';
  const vmess = Buffer.from(JSON.stringify({ v: '2', ps: label, add: host, port: '443', id: gatewayConfig.uuid, aid: '0', scy: 'none', net: 'ws', type: 'none', host, path: gatewayConfig.paths.vmess, tls: 'tls', sni: host })).toString('base64');
  return {
    vless: `vless://${gatewayConfig.uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${encoded(host)}&path=${encoded(gatewayConfig.paths.vless)}#${encoded(label + ' VLESS')}`,
    vmess: `vmess://${vmess}`,
    trojan: `trojan://${gatewayConfig.uuid}@${host}:443?security=tls&type=ws&host=${encoded(host)}&path=${encoded(gatewayConfig.paths.trojan)}#${encoded(label + ' Trojan')}`,
    ss: `ss://${Buffer.from(`aes-128-gcm:${gatewayConfig.uuid}`).toString('base64url')}@${host}:443/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bpath%3D${encoded(gatewayConfig.paths.ss)}%3Bhost%3D${encoded(host)}#${encoded(label + ' Shadowsocks')}`
  };
}

function sessionCookie(req) {
  const value = (req.headers.cookie || '').match(/(?:^|;\s*)dashboard_session=([^;]+)/);
  return value && sessions.get(value[1]);
}
function authenticated(req) {
  const session = sessionCookie(req);
  return session && session.expires > Date.now();
}
function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(payload);
}
function requireAuth(req, res) {
  if (authenticated(req)) return true;
  sendJson(res, 401, { error: 'Authentication required' });
  return false;
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 16384) reject(new Error('Request too large')); });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}

const loginPage = `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Gateway Login</title><style>body{background:#101317;color:#e8edf2;font:16px system-ui;display:grid;place-items:center;min-height:100vh;margin:0}form{background:#191e25;padding:2rem;border:1px solid #303943;border-radius:12px;width:min(360px,80vw)}input,button{box-sizing:border-box;width:100%;padding:.75rem;margin-top:.5rem;background:#0e1217;color:inherit;border:1px solid #46515e;border-radius:6px}button{background:#4f8cff;border:0;cursor:pointer;margin-top:1rem}</style></head><body><form method="post" action="/dashboard/login"><h1>Gateway login</h1><label>Username<input name="username" autocomplete="username" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button>Log in</button></form></body></html>`;
const dashboardPage = `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Xray Dashboard</title><style>body{background:#101317;color:#e8edf2;font:15px system-ui;margin:0}main{max-width:1100px;margin:auto;padding:1.5rem}h1{margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}.card{background:#191e25;border:1px solid #303943;border-radius:10px;padding:1rem}label{display:block;margin:.7rem 0;color:#aeb8c2}input{width:100%;box-sizing:border-box;padding:.65rem;background:#0e1217;color:inherit;border:1px solid #46515e;border-radius:5px}button{padding:.65rem 1rem;border:0;border-radius:5px;background:#4f8cff;color:#fff;cursor:pointer}button.secondary{background:#3b444e}.uri{font:12px ui-monospace;word-break:break-all;background:#0e1217;padding:.6rem;border-radius:5px;margin:.5rem 0}.qr{background:#fff;padding:8px;width:150px;max-width:100%}pre{white-space:pre-wrap;max-height:300px;overflow:auto;background:#0e1217;padding:1rem;border-radius:5px;color:#b7f5c2}.status{min-height:1.5em;color:#aeb8c2}</style></head><body><main><h1>Xray Gateway Dashboard</h1><button class="secondary" onclick="logout()">Log out</button><section class="card"><h2>Configuration</h2><form id="config"><label>UUID<input id="uuid" required></label><label>VLESS path<input id="vless" required></label><label>VMess path<input id="vmess" required></label><label>Trojan path<input id="trojan" required></label><label>Shadowsocks path<input id="ss" required></label><button>Save and restart Xray</button><p class="status" id="status"></p></form></section><h2>Connection URIs</h2><section class="grid" id="uris"></section><section class="card"><h2>Live logs</h2><pre id="logs">Loading...</pre></section></main><script>
async function api(url, options){const r=await fetch(url,options);if(r.status===401){location='/dashboard/login';throw Error('login required')}const d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
function show(data){document.querySelector('#uuid').value=data.uuid;for(const k of ['vless','vmess','trojan','ss'])document.querySelector('#'+k).value=data.paths[k];document.querySelector('#uris').innerHTML=Object.entries(data.uris).map(([k,v])=>'<article class="card"><h3>'+k.toUpperCase()+'</h3><img class="qr" src="'+data.qr[k]+'" alt="'+k+' QR code"><div class="uri">'+v+'</div><button class="secondary" onclick="navigator.clipboard.writeText('+JSON.stringify(v)+')">Copy URI</button></article>').join('')}
async function load(){try{show(await api('/api/config'));document.querySelector('#logs').textContent=(await api('/api/logs')).logs.join('\\n')}catch(e){document.querySelector('#status').textContent=e.message}}
async function logout(){await fetch('/api/logout',{method:'POST'});location='/dashboard/login'}load();setInterval(async()=>{try{document.querySelector('#logs').textContent=(await api('/api/logs')).logs.join('\\n')}catch{}},3000);
</script></body></html>`;

function targets() {
  return { [gatewayConfig.paths.vless]: 14016, [gatewayConfig.paths.vmess]: 23456, [gatewayConfig.paths.trojan]: 25432, [gatewayConfig.paths.ss]: 30300 };
}
function forwardHttp(req, res, targetPort) {
  const upstream = http.request({ hostname: '127.0.0.1', port: targetPort, path: req.url, method: req.method, headers: req.headers, timeout: 3600000 }, upstreamRes => { res.writeHead(upstreamRes.statusCode, upstreamRes.headers); upstreamRes.pipe(res); });
  upstream.on('timeout', () => upstream.destroy());
  upstream.on('error', error => { recordLog(`Proxy error: ${error.message}`); if (!res.headersSent) res.writeHead(502); res.end('Bad gateway'); });
  req.pipe(upstream);
}
const server = http.createServer(async (req, res) => {
  const requestPath = req.url.split('?')[0];
  if (requestPath === '/dashboard/login' && req.method === 'GET') return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(loginPage);
  if (requestPath === '/dashboard/login' && req.method === 'POST') {
    let body = ''; req.on('data', chunk => { body += chunk; }); req.on('end', () => { const form = new URLSearchParams(body); if (!dashboardPassword || form.get('username') !== dashboardUser || form.get('password') !== dashboardPassword) return res.writeHead(401).end('Invalid credentials'); const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, { expires: Date.now() + 86400000 }); const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : ''; res.writeHead(302, { location: '/dashboard', 'set-cookie': `dashboard_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400${secure}` }).end(); }); return;
  }
  if (requestPath === '/dashboard' && req.method === 'GET') { if (!authenticated(req)) return res.writeHead(302, { location: '/dashboard/login' }).end(); return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(dashboardPage); }
  if (requestPath === '/api/logout' && req.method === 'POST') { const token = (req.headers.cookie || '').match(/(?:^|;\s*)dashboard_session=([^;]+)/); if (token) sessions.delete(token[1]); return res.writeHead(204, { 'set-cookie': 'dashboard_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' }).end(); }
  if (requestPath === '/api/config' && req.method === 'GET') { if (!requireAuth(req, res)) return; const uris = buildUris(req); const qr = {}; for (const [key, uri] of Object.entries(uris)) qr[key] = await QRCode.toDataURL(uri, { margin: 1, width: 240 }); return sendJson(res, 200, { ...gatewayConfig, uris, qr }); }
  if (requestPath === '/api/config' && req.method === 'PUT') { if (!requireAuth(req, res)) return; try { const body = await readBody(req); const pathValues = body.paths && ['vless', 'vmess', 'trojan', 'ss'].map(key => body.paths[key]); if (!validUuid(body.uuid) || !body.paths || !pathValues.every(validPath) || new Set(pathValues).size !== pathValues.length) throw new Error('Invalid UUID or paths'); const nextConfig = { uuid: body.uuid.toLowerCase(), paths: body.paths }; saveGatewayConfig(nextConfig); gatewayConfig = nextConfig; restartXray(); recordLog('Gateway configuration updated from dashboard'); const uris = buildUris(req); const qr = {}; for (const [key, uri] of Object.entries(uris)) qr[key] = await QRCode.toDataURL(uri, { margin: 1, width: 240 }); return sendJson(res, 200, { ...gatewayConfig, uris, qr }); } catch (error) { return sendJson(res, 400, { error: error.message }); } }
  if (requestPath === '/api/logs' && req.method === 'GET') { if (!requireAuth(req, res)) return; return sendJson(res, 200, { logs: runtimeLogs }); }
  if (requestPath === '/') return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Made by Zhuo Fan</title></head><body style="background:#1c1c1c;color:white;font:28px Arial;text-align:center;padding-top:20vh"><p>Made by</p><h1>Zhuo Fan</h1></body></html>');
  if (requestPath === '/pass') { if (process.env.EXPOSE_PASS !== 'true') return res.writeHead(404).end('Not found'); return res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }).end(`UUID: ${gatewayConfig.uuid}\nVLESS_PATH: ${gatewayConfig.paths.vless}\nVMESS_PATH: ${gatewayConfig.paths.vmess}\nTROJAN_PATH: ${gatewayConfig.paths.trojan}\nSS_PATH: ${gatewayConfig.paths.ss}\n`); }
  if (requestPath === '/logs') { if (process.env.DEBUG_LOGS !== 'true') return res.writeHead(404).end('Not found'); return res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }).end(runtimeLogs.join('\n') || 'No runtime logs yet.'); }
  const targetPort = targets()[requestPath];
  if (targetPort) return forwardHttp(req, res, targetPort);
  res.writeHead(404).end('Not found');
});
server.on('upgrade', (req, socket, head) => { const targetPort = targets()[req.url.split('?')[0]]; if (!targetPort) return socket.destroy(); const upstream = net.connect(targetPort, '127.0.0.1', () => { let request = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`; for (let i = 0; i < req.rawHeaders.length; i += 2) request += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`; upstream.write(`${request}\r\n`); if (head.length) upstream.write(head); socket.pipe(upstream).pipe(socket); }); upstream.setTimeout(3600000); upstream.on('error', error => { recordLog(`WebSocket proxy error: ${error.message}`); socket.destroy(); }); socket.on('error', () => upstream.destroy()); });
function shutdown(signal) { server.close(() => { if (xray) xray.kill('SIGTERM'); fs.rmSync(configPath, { force: true }); process.exit(0); }); setTimeout(() => process.exit(1), 10000).unref(); console.log(`Received ${signal}; shutting down`); }
process.on('SIGTERM', () => shutdown('SIGTERM')); process.on('SIGINT', () => shutdown('SIGINT'));
server.listen(port, '0.0.0.0', () => { console.log(`Listening on ${port}`); console.log(`Dashboard: /dashboard`); });
