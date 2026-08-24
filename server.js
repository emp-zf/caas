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

const loginPage = `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>ZFTunnel by Velocity · Sign in</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#081014;color:#e8f3f1;font:15px Inter,ui-sans-serif,system-ui,sans-serif}body:before{content:"";position:fixed;inset:0;background:radial-gradient(circle at 20% 10%,#0d3b3a 0,transparent 34%),radial-gradient(circle at 90% 85%,#19342b 0,transparent 30%);opacity:.7;pointer-events:none}.login{position:relative;width:min(420px,calc(100% - 32px));padding:34px;background:rgba(14,25,28,.92);border:1px solid #244443;border-radius:24px;box-shadow:0 24px 80px #0008}.mark{display:flex;align-items:center;gap:10px;color:#7ef5ce;font-size:12px;font-weight:800;letter-spacing:.16em}.mark i{display:block;width:11px;height:11px;background:#70f1bc;border-radius:50%;box-shadow:0 0 18px #70f1bc}.login h1{margin:30px 0 8px;font-size:32px;letter-spacing:-.04em}.login p{margin:0 0 26px;color:#8ca9a5}label{display:block;margin:16px 0;color:#aac1bd;font-size:13px;font-weight:650}input{display:block;width:100%;margin-top:8px;padding:13px 14px;border:1px solid #315452;border-radius:10px;background:#091416;color:#eefefa;outline:none}input:focus{border-color:#70f1bc;box-shadow:0 0 0 3px #70f1bc1f}button{width:100%;padding:13px;border:0;border-radius:10px;background:#70f1bc;color:#062019;font-weight:800;cursor:pointer;margin-top:12px}.theme{position:absolute;right:22px;top:22px;width:auto;padding:8px 11px;margin:0;background:#17302e;color:#acd9cf;border:1px solid #2c514c;font-size:12px}[data-theme=light] body{background:#f2f7f5;color:#122a27}[data-theme=light] body:before{background:radial-gradient(circle at 20% 10%,#d8f4e8 0,transparent 34%),radial-gradient(circle at 90% 85%,#cce9df 0,transparent 30%)}[data-theme=light] .login{background:rgba(255,255,255,.9);border-color:#c8ded7;box-shadow:0 24px 80px #32665b22}[data-theme=light] .login p,[data-theme=light] label{color:#56736d}[data-theme=light] input{background:#f7fbfa;color:#17332f;border-color:#b9d2ca}[data-theme=light] .theme{background:#e4f3ee;color:#24574c;border-color:#b9d2ca}</style></head><body><form class="login" method="post" action="/dashboard/login"><button type="button" class="theme" id="theme" onclick="toggleTheme()">Light mode</button><div class="mark"><i></i>ZFTUNNEL <span style="font-weight:500;letter-spacing:.05em">BY VELOCITY</span></div><h1>Welcome back</h1><p>Sign in to manage your secure gateway.</p><label>Username<input name="username" autocomplete="username" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button>Sign in to dashboard</button></form><script>const savedTheme=localStorage.getItem('zftunnel-theme')||'dark';document.documentElement.dataset.theme=savedTheme;function toggleTheme(){const next=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=next;localStorage.setItem('zftunnel-theme',next);document.querySelector('#theme').textContent=next==='dark'?'Light mode':'Dark mode'}document.querySelector('#theme').textContent=savedTheme==='dark'?'Light mode':'Dark mode'</script></body></html>`;
const dashboardPage = `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>EdgeTunnel · Dashboard</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#081014;color:#e8f3f1;font:14px Inter,ui-sans-serif,system-ui,sans-serif}body:before{content:"";position:fixed;z-index:-1;inset:0;background:radial-gradient(circle at 12% 0,#0b3030 0,transparent 32%),radial-gradient(circle at 95% 100%,#153329 0,transparent 34%);opacity:.7}.shell{max-width:1240px;margin:auto;padding:28px 24px 44px}.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:42px}.brand{display:flex;align-items:center;gap:12px;font-weight:850;letter-spacing:.14em}.brand i{width:12px;height:12px;display:block;border-radius:50%;background:#70f1bc;box-shadow:0 0 20px #70f1bc}.brand small{display:block;color:#6d8e89;font-size:10px;letter-spacing:.08em;font-weight:500;margin-top:4px}.actions{display:flex;gap:8px}.topbar button{width:auto;margin:0}.hero{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:26px}.eyebrow{color:#70f1bc;text-transform:uppercase;letter-spacing:.15em;font-size:11px;font-weight:800}.hero h1{font-size:clamp(30px,5vw,52px);line-height:1;margin:10px 0 0;letter-spacing:-.06em}.hero p{color:#86a39e;margin:14px 0 0}.online{display:flex;align-items:center;gap:8px;color:#9ae9c9;font-size:12px;white-space:nowrap}.online:before{content:"";width:8px;height:8px;border-radius:50%;background:#70f1bc;box-shadow:0 0 12px #70f1bc}.layout{display:grid;grid-template-columns:minmax(280px,.72fr) minmax(0,1.28fr);gap:18px}.card{background:rgba(13,25,28,.88);border:1px solid #23413f;border-radius:18px;padding:22px;box-shadow:0 14px 44px #0002}.card h2{font-size:17px;margin:0 0 5px;letter-spacing:-.02em}.muted{color:#77918e;margin:0 0 20px;font-size:13px}.fields{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}label{display:block;margin:12px 0;color:#9eb9b4;font-size:12px;font-weight:650}input{display:block;width:100%;margin-top:7px;padding:11px 12px;border:1px solid #2c4e4b;border-radius:9px;background:#091416;color:#eefefa;outline:none;font:13px ui-monospace,monospace}input:focus{border-color:#70f1bc;box-shadow:0 0 0 3px #70f1bc1f}button{padding:11px 15px;border:0;border-radius:9px;background:#70f1bc;color:#062019;font-weight:800;cursor:pointer}button.secondary{background:#17302e;color:#acd9cf;border:1px solid #2c514c}.save{width:100%;margin-top:14px}.status{min-height:18px;color:#8ea9a4;margin:12px 0 0;font-size:12px}.uri-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.protocol{padding:17px;border:1px solid #24423f;border-radius:14px;background:#0b191b}.protocol h3{font-size:12px;color:#70f1bc;letter-spacing:.14em;margin:0 0 13px}.qr-wrap{display:flex;align-items:center;justify-content:center;min-height:174px;background:#eef7f2;border-radius:10px}.qr{width:156px;max-width:100%;image-rendering:pixelated}.uri{font:11px/1.5 ui-monospace,monospace;word-break:break-all;color:#aac7c0;background:#071012;border:1px solid #1d3735;padding:10px;border-radius:8px;margin:12px 0;max-height:82px;overflow:auto}.copy{width:100%;padding:9px;font-size:12px}.logs{margin-top:18px}.logs pre{white-space:pre-wrap;max-height:280px;min-height:110px;overflow:auto;background:#071012;border:1px solid #1d3735;padding:14px;border-radius:10px;color:#9fe8c4;font:12px/1.7 ui-monospace,monospace}.log-head{display:flex;justify-content:space-between;align-items:center}.live{color:#6d8e89;font-size:11px}[data-theme=light] body{background:#f2f7f5;color:#122a27}[data-theme=light] body:before{background:radial-gradient(circle at 12% 0,#d8f4e8 0,transparent 32%),radial-gradient(circle at 95% 100%,#cce9df 0,transparent 34%)}[data-theme=light] .brand small,[data-theme=light] .live{color:#6c8981}[data-theme=light] .hero p,[data-theme=light] .muted{color:#638079}[data-theme=light] .card{background:rgba(255,255,255,.86);border-color:#c8ded7;box-shadow:0 14px 44px #32665b12}[data-theme=light] input{background:#f7fbfa;color:#17332f;border-color:#b9d2ca}[data-theme=light] .protocol{background:#edf7f3;border-color:#c8ded7}[data-theme=light] .uri,[data-theme=light] .logs pre{background:#f7fbfa;color:#315c52;border-color:#c8ded7}[data-theme=light] button.secondary{background:#e4f3ee;color:#24574c;border-color:#b9d2ca}@media(max-width:800px){.shell{padding:20px 14px 30px}.topbar{margin-bottom:30px}.hero{align-items:start;flex-direction:column}.layout{grid-template-columns:1fr}.uri-grid{grid-template-columns:1fr}}@media(max-width:430px){.fields{grid-template-columns:1fr}.card{padding:17px}}</style></head><body><main class="shell"><header class="topbar"><div class="brand"><i></i><div>EDGETUNNEL<small>XRAY CONTROL CENTER</small></div></div><div class="actions"><button class="secondary" id="theme" onclick="toggleTheme()">Light mode</button><button class="secondary" onclick="logout()">Log out</button></div></header><section class="hero"><div><div class="eyebrow">Gateway overview</div><h1>Command center</h1><p>Manage access, endpoints, and client profiles from one place.</p></div><div class="online">Dashboard connected</div></section><section class="layout"><div><section class="card"><h2>Gateway configuration</h2><p class="muted">Changes restart Xray and refresh all connection profiles.</p><form id="config"><label>Client UUID<input id="uuid" required></label><div class="fields"><label>VLESS path<input id="vless" required></label><label>VMess path<input id="vmess" required></label><label>Trojan path<input id="trojan" required></label><label>Shadowsocks path<input id="ss" required></label></div><button class="save">Save configuration</button><p class="status" id="status"></p></form></section><section class="card logs"><div class="log-head"><div><h2>Runtime logs</h2><p class="muted">Live process output</p></div><span class="live">AUTO-REFRESH 3S</span></div><pre id="logs">Loading...</pre></section></div><section class="card"><h2>Connection profiles</h2><p class="muted">Scan a QR code or copy a URI into your client.</p><section class="uri-grid" id="uris"></section></section></section></main><script>const savedTheme=localStorage.getItem('edgetunnel-theme')||'dark';document.documentElement.dataset.theme=savedTheme;function toggleTheme(){const next=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=next;localStorage.setItem('edgetunnel-theme',next);document.querySelector('#theme').textContent=next==='dark'?'Light mode':'Dark mode'}document.querySelector('#theme').textContent=savedTheme==='dark'?'Light mode':'Dark mode';
async function api(url, options){const r=await fetch(url,options);if(r.status===401){location='/dashboard/login';throw Error('login required')}const d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
function show(data){const quote=value=>"'"+value.replaceAll("'","\\'")+"'";document.querySelector('#uuid').value=data.uuid;for(const k of ['vless','vmess','trojan','ss'])document.querySelector('#'+k).value=data.paths[k];document.querySelector('#uris').innerHTML=Object.entries(data.uris).map(([k,v])=>'<article class="protocol"><h3>'+k.toUpperCase()+'</h3><div class="uri">'+v+'</div><div style="display:flex;gap:8px"><button class="secondary copy" style="flex:1;width:auto" onclick="openQr('+quote(data.qr[k])+','+quote(k)+')">QR code</button><button class="secondary copy" style="flex:1;width:auto" onclick="navigator.clipboard.writeText('+quote(v)+')">Copy URI</button></div></article>').join('')}
function openQr(source, name){let modal=document.querySelector('#qr-modal');if(!modal){modal=document.createElement('div');modal.id='qr-modal';modal.style='position:fixed;inset:0;z-index:10;display:grid;place-items:center;padding:20px;background:#03100dcc';modal.innerHTML='<div style="position:relative;width:min(360px,100%);padding:22px;background:#102124;border:1px solid #315c56;border-radius:18px;text-align:center;box-shadow:0 24px 80px #0009"><button id="qr-close" style="position:absolute;right:12px;top:12px;width:auto;padding:6px 10px;background:#1c3b38;color:#bde8dd;border:1px solid #416a63;border-radius:7px">Close</button><p id="qr-title" style="color:#70f1bc;font:800 12px system-ui;letter-spacing:.14em">QR CODE</p><div style="background:#f5fbf8;padding:14px;border-radius:10px"><img id="qr-image" style="display:block;width:100%;image-rendering:pixelated" alt="QR code"></div></div>';document.body.append(modal);document.querySelector('#qr-close').onclick=()=>modal.remove();modal.onclick=e=>{if(e.target===modal)modal.remove()};window.addEventListener('keydown',function closeQr(e){if(e.key==='Escape'){modal.remove();window.removeEventListener('keydown',closeQr)}})}document.querySelector('#qr-title').textContent=name.toUpperCase()+' QR CODE';document.querySelector('#qr-image').src=source;modal.style.display='grid'}
function renderLogs(logs){const output=document.querySelector('#logs');output.textContent=logs.join('\\n');output.scrollTop=output.scrollHeight}
async function load(){try{show(await api('/api/config'));renderLogs((await api('/api/logs')).logs)}catch(e){document.querySelector('#status').textContent=e.message}}
async function logout(){await fetch('/api/logout',{method:'POST'});location='/dashboard/login'}load();setInterval(async()=>{try{renderLogs((await api('/api/logs')).logs)}catch{}},3000);
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
  if (requestPath === '/dashboard' && req.method === 'GET') { if (!authenticated(req)) return res.writeHead(302, { location: '/dashboard/login' }).end(); const page = dashboardPage.replaceAll('EdgeTunnel', 'ZFTunnel by Velocity').replaceAll('EDGETUNNEL', 'ZFTUNNEL').replaceAll('edgetunnel-theme', 'zftunnel-theme'); return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(page); }
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
