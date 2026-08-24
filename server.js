#!/usr/bin/env node
const fs = require('fs');
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const { spawn, spawnSync } = require('child_process');
const QRCode = require('qrcode');

const runtimeLogs = [];
const traffic = { uploaded: 0, downloaded: 0, active: 0 };
const sessions = new Map();
const port = Number(process.env.PORT || 3000);
const defaultUuid = 'bb415533-7734-46e7-a989-74dba131f257';
const configuredConfigFile = process.env.GATEWAY_CONFIG_FILE || path.join(__dirname, 'data', 'gateway-config.json');
const fallbackConfigFile = path.join('/tmp', 'zftunnel-config.json');
let configFile = configuredConfigFile;
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
    if (validUuid(saved.uuid) && saved.paths && Object.values(saved.paths).every(validPath)) return { ...saved, paths: { ...saved.paths, xhttp: saved.paths.xhttp || '/xhttp_zhuofan' } };
  } catch (error) {
    if (error.code === 'EACCES' && configFile !== fallbackConfigFile) {
      configFile = fallbackConfigFile;
      return loadGatewayConfig();
    }
    if (error.code !== 'ENOENT') recordLog(`Configuration load error: ${error.message}`);
  }
  return {
    uuid: defaultUuid,
    paths: { vless: '/vless_zhuofan', vmess: '/vmess_zhuofan', trojan: '/trojan-ws_zhuofan', ss: '/ss-ws_zhuofan', xhttp: '/xhttp_zhuofan' }
  };
}

let gatewayConfig = loadGatewayConfig();
function saveGatewayConfig(next) {
  try {
    fs.mkdirSync(path.dirname(configFile), { recursive: true });
    const temporary = `${configFile}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(next, null, 2), { mode: 0o600 });
    fs.renameSync(temporary, configFile);
  } catch (error) {
    if (error.code !== 'EACCES' || configFile === fallbackConfigFile) throw error;
    configFile = fallbackConfigFile;
    saveGatewayConfig(next);
    recordLog('Persistent configuration path is not writable; using temporary runtime storage');
  }
}

function xrayConfig() {
  const inbounds = [
    ['vless', 14016, { decryption: 'none', clients: [{ id: gatewayConfig.uuid }] }],
    ['vmess', 23456, { clients: [{ id: gatewayConfig.uuid, alterId: 0 }] }],
    ['trojan', 25432, { clients: [{ password: gatewayConfig.uuid }] }],
    ['shadowsocks', 30300, { clients: [{ method: 'aes-128-gcm', password: gatewayConfig.uuid }] }],
    ['vless', 14443, { decryption: 'none', clients: [{ id: gatewayConfig.uuid, email: gatewayConfig.uuid }] }, 'xhttp']
  ];
  return {
    log: { access: '', error: '', loglevel: process.env.XRAY_LOGLEVEL || 'warning' },
    inbounds: inbounds.map(([protocol, inboundPort, settings, transport = protocol]) => ({
      listen: '127.0.0.1', port: inboundPort, protocol, settings,
      streamSettings: transport === 'xhttp' ? { network: 'xhttp', security: 'none', xhttpSettings: { path: gatewayConfig.paths.xhttp, mode: 'auto' } } : { network: 'ws', security: 'none', wsSettings: { path: gatewayConfig.paths[protocol === 'shadowsocks' ? 'ss' : transport] } }
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
    ss: `ss://${Buffer.from(`aes-128-gcm:${gatewayConfig.uuid}`).toString('base64url')}@${host}:443/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bpath%3D${encoded(gatewayConfig.paths.ss)}%3Bhost%3D${encoded(host)}#${encoded(label + ' Shadowsocks')}`,
    xhttp: `vless://${gatewayConfig.uuid}@${host}:443?encryption=none&security=tls&type=xhttp&mode=auto&host=${encoded(host)}&path=${encoded(gatewayConfig.paths.xhttp)}#${encoded(label + ' XHTTP')}`
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
async function networkProbe(url) {
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, { signal: controller.signal, redirect: 'follow' });
    return { ok: true, status: response.status, latency: Date.now() - started };
  } catch (error) {
    return { ok: false, error: error.name === 'AbortError' ? 'timeout' : error.message, latency: Date.now() - started };
  } finally {
    clearTimeout(timeout);
  }
}
async function networkInformation(req) {
  const testTargets = [
    ['ByteDance Douyin', 'https://www.douyin.com', 'DOMESTIC'],
    ['Bilibili', 'https://www.bilibili.com', 'DOMESTIC'],
    ['Tencent WeChat', 'https://weixin.qq.com', 'DOMESTIC'],
    ['Alibaba Taobao', 'https://www.taobao.com', 'DOMESTIC'],
    ['GitHub', 'https://github.com', 'INTERNATIONAL'],
    ['Telegram DC5', 'https://telegram.org', 'INTERNATIONAL'],
    ['X.com', 'https://x.com', 'INTERNATIONAL'],
    ['YouTube', 'https://www.youtube.com', 'INTERNATIONAL']
  ];
  const [ipResult, cloudflareResult, ...tests] = await Promise.all([
    fetch('https://api.ipify.org?format=json').then(response => response.json()).catch(() => ({})),
    fetch('https://www.cloudflare.com/cdn-cgi/trace').then(response => response.text()).catch(() => ''),
    ...testTargets.map(async ([name, url, region]) => ({ name, region, ...(await networkProbe(url)) }))
  ]);
  const trace = Object.fromEntries(cloudflareResult.split('\n').filter(line => line.includes('=')).map(line => line.split('=')));
  return {
    host: publicHost(req),
    protocol: req.headers['x-forwarded-proto'] || 'http',
    xray: xray ? 'online' : 'offline',
    uptime: Math.floor(process.uptime()),
    runtime: `Node ${process.version} · ${process.platform}/${process.arch}`,
    inbounds: { vless: 14016, vmess: 23456, trojan: 25432, shadowsocks: 30300, xhttp: 14443 },
    interfaces: Object.keys(os.networkInterfaces()).filter(name => name !== 'lo'),
    publicIp: ipResult.ip || 'unavailable',
    location: trace.loc || 'unknown',
    cloudflareIp: trace.ip || 'unavailable',
    tests
  };
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
function show(data){const quote=value=>"'"+value.replaceAll("'","\\'")+"'";if(!document.querySelector('#uri-card-style')){const style=document.createElement('style');style.id='uri-card-style';style.textContent='.uri-grid{grid-template-columns:1fr!important}.protocol{display:grid;grid-template-columns:180px minmax(0,1fr) auto;align-items:center;gap:14px;padding:14px 16px!important;background:#fff!important;border:1px solid #e5e7eb!important;border-radius:10px!important;box-shadow:0 1px 3px #00000014!important}.protocol h3{margin:0!important;color:#374151!important;font:600 12px Inter,system-ui,sans-serif!important;letter-spacing:.02em!important}.protocol .uri{min-width:0;margin:0!important;padding:10px 12px!important;background:#f9fafb!important;border:1px solid #d1d5db!important;border-radius:7px!important;color:#4b5563!important;font:12px ui-monospace,monospace!important;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.protocol>div:last-child{display:flex;justify-content:flex-end;gap:8px}.protocol .copy{width:auto!important;min-width:92px!important;padding:10px 14px!important;border:0!important;border-radius:8px!important;font-size:12px!important}.protocol .copy:first-child{background:linear-gradient(135deg,#06b6d4,#0891b2)!important;color:#fff!important;box-shadow:0 3px 10px #06b6d433}.protocol .copy:last-child{background:linear-gradient(135deg,#faab41,#f6821f)!important;color:#fff!important;box-shadow:0 3px 10px #f6821f33}.protocol .copy:hover{transform:translateY(-1px);filter:brightness(1.05)}[data-theme=dark] .protocol{background:#0b191b!important;border-color:#24423f!important}[data-theme=dark] .protocol h3{color:#70f1bc!important}[data-theme=dark] .protocol .uri{background:#071012!important;border-color:#1d3735!important;color:#aac7c0!important}@media(max-width:800px){.protocol{grid-template-columns:1fr;gap:9px}.protocol>div:last-child{justify-content:flex-end}}';document.head.append(style)}const logsPanel=document.querySelector('.logs');if(logsPanel)logsPanel.remove();const actions=document.querySelector('.actions');if(actions&&!document.querySelector('#logs-button')){const button=document.createElement('button');button.id='logs-button';button.className='secondary';button.textContent='Logs';button.onclick=openLogs;actions.insertBefore(button,actions.lastElementChild)}document.querySelector('#uuid').value=data.uuid;for(const k of ['vless','vmess','trojan','ss'])document.querySelector('#'+k).value=data.paths[k];document.querySelector('#uris').innerHTML=Object.entries(data.uris).map(([k,v])=>'<article class="protocol"><h3>'+k.toUpperCase()+'</h3><div class="uri" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'+v+'">'+v+'</div><div style="display:flex;justify-content:flex-end;gap:8px"><button class="secondary copy" style="flex:0 0 auto;width:auto" onclick="openQr('+quote(data.qr[k])+','+quote(k)+')">QR code</button><button class="secondary copy" style="flex:0 0 auto;width:auto" onclick="navigator.clipboard.writeText('+quote(v)+')">Copy URI</button></div></article>').join('')}
function openLogs(){let modal=document.querySelector('#logs-modal');if(!modal){modal=document.createElement('div');modal.id='logs-modal';modal.style='position:fixed;inset:0;z-index:10;display:grid;place-items:center;padding:20px;background:#03100dcc';modal.innerHTML='<div style="position:relative;width:min(900px,100%);padding:22px;background:#102124;border:1px solid #315c56;border-radius:18px;box-shadow:0 24px 80px #0009"><button id="logs-close" style="position:absolute;right:12px;top:12px;width:auto;padding:6px 10px;background:#1c3b38;color:#bde8dd;border:1px solid #416a63;border-radius:7px">Close</button><h2 style="margin:0 0 14px;color:#70f1bc;font-size:17px">Runtime logs</h2><pre id="logs" style="white-space:pre-wrap;max-height:65vh;min-height:240px;overflow:auto;background:#071012;border:1px solid #1d3735;padding:14px;border-radius:10px;color:#9fe8c4;font:12px/1.7 ui-monospace,monospace">Loading...</pre></div>';document.body.append(modal);document.querySelector('#logs-close').onclick=()=>modal.remove();modal.onclick=e=>{if(e.target===modal)modal.remove()}}modal.style.display='grid';api('/api/logs').then(data=>renderLogs(data.logs)).catch(()=>{});}
function openQr(source, name){let modal=document.querySelector('#qr-modal');if(!modal){modal=document.createElement('div');modal.id='qr-modal';modal.style='position:fixed;inset:0;z-index:10;display:grid;place-items:center;padding:20px;background:#03100dcc';modal.innerHTML='<div style="position:relative;width:min(360px,100%);padding:22px;background:#102124;border:1px solid #315c56;border-radius:18px;text-align:center;box-shadow:0 24px 80px #0009"><button id="qr-close" style="position:absolute;right:12px;top:12px;width:auto;padding:6px 10px;background:#1c3b38;color:#bde8dd;border:1px solid #416a63;border-radius:7px">Close</button><p id="qr-title" style="color:#70f1bc;font:800 12px system-ui;letter-spacing:.14em">QR CODE</p><div style="background:#f5fbf8;padding:14px;border-radius:10px"><img id="qr-image" style="display:block;width:100%;image-rendering:pixelated" alt="QR code"></div></div>';document.body.append(modal);document.querySelector('#qr-close').onclick=()=>modal.remove();modal.onclick=e=>{if(e.target===modal)modal.remove()};window.addEventListener('keydown',function closeQr(e){if(e.key==='Escape'){modal.remove();window.removeEventListener('keydown',closeQr)}})}document.querySelector('#qr-title').textContent=name.toUpperCase()+' QR CODE';document.querySelector('#qr-image').src=source;modal.style.display='grid'}
function compactUriCards(){const columns=window.innerWidth<=800?'1fr':'max-content minmax(0,1fr) auto';document.querySelectorAll('.protocol').forEach(card=>{card.style.gridTemplateColumns=columns})}
function openConfig(){const modal=document.querySelector('#config-modal');if(modal)modal.style.display='grid'}
function initializeConfigModal(){const panel=document.querySelector('#config')&&document.querySelector('#config').closest('.card');const layout=document.querySelector('.layout');if(!panel||document.querySelector('#config-modal'))return;if(layout&&layout.firstElementChild){layout.firstElementChild.remove();const profiles=layout.querySelector('.card');if(profiles)profiles.style.gridColumn='1/-1'}const modal=document.createElement('div');modal.id='config-modal';modal.style='position:fixed;inset:0;z-index:9;display:none;place-items:center;padding:20px;background:#03100dcc';const inner=document.createElement('div');inner.style='position:relative;width:min(620px,100%);max-height:90vh;overflow:auto;padding:22px;background:#102124;border:1px solid #315c56;border-radius:18px;box-shadow:0 24px 80px #0009';const close=document.createElement('button');close.textContent='Close';close.className='secondary';close.style='position:absolute;right:22px;top:22px;width:auto';close.onclick=()=>modal.style.display='none';inner.append(close);inner.append(panel);modal.append(inner);modal.onclick=e=>{if(e.target===modal)modal.style.display='none'};document.body.append(modal);const actions=document.querySelector('.actions');if(actions&&!document.querySelector('#config-button')){const button=document.createElement('button');button.id='config-button';button.className='secondary';button.textContent='Configuration';button.onclick=openConfig;actions.insertBefore(button,actions.firstElementChild)}window.addEventListener('keydown',e=>{if(e.key==='Escape'&&modal.style.display==='grid')modal.style.display='none'})}
function addXhttpConfig(){const form=document.querySelector('#config');const fields=form&&form.querySelector('.fields');if(!fields||document.querySelector('#xhttp'))return;const label=document.createElement('label');label.textContent='XHTTP path';const input=document.createElement('input');input.id='xhttp';input.required=true;label.append(input);fields.append(label)}
function addNetworkCard(){if(document.querySelector('#network-card'))return;const layout=document.querySelector('.layout');if(!layout)return;const card=document.createElement('section');card.id='network-card';card.className='card';card.style='margin-bottom:18px';card.innerHTML='<div style="display:flex;justify-content:space-between;align-items:start;gap:12px"><div><h2>Current network information</h2><p class="muted">Live gateway and runtime status</p></div><span id="network-status" class="online">Checking</span></div><div id="network-details" style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px"></div>';layout.parentNode.insertBefore(card,layout);}
async function refreshNetwork(){try{const data=await api('/api/network');const details=document.querySelector('#network-details');const status=document.querySelector('#network-status');if(!details)return;status.textContent=data.xray==='online'?'Xray online':'Xray offline';details.innerHTML=[['Public host',data.host],['Transport',data.protocol.toUpperCase()+' / port 443'],['Runtime',data.runtime],['Uptime',Math.floor(data.uptime/86400)+'d '+Math.floor(data.uptime%86400/3600)+'h '+Math.floor(data.uptime%3600/60)+'m'],['Inbound ports',Object.values(data.inbounds).join(' · ')],['Interfaces',data.interfaces.join(', ')||'none']].map(([label,value])=>'<div style="padding:11px 12px;border:1px solid #2c4e4b;border-radius:8px;background:#091416"><small style="display:block;color:#77918e;font-size:10px;text-transform:uppercase;letter-spacing:.08em">'+label+'</small><strong style="display:block;margin-top:4px;font:12px ui-monospace,monospace;word-break:break-word">'+value+'</strong></div>').join('')}catch{}}
function bindConfigForm(){const form=document.querySelector('#config');if(!form)return;form.onsubmit=async event=>{event.preventDefault();const paths={};for(const key of ['vless','vmess','trojan','ss','xhttp'])paths[key]=document.querySelector('#'+key).value;try{const data=await api('/api/config',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({uuid:document.querySelector('#uuid').value,paths})});show(data);document.querySelector('#xhttp').value=data.paths.xhttp;document.querySelector('#status').textContent='Saved and Xray restarted.'}catch(error){document.querySelector('#status').textContent=error.message}}}
function arrangeActions(){const actions=document.querySelector('.actions');const logoutButton=actions&&actions.querySelector('button[onclick="logout()"]');if(!actions||!logoutButton)return;for(const id of ['config-button','logs-button','theme']){const button=document.querySelector('#'+id);if(button)actions.insertBefore(button,logoutButton)}}
function renderLogs(logs){const output=document.querySelector('#logs');if(!output)return;output.textContent=logs.join('\\n');output.scrollTop=output.scrollHeight}
async function load(){try{const data=await api('/api/config');show(data);compactUriCards();initializeConfigModal();addXhttpConfig();addNetworkCard();ensureNetworkTests();ensureTrafficCounter();document.querySelector('#xhttp').value=data.paths.xhttp;bindConfigForm();arrangeActions();await refreshNetwork();syncNetworkSummaryTheme();renderNetworkTests();await refreshTraffic();renderLogs((await api('/api/logs')).logs)}catch(e){document.querySelector('#status').textContent=e.message}}
async function logout(){await fetch('/api/logout',{method:'POST'});location='/dashboard/login'}window.addEventListener('resize',compactUriCards);load();setInterval(async()=>{try{renderLogs((await api('/api/logs')).logs)}catch{}},3000);
function ensureNetworkTests(){const card=document.querySelector('#network-card');if(!card||document.querySelector('#network-tests'))return;const section=document.createElement('div');section.id='network-tests';section.style='margin-top:18px';const observer=new MutationObserver(()=>{const heading=section.querySelector('h3');if(heading)heading.style.display='none'});observer.observe(section,{childList:true});card.append(section)}
async function renderNetworkTests(){try{const data=await api('/api/network');const target=document.querySelector('#network-tests');if(!target)return;const rows=[['Domestic testing','ByteDance Douyin',data.publicIp,data.location,'IP used for domestic destinations'],['Overseas testing','Fish that slipped through the net',data.publicIp,data.location,'IP used for international destinations'],['Cloudflare','ProxyIPv4',data.cloudflareIp,data.location,'Landing IP used for Cloudflare CDN'],['External testing','Google / Twitter (X.com)',data.publicIp,data.location,'IP used for external destinations']];target.innerHTML='<h3 style="margin:0 0 12px;font-size:14px">🌍 Current network information</h3>'+rows.map(row=>'<div style="display:grid;grid-template-columns:minmax(150px,.7fr) minmax(0,1.3fr);gap:4px 14px;padding:12px 0;border-top:1px solid #2c4e4b"><strong style="font-size:12px">'+row[0]+'</strong><span style="font-size:12px;color:#9eb9b4">'+row[1]+'</span><span style="font:12px ui-monospace,monospace;color:#70f1bc">'+row[2]+'</span><span style="font-size:11px;color:#77918e">'+row[3]+' · '+row[4]+'</span></div>').join('')+'<h3 style="margin:18px 0 10px;font-size:14px">Connectivity checks</h3><div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px">'+data.tests.map(test=>'<div style="display:flex;justify-content:space-between;gap:8px;padding:9px 10px;border:1px solid #2c4e4b;border-radius:8px;background:#091416"><span style="font-size:12px">'+test.name+'</span><strong style="font:12px ui-monospace,monospace;color:'+(test.ok?'#70f1bc':'#fca5a5')+'">'+(test.ok?test.latency+' ms':test.error)+'</strong></div>').join('')+'</div>'}catch{}}
async function renderEdgeNetworkCards(){try{const data=await api('/api/network');const target=document.querySelector('#network-tests');if(!target)return;const rows=[['Domestic testing','ByteDance Douyin',data.publicIp,data.location,'The IP address used to access domestic websites'],['Overseas testing','Fish that slipped through the net',data.publicIp,data.location,'The IP address used to access unblocked foreign websites'],['Cloudflare','ProxyIPv4',data.cloudflareIp,data.location,'The landing IP used to access the Cloudflare CDN'],['External testing','Google / Twitter (X.com)',data.publicIp,data.location,'The IP address used to access Google']];target.innerHTML='<div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px">'+rows.map(row=>'<article style="padding:16px;border:1px solid #d1d5db;border-radius:14px;background:#fff;box-shadow:0 4px 6px #0000000d"><div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #e5e7eb"><span style="width:10px;height:10px;border-radius:50%;background:#4caf50;box-shadow:0 0 5px #4caf50"></span><div><strong style="display:block;font-size:14px">'+row[0]+'</strong><small style="color:#6b7280">'+row[1]+'</small></div></div><strong style="display:block;font-size:18px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#333">'+row[2]+'</strong><div style="margin:8px 0;color:#666;font-size:14px">'+row[3]+'</div><small style="display:block;color:#999;font-size:12px">· '+row[4]+'</small></article>').join('')+'</div><small style="display:block;margin-top:10px;color:#9ca3af;font-size:12px">💡 These checks represent the Cloudways server outbound network.</small><h3 style="margin:18px 0 10px;font-size:14px">Connectivity checks</h3><div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px">'+data.tests.map(test=>'<div style="display:flex;justify-content:space-between;gap:8px;padding:12px;border:1px solid #d1d5db;border-radius:10px;background:#fff"><span style="font-size:12px">'+test.name+'</span><strong style="font:12px ui-monospace,monospace;color:'+(test.ok?'#16a34a':'#dc2626')+'">'+(test.ok?test.latency+' ms':test.error)+'</strong></div>').join('')+'</div>';syncNetworkTheme()}catch{}}
function syncNetworkTheme(){const target=document.querySelector('#network-tests');if(!target)return;const dark=document.documentElement.dataset.theme==='dark';const surface=dark?'#0b191b':'#fff';const border=dark?'#24423f':'#d1d5db';const text=dark?'#e8f3f1':'#333';const muted=dark?'#aac7c0':'#6b7280';target.querySelectorAll('article,article~*').forEach(element=>{if(element.tagName==='ARTICLE'||element.style.display==='flex'){element.style.background=surface;element.style.borderColor=border}});target.querySelectorAll('article').forEach(card=>{card.style.background=surface;card.style.borderColor=border;card.querySelector('strong[style*="font-size:18px"]').style.color=text;card.querySelectorAll('small').forEach(item=>item.style.color=muted);card.querySelector('div[style*="border-bottom"]').style.borderColor=border});const latency=target.lastElementChild;[...(latency?.children||[])].forEach(item=>{item.style.background=surface;item.style.borderColor=border;item.firstElementChild.style.color=text})}
function syncNetworkSummaryTheme(){const details=document.querySelector('#network-details');if(!details)return;const dark=document.documentElement.dataset.theme==='dark';const surface=dark?'#091416':'#f7fbfa';const border=dark?'#2c4e4b':'#c8ded7';const text=dark?'#e8f3f1':'#17332f';const muted=dark?'#77918e':'#56736d';details.querySelectorAll('div').forEach((tile,index)=>{tile.style.background=surface;tile.style.borderColor=border;tile.style.display=index>1?'none':'';tile.querySelectorAll('strong').forEach(item=>item.style.color=text);tile.querySelectorAll('small').forEach(item=>item.style.color=muted)})}
function countryFlag(code){return /^[A-Z]{2}$/.test(code)?String.fromCodePoint(...[...code].map(letter=>127397+letter.charCodeAt(0))):'🌐'}
function addNetworkFlags(){const target=document.querySelector('#network-tests');if(!target)return;target.querySelectorAll('article').forEach(card=>{if(card.dataset.flagAdded)return;const location=card.querySelector('div[style*="margin:8px"]');const ip=card.querySelector('strong[style*="font-size:18px"]');if(!location||!ip)return;const code=location.textContent.trim().slice(0,2).toUpperCase();const flag=countryFlag(code);ip.textContent=flag+' '+ip.textContent;location.textContent=flag+' '+location.textContent;card.dataset.flagAdded='true'})}
function ensureTrafficCounter(){const card=document.querySelector('#network-card');if(!card||document.querySelector('#traffic-counter'))return;const counter=document.createElement('div');counter.id='traffic-counter';counter.style='margin-top:18px;padding-top:16px;border-top:1px solid #2c4e4b';counter.innerHTML='<h3 style="margin:0 0 10px;font-size:14px">Traffic counter</h3><div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px"><div><small style="color:#77918e">UPLOADED</small><strong id="traffic-up" style="display:block;color:#70f1bc">0 B</strong></div><div><small style="color:#77918e">DOWNLOADED</small><strong id="traffic-down" style="display:block;color:#70f1bc">0 B</strong></div><div><small style="color:#77918e">ACTIVE</small><strong id="traffic-active" style="display:block;color:#70f1bc">0</strong></div></div>';card.append(counter)}
async function refreshTraffic(){try{const data=await api('/api/traffic');const format=bytes=>{if(!bytes)return'0 B';const units=['B','KB','MB','GB','TB'];const index=Math.min(Math.floor(Math.log(bytes)/Math.log(1024)),units.length-1);return(bytes/1024**index).toFixed(index?2:0)+' '+units[index]};document.querySelector('#traffic-up').textContent=format(data.uploaded);document.querySelector('#traffic-down').textContent=format(data.downloaded);document.querySelector('#traffic-active').textContent=data.active}catch{}}
function syncModalTheme(){const dark=document.documentElement.dataset.theme==='dark';document.documentElement.style.colorScheme=dark?'dark':'light';const surface=dark?'#102124':'#fff';const border=dark?'#315c56':'#c8ded7';const text=dark?'#e8f3f1':'#17332f';for(const id of ['config-modal','logs-modal','qr-modal']){const modal=document.querySelector('#'+id);if(!modal)continue;const panel=modal.firstElementChild;if(panel){panel.style.background=surface;panel.style.borderColor=border;panel.style.color=text;panel.querySelectorAll('h2').forEach(item=>item.style.color=dark?'#70f1bc':'#17332f');panel.querySelectorAll('button').forEach(item=>{if(item.id.endsWith('close')){item.style.background=dark?'#1c3b38':'#e4f3ee';item.style.color=dark?'#bde8dd':'#24574c';item.style.borderColor=border}})}}}
setInterval(()=>{ensureNetworkTests();ensureTrafficCounter();refreshNetwork().then(syncNetworkSummaryTheme);renderNetworkTests();renderEdgeNetworkCards();refreshTraffic()},30000);setInterval(refreshTraffic,3000);setTimeout(()=>{ensureNetworkTests();ensureTrafficCounter();renderEdgeNetworkCards();syncNetworkSummaryTheme();syncModalTheme();addNetworkFlags()},1000);new MutationObserver(()=>{syncNetworkTheme();syncNetworkSummaryTheme();syncModalTheme()}).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});new MutationObserver(()=>{syncModalTheme();addNetworkFlags()}).observe(document.body,{childList:true,subtree:true});</script></body></html>`;

function targets() {
  return { [gatewayConfig.paths.vless]: 14016, [gatewayConfig.paths.vmess]: 23456, [gatewayConfig.paths.trojan]: 25432, [gatewayConfig.paths.ss]: 30300, [gatewayConfig.paths.xhttp]: 14443 };
}
function resolveTarget(requestPath) {
  const routeMap = targets();
  if (routeMap[requestPath]) return routeMap[requestPath];
  if (requestPath.startsWith(`${gatewayConfig.paths.xhttp}/`)) return routeMap[gatewayConfig.paths.xhttp];
  return undefined;
}
function forwardHttp(req, res, targetPort) {
  traffic.active += 1;
  req.on('data', chunk => { traffic.uploaded += chunk.length; });
  const upstream = http.request({ hostname: '127.0.0.1', port: targetPort, path: req.url, method: req.method, headers: req.headers, timeout: 3600000 }, upstreamRes => { res.writeHead(upstreamRes.statusCode, upstreamRes.headers); upstreamRes.on('data', chunk => { traffic.downloaded += chunk.length; }); upstreamRes.pipe(res); });
  upstream.on('timeout', () => upstream.destroy());
  upstream.on('error', error => { recordLog(`Proxy error: ${error.message}`); if (!res.headersSent) res.writeHead(502); res.end('Bad gateway'); });
  upstream.on('close', () => { traffic.active = Math.max(0, traffic.active - 1); });
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
  if (requestPath === '/api/network' && req.method === 'GET') { if (!requireAuth(req, res)) return; return sendJson(res, 200, await networkInformation(req)); }
  if (requestPath === '/api/traffic' && req.method === 'GET') { if (!requireAuth(req, res)) return; return sendJson(res, 200, traffic); }
  if (requestPath === '/') return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>Made by Zhuo Fan</title></head><body style="background:#1c1c1c;color:white;font:28px Arial;text-align:center;padding-top:20vh"><p>Made by</p><h1>Zhuo Fan</h1></body></html>');
  if (requestPath === '/pass') { if (process.env.EXPOSE_PASS !== 'true') return res.writeHead(404).end('Not found'); return res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }).end(`UUID: ${gatewayConfig.uuid}\nVLESS_PATH: ${gatewayConfig.paths.vless}\nVMESS_PATH: ${gatewayConfig.paths.vmess}\nTROJAN_PATH: ${gatewayConfig.paths.trojan}\nSS_PATH: ${gatewayConfig.paths.ss}\n`); }
  if (requestPath === '/logs') { if (process.env.DEBUG_LOGS !== 'true') return res.writeHead(404).end('Not found'); return res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }).end(runtimeLogs.join('\n') || 'No runtime logs yet.'); }
  const targetPort = resolveTarget(requestPath);
  if (targetPort) return forwardHttp(req, res, targetPort);
  res.writeHead(404).end('Not found');
});
server.on('upgrade', (req, socket, head) => { const targetPort = resolveTarget(req.url.split('?')[0]); if (!targetPort) return socket.destroy(); traffic.active += 1; const upstream = net.connect(targetPort, '127.0.0.1', () => { let request = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`; for (let i = 0; i < req.rawHeaders.length; i += 2) request += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`; upstream.write(`${request}\r\n`); if (head.length) upstream.write(head); socket.on('data', chunk => { traffic.uploaded += chunk.length; }); upstream.on('data', chunk => { traffic.downloaded += chunk.length; }); socket.pipe(upstream).pipe(socket); }); upstream.setTimeout(3600000); upstream.on('error', error => { recordLog(`WebSocket proxy error: ${error.message}`); socket.destroy(); }); upstream.on('close', () => { traffic.active = Math.max(0, traffic.active - 1); }); socket.on('error', () => upstream.destroy()); });
function shutdown(signal) { server.close(() => { if (xray) xray.kill('SIGTERM'); fs.rmSync(configPath, { force: true }); process.exit(0); }); setTimeout(() => process.exit(1), 10000).unref(); console.log(`Received ${signal}; shutting down`); }
process.on('SIGTERM', () => shutdown('SIGTERM')); process.on('SIGINT', () => shutdown('SIGINT'));
server.listen(port, '0.0.0.0', () => { console.log(`Listening on ${port}`); console.log(`Dashboard: /dashboard`); });
