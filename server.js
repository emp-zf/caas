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
const speedSamples = [];
let speedLastTotals = null;
setInterval(() => {
  const now = Date.now();
  const totals = { uploaded: traffic.uploaded, downloaded: traffic.downloaded };
  if (speedLastTotals) {
    const up = Math.max(0, totals.uploaded - speedLastTotals.uploaded);
    const down = Math.max(0, totals.downloaded - speedLastTotals.downloaded);
    speedSamples.push({ t: now, up, down });
    if (speedSamples.length > 30) speedSamples.shift();
  }
  speedLastTotals = totals;
}, 1000).unref();
const sessions = new Map();
let networkCache = null;
let networkCacheAt = 0;
let networkInflight = null;
const NETWORK_CACHE_TTL_MS = 30000;
const port = Number(process.env.PORT || 3000);
const defaultUuid = '769c35e2-2cad-44db-8df3-784b2d634079';
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
      streamSettings: { ...(transport === 'xhttp' ? { network: 'xhttp', security: 'none', xhttpSettings: { path: gatewayConfig.paths.xhttp, mode: 'auto' } } : { network: 'ws', security: 'none', wsSettings: { path: gatewayConfig.paths[protocol === 'shadowsocks' ? 'ss' : transport] } }), sockopt: { trustedXForwardedFor: ['127.0.0.1'] } }
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
  if (fs.existsSync(xrayPath)) {
    let pinned = '';
    try {
      const src = fs.readFileSync(path.join(__dirname, 'build-xray.js'), 'utf8');
      pinned = (src.match(/const version = '([^']+)'/) || [])[1] || '';
    } catch (error) {}
    const probe = spawnSync(xrayPath, ['version'], { encoding: 'utf8', timeout: 10000 });
    const installed = (probe.stdout || probe.stderr || '').split('\n')[0] || '';
    if (pinned && installed && !installed.includes(pinned)) {
      recordLog(`Xray binary is ${installed.split(' ')[1] || 'unknown'}; updating to ${pinned}`);
      const install = spawnSync(process.execPath, [path.join(__dirname, 'build-xray.js')], { env: process.env, encoding: 'utf8' });
      if (install.stdout) recordLog(`Xray install: ${install.stdout}`);
      if (install.stderr) recordLog(`Xray install error: ${install.stderr}`);
    }
  }
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
  const timeout = setTimeout(() => controller.abort(), 4000);
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
  if (networkCache && Date.now() - networkCacheAt < NETWORK_CACHE_TTL_MS) {
    return { ...networkCache, host: publicHost(req), protocol: req.headers['x-forwarded-proto'] || 'http' };
  }
  if (networkInflight) return networkInflight;
  networkInflight = (async () => {
    try {
      return await refreshNetworkData(req);
    } finally {
      networkInflight = null;
    }
  })();
  return networkInflight;
}
async function refreshNetworkData(req) {
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
  networkCache = {
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
  networkCacheAt = Date.now();
  return networkCache;
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

const loginPage = `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>ZFTunnel by Velocity · Sign in</title><style>
:root{color-scheme:dark;--field:#05090d;--field-2:#0a1418;--orb-a:#12d9a0;--orb-b:#0ea5e9;--orb-c:#8b5cf6;--glass:rgba(255,255,255,.06);--glass-2:rgba(255,255,255,.10);--surface:rgba(255,255,255,.05);--stroke:rgba(255,255,255,.14);--stroke-hi:rgba(255,255,255,.24);--ink:#e8f3f1;--muted:#b6d2cc;--accent:#5ef2c3;--accent-ink:#062019;--r-card:20px;--r-ctl:12px;--shadow-card:0 24px 60px rgba(0,0,0,.38);--blur:20px;--ease:cubic-bezier(.22,1,.36,1);--dur-2:240ms;--dur-3:420ms}
[data-theme=light]{color-scheme:light;--field:#eef4f1;--field-2:#f7faf8;--orb-a:#7ce8c8;--orb-b:#a5d8f5;--orb-c:#d9c8f7;--glass:rgba(255,255,255,.65);--glass-2:rgba(255,255,255,.80);--surface:rgba(255,255,255,.80);--stroke:rgba(255,255,255,.72);--stroke-hi:#ffffff;--ink:#0f2724;--muted:#55706a;--accent:#0d9488;--accent-ink:#ffffff;--shadow-card:0 24px 60px rgba(13,50,45,.14)}
*{box-sizing:border-box}html,body{margin:0}body{min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 45% 55%,rgba(18,217,160,.16),transparent 42%),radial-gradient(circle at 85% 15%,rgba(14,165,233,.12),transparent 40%),radial-gradient(circle at 15% 90%,rgba(139,92,246,.14),transparent 45%),var(--field);color:var(--ink);font:15px/1.5 Inter,ui-sans-serif,system-ui,sans-serif;transition:background var(--dur-2) var(--ease),color var(--dur-2) var(--ease)}
.field{position:fixed;inset:0;z-index:-1;overflow:visible;background:linear-gradient(180deg,var(--field),var(--field-2))}
.orb{position:absolute;border-radius:50%;filter:blur(90px);will-change:transform}
.orb-a{width:540px;height:540px;left:-140px;top:-120px;background:var(--orb-a);opacity:.34;animation:drift-a 32s var(--ease) infinite alternate}
.orb-b{width:480px;height:480px;right:-120px;top:18%;background:var(--orb-b);opacity:.30;animation:drift-b 38s var(--ease) infinite alternate}
.orb-c{width:440px;height:440px;left:28%;bottom:-160px;background:var(--orb-c);opacity:.28;animation:drift-c 30s var(--ease) infinite alternate}
@keyframes drift-a{from{transform:translate(0,0) scale(1)}to{transform:translate(80px,60px) scale(1.08)}}
@keyframes drift-b{from{transform:translate(0,0) scale(1)}to{transform:translate(-70px,50px) scale(1.05)}}
@keyframes drift-c{from{transform:translate(0,0) scale(1)}to{transform:translate(50px,-60px) scale(1.1)}}
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;padding:0!important}.icon-btn svg{display:block}.login{position:relative;width:min(420px,calc(100% - 32px));padding:36px;background:radial-gradient(70% 55% at 50% 42%,rgba(18,217,160,.10),transparent 62%),var(--glass);backdrop-filter:blur(var(--blur)) saturate(1.5);-webkit-backdrop-filter:blur(var(--blur)) saturate(1.5);border:1px solid var(--stroke);border-radius:var(--r-card);box-shadow:var(--shadow-card),inset 0 1px 0 var(--stroke-hi);animation:rise var(--dur-3) var(--ease) both}
.mark{display:flex;align-items:center;gap:10px;color:var(--accent);font-size:13px;font-weight:600}
.mark i{display:block;width:11px;height:11px;background:var(--accent);border-radius:50%;box-shadow:0 0 18px var(--accent);animation:pulse-dot 2.4s var(--ease) infinite}
.login h1{margin:30px 0 8px;font-size:32px;letter-spacing:-.03em;font-weight:600;color:var(--ink)}
.login p{margin:0 0 26px;color:var(--muted)}
label{display:block;margin:16px 0;color:var(--muted);font-size:14px;font-weight:500}
input{display:block;width:100%;margin-top:8px;padding:13px 14px;border:1px solid var(--stroke);border-radius:10px;background:var(--surface);color:var(--ink);outline:none;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);transition:border-color var(--dur-2) var(--ease),box-shadow var(--dur-2) var(--ease)}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
button{width:100%;padding:15px 16px;border:0;border-radius:12px;background:linear-gradient(135deg,var(--accent),color-mix(in srgb,var(--accent) 70%,var(--orb-b)));color:var(--accent-ink);font:600 15px Inter,ui-sans-serif,system-ui,sans-serif;cursor:pointer;margin-top:12px;transition:transform var(--dur-2) var(--ease),filter var(--dur-2) var(--ease)}
button:hover{filter:brightness(1.06);transform:translateY(-1px)}
button:active{transform:scale(.98)}
button.theme{position:absolute;right:20px;top:20px;width:38px;height:38px;padding:0;margin:0;display:inline-flex;align-items:center;justify-content:center;background:var(--glass);color:var(--ink);border:1px solid var(--stroke);border-radius:12px;backdrop-filter:blur(var(--blur));transition:border-color var(--dur-2) var(--ease),background var(--dur-2) var(--ease)}button.theme:hover{border-color:var(--stroke-hi);background:var(--glass-2)}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse-dot{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--accent) 55%,transparent)}70%{box-shadow:0 0 0 9px transparent}100%{box-shadow:0 0 0 0 transparent}}
@media (prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}.orb{animation:none}}
</style></head><body>
<div class="field" aria-hidden="true"><i class="orb orb-a"></i><i class="orb orb-b"></i><i class="orb orb-c"></i></div>
<form class="login" method="post" action="/dashboard/login"><button type="button" class="theme icon-btn" id="theme" onclick="toggleTheme()" aria-label="Toggle light/dark mode" title="Toggle theme"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg></button><div class="mark"><i data-seenry-dot></i><span style="font-weight:600">ZFTUNNEL</span> <span style="font-weight:500">BY VELOCITY</span></div><h1>Welcome back</h1><p>Sign in to manage your secure gateway.</p><label>Username<input name="username" autocomplete="username" placeholder="admin" required></label><label>Password<input name="password" type="password" autocomplete="current-password" placeholder="••••••••" required></label><button>Sign in to dashboard</button></form><script>const savedTheme=localStorage.getItem('zftunnel-theme')||'dark';document.documentElement.dataset.theme=savedTheme;function toggleTheme(){const next=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=next;localStorage.setItem('zftunnel-theme',next);const t=document.querySelector('#theme');t.innerHTML=next==='dark'?'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg>':'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'}const t0=document.querySelector('#theme');t0.innerHTML=savedTheme==='dark'?'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg>':'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'</script></body></html>
`;
const dashboardPage = `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>EdgeTunnel · Dashboard</title><style>
:root{color-scheme:dark;--field:#05090d;--field-2:#0a1418;--orb-a:#12d9a0;--orb-b:#0ea5e9;--orb-c:#8b5cf6;--glass:rgba(255,255,255,.06);--glass-2:rgba(255,255,255,.10);--surface:rgba(255,255,255,.05);--surface-2:rgba(10,20,24,.78);--stroke:rgba(255,255,255,.14);--stroke-hi:rgba(255,255,255,.24);--ink:#e8f3f1;--muted:#b6d2cc;--accent:#5ef2c3;--accent-ink:#062019;--danger:#ff6b81;--ok:#5ef2c3;--r-card:20px;--r-ctl:12px;--r-pill:999px;--shadow-card:0 24px 60px rgba(0,0,0,.38);--shadow-surface:0 8px 24px rgba(0,0,0,.20);--blur:20px;--ease:cubic-bezier(.22,1,.36,1);--dur-1:140ms;--dur-2:240ms;--dur-3:420ms}
[data-theme=light]{color-scheme:light;--field:#eef4f1;--field-2:#f7faf8;--orb-a:#7ce8c8;--orb-b:#a5d8f5;--orb-c:#d9c8f7;--glass:rgba(255,255,255,.65);--glass-2:rgba(255,255,255,.80);--surface:rgba(255,255,255,.62);--surface-2:rgba(255,255,255,.88);--stroke:rgba(13,50,45,.14);--stroke-hi:rgba(255,255,255,.9);--ink:#0f2724;--muted:#55706a;--accent:#0d9488;--accent-ink:#ffffff;--danger:#d64550;--ok:#0d9488;--shadow-card:0 24px 60px rgba(13,50,45,.14);--shadow-surface:0 8px 24px rgba(13,50,45,.08)}
*{box-sizing:border-box}html,body{margin:0}body{min-height:100vh;background:radial-gradient(circle at 8% -5%,rgba(18,217,160,.10),transparent 70%),radial-gradient(circle at 92% 12%,rgba(14,165,233,.08),transparent 68%),radial-gradient(circle at 50% 62%,rgba(14,165,233,.04),transparent 75%),radial-gradient(circle at 45% 108%,rgba(139,92,246,.10),transparent 72%),var(--field);color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,sans-serif;transition:background var(--dur-2) var(--ease),color var(--dur-2) var(--ease)}
.field{position:fixed;inset:0;z-index:-1;overflow:hidden;background:linear-gradient(180deg,var(--field),var(--field-2));transition:background var(--dur-2) var(--ease)}
.orb{position:absolute;border-radius:50%;filter:blur(90px);will-change:transform;transition:background var(--dur-2) var(--ease)}
.orb-a{width:540px;height:540px;left:-140px;top:-120px;background:var(--orb-a);opacity:.34;animation:drift-a 32s var(--ease) infinite alternate}
.orb-b{width:480px;height:480px;right:-120px;top:18%;background:var(--orb-b);opacity:.30;animation:drift-b 38s var(--ease) infinite alternate}
.orb-c{width:440px;height:440px;left:28%;bottom:-160px;background:var(--orb-c);opacity:.28;animation:drift-c 30s var(--ease) infinite alternate}
@keyframes drift-a{from{transform:translate(0,0) scale(1)}to{transform:translate(80px,60px) scale(1.08)}}
@keyframes drift-b{from{transform:translate(0,0) scale(1)}to{transform:translate(-70px,50px) scale(1.05)}}
@keyframes drift-c{from{transform:translate(0,0) scale(1)}to{transform:translate(50px,-60px) scale(1.1)}}
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;padding:0!important}.icon-btn svg{display:block}.shell{max-width:1240px;margin:auto;padding:28px 24px 48px;position:relative}
.topbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px 16px;margin-bottom:40px;animation:rise var(--dur-3) var(--ease) both}
.brand{display:flex;align-items:center;gap:12px;font-weight:600;letter-spacing:.12em;color:var(--ink)}
.brand i{width:12px;height:12px;display:block;border-radius:50%;background:var(--accent);box-shadow:0 0 20px var(--accent);animation:pulse-dot 2.4s var(--ease) infinite}
.brand small{display:block;color:var(--muted);font-size:10px;letter-spacing:.08em;font-weight:500;margin-top:4px}
.actions{display:flex;gap:10px;align-items:center}
button{font:500 13px Inter,ui-sans-serif,system-ui,sans-serif;border-radius:var(--r-ctl);border:1px solid var(--stroke);background:var(--glass);color:var(--ink);padding:10px 16px;cursor:pointer;backdrop-filter:blur(var(--blur));-webkit-backdrop-filter:blur(var(--blur));transition:transform var(--dur-1) var(--ease),border-color var(--dur-2) var(--ease),background var(--dur-2) var(--ease),color var(--dur-2) var(--ease),box-shadow var(--dur-2) var(--ease)}
button:hover{border-color:var(--stroke-hi);background:var(--glass-2);transform:translateY(-1px)}
button:active{transform:scale(.98)}
button.save{background:linear-gradient(135deg,var(--accent),color-mix(in srgb,var(--accent) 70%,var(--orb-b)));color:var(--accent-ink);border:0;font-weight:600;box-shadow:0 10px 28px color-mix(in srgb,var(--accent) 28%,transparent)}
button.save:hover{filter:brightness(1.06)}
button.secondary{background:var(--glass);border:1px solid var(--stroke)}
.hero{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:26px;animation:rise var(--dur-3) var(--ease) .06s both}
.hero h1{font-size:clamp(30px,5vw,50px);line-height:1.02;margin:10px 0 0;letter-spacing:-.03em;font-weight:600;color:var(--ink)}
.hero p{color:var(--muted);margin:14px 0 0;max-width:52ch}
.hero .kicker{color:var(--accent);font-size:12px;font-weight:600}
.online{display:flex;align-items:center;gap:8px;color:var(--ok);font-size:12px;white-space:nowrap;font-weight:500}
.online:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 12px var(--ok);animation:pulse-dot 2s var(--ease) infinite}
@keyframes pulse-dot{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--ok) 55%,transparent)}70%{box-shadow:0 0 0 9px transparent}100%{box-shadow:0 0 0 0 transparent}}
.layout{display:grid;grid-template-columns:minmax(280px,.72fr) minmax(0,1.28fr);gap:18px}
.card{background:radial-gradient(60% 45% at 82% 0%,rgba(14,165,233,.10),transparent 60%),radial-gradient(55% 50% at 15% 100%,rgba(139,92,246,.12),transparent 65%),linear-gradient(160deg,rgba(255,255,255,.08),rgba(255,255,255,.03));backdrop-filter:blur(24px) saturate(1.5);-webkit-backdrop-filter:blur(24px) saturate(1.5);border:1px solid var(--stroke);border-radius:var(--r-card);padding:22px;box-shadow:var(--shadow-card),inset 0 1px 0 var(--stroke-hi);animation:rise var(--dur-3) var(--ease) both;transition:transform var(--dur-2) var(--ease),border-color var(--dur-2) var(--ease),box-shadow var(--dur-2) var(--ease)}
.card:hover{transform:translateY(-2px);border-color:var(--stroke-hi)}
.card h2{font-size:16px;margin:0 0 5px;letter-spacing:-.02em;font-weight:600;color:var(--ink)}
.muted{color:var(--muted);margin:0 0 18px;font-size:13px}
.fields{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
label{display:block;margin:12px 0;color:var(--muted);font-size:12px;font-weight:500}
input{display:block;width:100%;margin-top:8px;padding:12px 13px;border:1px solid var(--stroke);border-radius:10px;background:var(--surface);color:var(--ink);outline:none;font:500 13px ui-monospace,monospace;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);transition:border-color var(--dur-1) var(--ease),box-shadow var(--dur-1) var(--ease)}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
.status{color:var(--ok);font-size:13px;min-height:18px;margin:14px 0 0}
.log-head{display:flex;justify-content:space-between;align-items:start;gap:12px}
.live{color:var(--accent);font-size:10px;font-weight:600;letter-spacing:.06em;white-space:nowrap;border:1px solid var(--stroke);border-radius:var(--r-pill);padding:4px 10px;background:var(--glass)}
pre#logs{white-space:pre-wrap;max-height:52vh;min-height:220px;overflow:auto;background:var(--surface);border:1px solid var(--stroke);padding:14px;border-radius:12px;color:var(--ink);font:12px/1.7 ui-monospace,monospace;margin:0;backdrop-filter:blur(10px) saturate(1.2);-webkit-backdrop-filter:blur(10px) saturate(1.2)}
.uri-grid{display:grid;gap:12px}
.data-panel{background:var(--surface);border:1px solid var(--stroke);border-radius:12px;padding:14px 16px;backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
div[id$="-modal"]{position:fixed;inset:0;z-index:10;display:grid;place-items:center;padding:20px;background:rgba(4,8,12,.55);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);animation:fade-in var(--dur-2) var(--ease) both}
div[id$="-modal"]>div{background:linear-gradient(160deg,rgba(255,255,255,.12),rgba(255,255,255,.04));backdrop-filter:blur(24px) saturate(1.5);-webkit-backdrop-filter:blur(24px) saturate(1.5);border:1px solid var(--stroke);border-radius:var(--r-card);box-shadow:var(--shadow-card),inset 0 1px 0 var(--stroke-hi);animation:pop var(--dur-2) var(--ease) both}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
@keyframes fade-in{from{opacity:0}to{opacity:1}}
@keyframes pop{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:scale(1)}}
#network-tests article{background:var(--surface);border:1px solid var(--stroke);border-radius:12px;padding:14px 16px;backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);transition:border-color var(--dur-2) var(--ease)}
#network-tests article:hover{border-color:var(--stroke-hi)}
@media(max-width:860px){.layout{grid-template-columns:1fr}.fields{grid-template-columns:1fr}.hero{flex-direction:column;align-items:start}}@media(max-width:640px){#network-tests div[style*="grid-template-columns:repeat(4"]{grid-template-columns:1fr!important}#network-tests article{min-width:0;display:flex!important;flex-direction:column;gap:4px}#network-tests article>div{flex-wrap:wrap}#network-tests article strong[style*="font-size:18px"]{white-space:normal;overflow-wrap:anywhere;word-break:break-all;font-size:15px!important}#network-tests>div[style*="repeat(2"]{grid-template-columns:repeat(2,minmax(0,1fr))!important}#network-tests article div[style*="justify-content:space-between"]{grid-template-columns:repeat(2,minmax(0,1fr))!important;display:grid!important;gap:8px}#network-tests article div[style*="justify-content:space-between"] span{min-width:0;overflow-wrap:anywhere}#network-tests article div[style*="justify-content:space-between"] strong{white-space:nowrap;font-variant-numeric:tabular-nums}.card{overflow-x:hidden}}@media(max-width:420px){.topbar{flex-direction:column;align-items:stretch}.actions{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.actions button{width:100%;white-space:nowrap;padding:10px 12px;font-size:13px}}@media(max-width:420px){.topbar button{white-space:nowrap;padding:8px 12px;font-size:13px}}
@media (prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}.orb{animation:none}}
</style></head><body>
<div class="field" aria-hidden="true"><i class="orb orb-a"></i><i class="orb orb-b"></i><i class="orb orb-c"></i></div>
<main class="shell">
<header class="topbar">
<div class="brand"><i></i>EDGETUNNEL<small>XRAY CONTROL CENTER</small></div>
<div class="actions">
<button class="secondary icon-btn" id="theme" onclick="toggleTheme()" aria-label="Toggle light/dark mode" title="Toggle theme"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg></button>
<button class="secondary icon-btn" onclick="logout()" aria-label="Log out" title="Log out"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3"/><path d="m16 17 5-5-5-5M21 12H9"/></svg></button>
</div>
</header>
<section class="hero">
<div>
<div class="kicker">Gateway overview</div>
<h1>Command center</h1>
<p>Your Xray gateway at a glance — copy a profile, scan a QR code, or tune the configuration.</p>
</div>
<div class="online">Dashboard connected</div>
</section>
<section class="layout">
<div>
<section class="card">
<h2>Gateway configuration</h2>
<p class="muted">Changes restart Xray and refresh all connection profiles.</p>
<form id="config">
<label>Client UUID<input id="uuid" required></label>
<div class="fields">
<label>VLESS path<input id="vless" required></label>
<label>VMess path<input id="vmess" required></label>
<label>Trojan path<input id="trojan" required></label>
<label>Shadowsocks path<input id="ss" required></label>
</div>
<button class="save" type="submit">Save configuration</button>
<p class="status" id="status"></p>
</form>
</section>
<section class="card logs">
<div class="log-head">
<div>
<h2>Runtime logs</h2>
<p class="muted">Live process output</p>
</div>
<span class="live">AUTO-REFRESH 3S</span>
</div>
<pre id="logs">Loading...</pre>
</section>
</div>
<section class="card">
<h2>Connection profiles</h2>
<p class="muted">Scan a QR code or copy a URI into your client.</p>
<section class="uri-grid" id="uris"></section>
</section>
</section>

</main>
<script>


const savedTheme=localStorage.getItem('edgetunnel-theme')||'dark';document.documentElement.dataset.theme=savedTheme;function toggleTheme(){const next=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=next;localStorage.setItem('edgetunnel-theme',next);const t=document.querySelector('#theme');t.innerHTML=next==='dark'?'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg>':'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'}const t0=document.querySelector('#theme');t0.innerHTML=savedTheme==='dark'?'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg>':'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
async function api(url, options){const r=await fetch(url,options);if(r.status===401){location='/dashboard/login';throw Error('login required')}const d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
function show(data){const quote=value=>"'"+value.replaceAll("'","\\'")+"'";if(!document.querySelector('#uri-card-style')){const style=document.createElement('style');style.id='uri-card-style';style.textContent='.uri-grid{grid-template-columns:1fr!important}.protocol{display:grid;grid-template-columns:max-content minmax(0,1fr) auto;align-items:center;gap:12px 14px;padding:14px 16px!important;background:var(--surface)!important;border:1px solid var(--stroke)!important;border-radius:14px!important;box-shadow:0 1px 3px rgba(0,0,0,.08)!important;backdrop-filter:blur(14px) saturate(1.3)!important;-webkit-backdrop-filter:blur(14px) saturate(1.3)!important}.protocol h3{margin:0!important;color:var(--ink)!important;font:600 12px Inter,system-ui,sans-serif!important;letter-spacing:.02em!important}.protocol .uri{min-width:0;margin:0!important;padding:10px 12px!important;background:var(--surface-2)!important;border:1px solid var(--stroke)!important;border-radius:8px!important;color:var(--ink)!important;font:12px ui-monospace,monospace!important;white-space:normal;overflow-wrap:anywhere;word-break:break-all;line-height:1.6}.protocol>div:last-child{display:flex;justify-content:flex-end;gap:8px}.protocol .copy{width:auto!important;min-width:92px!important;padding:10px 14px!important;border:0!important;border-radius:8px!important;font-size:12px!important}.protocol .copy:first-child{background:linear-gradient(135deg,var(--accent),var(--accent))!important;color:var(--accent-ink)!important;box-shadow:0 3px 10px rgba(94,242,195,.25)}.protocol .copy:last-child{background:linear-gradient(135deg,var(--accent),var(--accent))!important;color:var(--accent-ink)!important;box-shadow:0 3px 10px rgba(94,242,195,.2)}.protocol .copy:hover{transform:translateY(-1px);filter:brightness(1.05)}[data-theme=dark] .protocol{background:var(--surface)!important;border-color:var(--stroke)!important}[data-theme=dark] .protocol h3{color:var(--accent)!important}[data-theme=dark] .protocol .uri{background:var(--surface)!important;border-color:var(--stroke)!important;color:var(--muted)!important}@media(max-width:800px){.protocol{grid-template-columns:1fr;gap:9px}.protocol>div:last-child{justify-content:flex-end}}';document.head.append(style)}const logsPanel=document.querySelector('.logs');if(logsPanel)logsPanel.remove();const actions=document.querySelector('.actions');if(actions&&!document.querySelector('#logs-button')){const button=document.createElement('button');button.id='logs-button';button.className='secondary icon-btn';button.setAttribute('aria-label','Runtime logs');button.title='Runtime logs';button.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="m7 9 3 3-3 3M13 15h4"/></svg>';button.onclick=openLogs;actions.insertBefore(button,actions.lastElementChild)}document.querySelector('#uuid').value=data.uuid;for(const k of ['vless','vmess','trojan','ss'])document.querySelector('#'+k).value=data.paths[k];document.querySelector('#uris').innerHTML=Object.entries(data.uris).map(([k,v])=>'<article class="protocol"><h3>'+k.toUpperCase()+'</h3><div class="uri" title="'+v+'">'+v+'</div><div style="display:flex;justify-content:flex-end;gap:8px"><button class="secondary copy" style="flex:0 0 auto;width:auto" onclick="openQr('+quote(data.qr[k])+','+quote(k)+')">QR code</button><button class="secondary copy" style="flex:0 0 auto;width:auto" onclick="navigator.clipboard.writeText('+quote(v)+')">Copy URI</button></div></article>').join('')}
function openLogs(){let modal=document.querySelector('#logs-modal');if(!modal){modal=document.createElement('div');modal.id='logs-modal';modal.style='position:fixed;inset:0;z-index:10;display:grid;place-items:center;padding:20px;background:rgba(6,12,16,.55)';modal.innerHTML='<div style="position:relative;width:min(900px,100%);padding:22px;background:var(--surface);border:1px solid var(--stroke);border-radius:18px;box-shadow:0 24px 80px rgba(0,0,0,.6)"><button id="logs-close" style="position:absolute;right:12px;top:12px;width:auto;padding:6px 10px;background:var(--glass-2);color:var(--ink);border:1px solid var(--stroke);border-radius:7px">Close</button><h2 style="margin:0 0 14px;color:var(--accent);font-size:17px">Runtime logs</h2><pre id="logs" style="white-space:pre-wrap;max-height:65vh;min-height:240px;overflow:auto;background:var(--surface);border:1px solid var(--stroke);padding:14px;border-radius:10px;color:var(--accent);font:12px/1.7 ui-monospace,monospace">Loading...</pre></div>';document.body.append(modal);document.querySelector('#logs-close').onclick=()=>modal.remove();modal.onclick=e=>{if(e.target===modal)modal.remove()}}modal.style.display='grid';api('/api/logs').then(data=>renderLogs(data.logs)).catch(()=>{});}
function openQr(source, name){let modal=document.querySelector('#qr-modal');if(!modal){modal=document.createElement('div');modal.id='qr-modal';modal.style='position:fixed;inset:0;z-index:10;display:grid;place-items:center;padding:20px;background:rgba(6,12,16,.55)';modal.innerHTML='<div style="position:relative;width:min(360px,100%);padding:22px;background:var(--surface);border:1px solid var(--stroke);border-radius:18px;text-align:center;box-shadow:0 24px 80px rgba(0,0,0,.6)"><button id="qr-close" style="position:absolute;right:12px;top:12px;width:auto;padding:6px 10px;background:var(--glass-2);color:var(--ink);border:1px solid var(--stroke);border-radius:7px">Close</button><p id="qr-title" style="color:var(--accent);font:800 12px system-ui;letter-spacing:.14em">QR CODE</p><div style="background:var(--surface);padding:14px;border-radius:10px"><img id="qr-image" style="display:block;width:100%;image-rendering:pixelated" alt="QR code"></div></div>';document.body.append(modal);document.querySelector('#qr-close').onclick=()=>modal.remove();modal.onclick=e=>{if(e.target===modal)modal.remove()};window.addEventListener('keydown',function closeQr(e){if(e.key==='Escape'){modal.remove();window.removeEventListener('keydown',closeQr)}})}document.querySelector('#qr-title').textContent=name.toUpperCase()+' QR CODE';document.querySelector('#qr-image').src=source;modal.style.display='grid'}
function compactUriCards(){const columns=window.innerWidth<=800?'1fr':'max-content minmax(0,1fr) auto';document.querySelectorAll('.protocol').forEach(card=>{card.style.gridTemplateColumns=columns})}
function openConfig(){const modal=document.querySelector('#config-modal');if(modal)modal.style.display='grid'}
function initializeConfigModal(){const panel=document.querySelector('#config')&&document.querySelector('#config').closest('.card');const layout=document.querySelector('.layout');if(!panel||document.querySelector('#config-modal'))return;if(layout&&layout.firstElementChild){layout.firstElementChild.remove();const profiles=layout.querySelector('.card');if(profiles)profiles.style.gridColumn='1/-1'}const modal=document.createElement('div');modal.id='config-modal';modal.style='position:fixed;inset:0;z-index:9;display:none;place-items:center;padding:20px;background:rgba(6,12,16,.55)';const inner=document.createElement('div');inner.style='position:relative;width:min(620px,100%);max-height:90vh;overflow:auto;padding:22px;background:var(--surface);border:1px solid var(--stroke);border-radius:18px;box-shadow:0 24px 80px rgba(0,0,0,.6)';const close=document.createElement('button');close.textContent='Close';close.className='secondary';close.style='position:absolute;right:22px;top:22px;width:auto;z-index:20';close.onclick=e=>{e.stopPropagation();modal.style.display='none'};close.type='button';inner.append(close);inner.append(panel);modal.append(inner);modal.onclick=e=>{if(e.target===modal)modal.style.display='none'};document.body.append(modal);const actions=document.querySelector('.actions');if(actions&&!document.querySelector('#config-button')){const button=document.createElement('button');button.id='config-button';button.className='secondary icon-btn';button.setAttribute('aria-label','Configuration');button.title='Configuration';button.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.03-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.56-1.03 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.08a1.7 1.7 0 0 0 1.03-1.56V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.08a1.7 1.7 0 0 0 1.56 1.03H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.56 1.03z"/></svg>';button.onclick=openConfig;actions.insertBefore(button,actions.firstElementChild)}window.addEventListener('keydown',e=>{if(e.key==='Escape'&&modal.style.display==='grid')modal.style.display='none'})}
function addXhttpConfig(){const form=document.querySelector('#config');const fields=form&&form.querySelector('.fields');if(!fields||document.querySelector('#xhttp'))return;const label=document.createElement('label');label.textContent='XHTTP path';const input=document.createElement('input');input.id='xhttp';input.required=true;label.append(input);fields.append(label)}
function addNetworkCard(){if(document.querySelector('#network-card'))return;const layout=document.querySelector('.layout');if(!layout)return;const card=document.createElement('section');card.id='network-card';card.className='card';card.style='margin-bottom:18px';card.innerHTML='<div style="display:flex;justify-content:space-between;align-items:start;gap:12px"><div><h2>Current network information</h2><p class="muted">Live gateway and runtime status</p></div><span id="network-status" class="online">Checking</span></div><div id="network-details" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:14px"></div>';layout.parentNode.insertBefore(card,layout);}
async function refreshNetwork(){try{const data=await api('/api/network');const details=document.querySelector('#network-details');const status=document.querySelector('#network-status');if(!details)return;status.textContent=data.xray==='online'?'Xray online':'Xray offline';details.innerHTML=[['Public host',data.host],['Transport',data.protocol.toUpperCase()+' / '+(data.port||443)],['Runtime',data.runtime],['Uptime',Math.floor(data.uptime/86400)+'d '+Math.floor(data.uptime%86400/3600)+'h '+Math.floor(data.uptime%3600/60)+'m'],['Inbound ports',Object.values(data.inbounds).join(' · ')],['Interfaces',data.interfaces.join(', ')||'none']].map(([label,value])=>'<div style="padding:11px 12px;border:1px solid var(--stroke);border-radius:8px;background:var(--surface)"><small style="display:block;color:var(--muted);font-size:10px;">'+label+'</small><strong style="display:block;margin-top:4px;font:12px ui-monospace,monospace;word-break:break-word">'+value+'</strong></div>').join('')}catch{}}
function bindConfigForm(){const form=document.querySelector('#config');if(!form)return;form.onsubmit=async event=>{event.preventDefault();const paths={};for(const key of ['vless','vmess','trojan','ss','xhttp'])paths[key]=document.querySelector('#'+key).value;try{const data=await api('/api/config',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({uuid:document.querySelector('#uuid').value,paths})});show(data);document.querySelector('#xhttp').value=data.paths.xhttp;document.querySelector('#status').textContent='Saved and Xray restarted.'}catch(error){document.querySelector('#status').textContent=error.message}}}
function arrangeActions(){const actions=document.querySelector('.actions');const logoutButton=actions&&actions.querySelector('button[onclick="logout()"]');if(!actions||!logoutButton)return;for(const id of ['config-button','logs-button','theme']){const button=document.querySelector('#'+id);if(button)actions.insertBefore(button,logoutButton)}}
function renderLogs(logs){const output=document.querySelector('#logs');if(!output)return;output.textContent=logs.join('\\n');output.scrollTop=output.scrollHeight}
async function load(){try{const data=await api('/api/config');show(data);compactUriCards();initializeConfigModal();addXhttpConfig();addNetworkCard();ensureNetworkTests();ensureTrafficCounter();document.querySelector('#xhttp').value=data.paths.xhttp;bindConfigForm();arrangeActions();await refreshNetwork();syncNetworkSummaryTheme();renderNetworkTests();await refreshTraffic();renderLogs((await api('/api/logs')).logs)}catch(e){document.querySelector('#status').textContent=e.message}}
async function logout(){await fetch('/api/logout',{method:'POST'});location='/dashboard/login'}window.addEventListener('resize',compactUriCards);load();setInterval(async()=>{try{renderLogs((await api('/api/logs')).logs)}catch{}},3000);
function ensureNetworkTests(){const card=document.querySelector('#network-card');if(!card||document.querySelector('#network-tests'))return;const section=document.createElement('div');section.id='network-tests';section.style='margin-top:18px';const observer=new MutationObserver(()=>{const heading=section.querySelector('h3');if(heading)heading.style.display='none'});observer.observe(section,{childList:true});card.append(section)}
async function renderNetworkTests(){try{const data=await api('/api/network');const target=document.querySelector('#network-tests');if(!target)return;const rows=[['Domestic testing','ByteDance Douyin',data.publicIp,data.location,'IP used for domestic destinations'],['Overseas testing','Direct routing',data.publicIp,data.location,'IP used for international destinations'],['Cloudflare','ProxyIPv4',data.cloudflareIp,data.location,'Landing IP used for Cloudflare CDN'],['External testing','Google / Twitter (X.com)',data.publicIp,data.location,'IP used for external destinations']];target.innerHTML='<h3 style="margin:0 0 12px;font-size:14px">🌍 Current network information</h3>'+rows.map(row=>'<div style="display:grid;grid-template-columns:minmax(150px,.7fr) minmax(0,1.3fr);gap:4px 14px;padding:12px 0;border-top:1px solid var(--stroke)"><strong style="font-size:12px">'+row[0]+'</strong><span style="font-size:12px;color:var(--muted)">'+row[1]+'</span><span style="font:12px ui-monospace,monospace;color:var(--accent)">'+row[2]+'</span><span style="font-size:11px;color:var(--muted)">'+row[3]+' · '+row[4]+'</span></div>').join('')+'<h3 style="margin:18px 0 10px;font-size:14px">Connectivity checks</h3><div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px">'+data.tests.map(test=>'<div style="display:flex;justify-content:space-between;gap:8px;padding:9px 10px;border:1px solid var(--stroke);border-radius:8px;background:var(--surface)"><span style="font-size:12px">'+test.name+'</span><strong style="font:12px ui-monospace,monospace;color:'+(test.ok?'var(--accent)':'var(--danger)')+'">'+(test.ok?test.latency+' ms':test.error)+'</strong></div>').join('')+'</div>'}catch{}}
async function renderEdgeNetworkCards(){try{const data=await api('/api/network');const target=document.querySelector('#network-tests');if(!target)return;const rows=[['Domestic testing','ByteDance Douyin',data.publicIp,data.location,'The IP address used to access domestic websites'],['Overseas testing','Direct routing',data.publicIp,data.location,'The IP address used to access unblocked foreign websites'],['Cloudflare','ProxyIPv4',data.cloudflareIp,data.location,'The landing IP used to access the Cloudflare CDN'],['External testing','Google / Twitter (X.com)',data.publicIp,data.location,'The IP address used to access Google']];target.innerHTML='<div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px">'+rows.map(row=>'<article style="padding:16px;border:1px solid var(--stroke);border-radius:14px;background:var(--surface);box-shadow:0 4px 6px rgba(0,0,0,.05)"><div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--stroke)"><span style="width:10px;height:10px;border-radius:50%;background:var(--ok);box-shadow:0 0 5px var(--ok)"></span><div><strong style="display:block;font-size:14px">'+row[0]+'</strong><small style="color:var(--muted)">'+row[1]+'</small></div></div><strong style="display:block;font-size:18px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink)">'+row[2]+'</strong><div style="margin:8px 0;color:var(--muted);font-size:14px">'+row[3]+'</div><small style="display:block;color:var(--muted);font-size:12px">· '+row[4]+'</small></article>').join('')+'</div><small style="display:block;margin-top:10px;color:var(--muted);font-size:12px">💡 These checks represent the Cloudways server outbound network.</small><h3 style="margin:18px 0 10px;font-size:14px">Connectivity checks</h3><div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px">'+data.tests.map(test=>'<div style="display:flex;justify-content:space-between;gap:8px;padding:12px;border:1px solid var(--stroke);border-radius:10px;background:var(--surface)"><span style="font-size:12px">'+test.name+'</span><strong style="font:12px ui-monospace,monospace;color:'+(test.ok?'var(--ok)':'var(--danger)')+'">'+(test.ok?test.latency+' ms':test.error)+'</strong></div>').join('')+'</div>';syncNetworkTheme()}catch{}}
function syncNetworkTheme(){const target=document.querySelector('#network-tests');if(!target)return;const dark=document.documentElement.dataset.theme==='dark';const surface=dark?'var(--surface)':'var(--surface)';const border=dark?'var(--stroke)':'var(--stroke)';const text=dark?'var(--ink)':'var(--ink)';const muted=dark?'var(--muted)':'var(--muted)';target.querySelectorAll('article,article~*').forEach(element=>{if(element.tagName==='ARTICLE'||element.style.display==='flex'){element.style.background=surface;element.style.borderColor=border}});target.querySelectorAll('article').forEach(card=>{card.style.background=surface;card.style.borderColor=border;card.querySelector('strong[style*="font-size:18px"]').style.color=text;card.querySelectorAll('small').forEach(item=>item.style.color=muted);card.querySelector('div[style*="border-bottom"]').style.borderColor=border});const latency=target.lastElementChild;[...(latency?.children||[])].forEach(item=>{item.style.background=surface;item.style.borderColor=border;item.firstElementChild.style.color=text})}
function syncNetworkSummaryTheme(){const details=document.querySelector('#network-details');if(!details)return;const dark=document.documentElement.dataset.theme==='dark';const surface=dark?'var(--surface)':'var(--surface)';const border=dark?'var(--stroke)':'var(--stroke)';const text=dark?'var(--ink)':'var(--ink)';const muted=dark?'var(--muted)':'var(--muted)';details.querySelectorAll('div').forEach((tile,index)=>{tile.style.background=surface;tile.style.borderColor=border;tile.querySelectorAll('strong').forEach(item=>item.style.color=text);tile.querySelectorAll('small').forEach(item=>item.style.color=muted)})}
function countryFlag(code){return /^[A-Z]{2}$/.test(code)?String.fromCodePoint(...[...code].map(letter=>127397+letter.charCodeAt(0))):'🌐'}
function addNetworkFlags(){const target=document.querySelector('#network-tests');if(!target)return;target.querySelectorAll('article').forEach(card=>{if(card.dataset.flagAdded)return;const location=card.querySelector('div[style*="margin:8px"]');const ip=card.querySelector('strong[style*="font-size:18px"]');if(!location||!ip)return;const code=location.textContent.trim().slice(0,2).toUpperCase();const flag=countryFlag(code);ip.textContent=flag+' '+ip.textContent;location.textContent=flag+' '+location.textContent;card.dataset.flagAdded='true'})}
function ensureTrafficCounter(){const card=document.querySelector('#network-card');if(!card||document.querySelector('#traffic-counter'))return;const counter=document.createElement('div');counter.id='traffic-counter';counter.style='margin-top:18px;padding-top:16px;border-top:1px solid var(--stroke)';counter.innerHTML='<h3 style="margin:0 0 10px;font-size:14px">Traffic counter</h3><div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px"><div><small style="color:var(--muted)">Uploaded</small><strong id="traffic-up" style="display:block;color:var(--accent)">0 B</strong></div><div><small style="color:var(--muted)">Downloaded</small><strong id="traffic-down" style="display:block;color:var(--accent)">0 B</strong></div><div><small style="color:var(--muted)">Active</small><strong id="traffic-active" style="display:block;color:var(--accent)">0</strong></div></div>';card.append(counter)}
async function refreshTraffic(){try{const data=await api('/api/traffic');const format=bytes=>{if(!bytes)return'0 B';const units=['B','KB','MB','GB','TB'];const index=Math.min(Math.floor(Math.log(bytes)/Math.log(1024)),units.length-1);return(bytes/1024**index).toFixed(index?2:0)+' '+units[index]};document.querySelector('#traffic-up').textContent=format(data.uploaded);document.querySelector('#traffic-down').textContent=format(data.downloaded);document.querySelector('#traffic-active').textContent=data.active}catch{}}
function syncModalTheme(){const dark=document.documentElement.dataset.theme==='dark';document.documentElement.style.colorScheme=dark?'dark':'light';const surface=dark?'var(--surface)':'var(--surface)';const border=dark?'var(--stroke)':'var(--stroke)';const text=dark?'var(--ink)':'var(--ink)';for(const id of ['config-modal','logs-modal','qr-modal']){const modal=document.querySelector('#'+id);if(!modal)continue;const panel=modal.firstElementChild;if(panel){panel.style.background=surface;panel.style.borderColor=border;panel.style.color=text;panel.querySelectorAll('h2').forEach(item=>item.style.color=dark?'var(--accent)':'var(--ink)');panel.querySelectorAll('button').forEach(item=>{if(item.id.endsWith('close')){item.style.background=dark?'var(--glass-2)':'var(--glass-2)';item.style.color=dark?'var(--ink)':'var(--ink)';item.style.borderColor=border}})}}}
setInterval(()=>{ensureNetworkTests();ensureTrafficCounter();refreshNetwork().then(syncNetworkSummaryTheme);renderNetworkTests();renderEdgeNetworkCards();refreshTraffic()},30000);setInterval(refreshTraffic,3000);setInterval(addNetworkFlags,1000);setTimeout(()=>{ensureNetworkTests();ensureTrafficCounter();renderEdgeNetworkCards();syncNetworkSummaryTheme();syncModalTheme();addNetworkFlags()},1000);new MutationObserver(()=>{syncNetworkTheme();syncNetworkSummaryTheme();syncModalTheme()}).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});new MutationObserver(()=>{syncModalTheme();addNetworkFlags()}).observe(document.body,{childList:true,subtree:true});</script></body></html>`;
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
const landingPage = `<!doctype html><html><head><meta name="viewport" content="width=device-width"><title>ZFTunnel by Velocity · Secure gateway</title><style>
:root{color-scheme:dark;--field:#05090d;--field-2:#0a1418;--orb-a:#12d9a0;--orb-b:#0ea5e9;--orb-c:#8b5cf6;--glass:rgba(255,255,255,.06);--glass-2:rgba(255,255,255,.10);--surface:rgba(255,255,255,.05);--surface-2:rgba(10,20,24,.78);--stroke:rgba(255,255,255,.14);--stroke-hi:rgba(255,255,255,.24);--ink:#e8f3f1;--muted:#b6d2cc;--accent:#5ef2c3;--accent-ink:#062019;--r-card:20px;--r-ctl:12px;--shadow-card:0 24px 60px rgba(0,0,0,.38);--blur:20px;--ease:cubic-bezier(.22,1,.36,1);--dur-2:240ms;--dur-3:420ms}
[data-theme=light]{color-scheme:light;--field:#eef4f1;--field-2:#f7faf8;--orb-a:#7ce8c8;--orb-b:#a5d8f5;--orb-c:#d9c8f7;--glass:rgba(255,255,255,.65);--glass-2:rgba(255,255,255,.80);--surface:rgba(255,255,255,.62);--surface-2:rgba(255,255,255,.88);--stroke:rgba(13,50,45,.16);--stroke-hi:rgba(255,255,255,.9);--ink:#0f2724;--muted:#55706a;--accent:#0d9488;--accent-ink:#ffffff;--shadow-card:0 24px 60px rgba(13,50,45,.14)}
*{box-sizing:border-box}html,body{margin:0}body{min-height:100vh;background:radial-gradient(circle at 8% -5%,rgba(18,217,160,.14),transparent 42%),radial-gradient(circle at 92% 12%,rgba(14,165,233,.12),transparent 40%),radial-gradient(circle at 50% 58%,rgba(14,165,233,.08),transparent 45%),radial-gradient(circle at 45% 108%,rgba(139,92,246,.14),transparent 46%),var(--field);color:var(--ink);font:15px/1.6 Inter,ui-sans-serif,system-ui,sans-serif;transition:background var(--dur-2) var(--ease),color var(--dur-2) var(--ease)}
.field{position:fixed;inset:0;z-index:-1;overflow:visible;background:linear-gradient(180deg,var(--field),var(--field-2))}
.orb{position:absolute;border-radius:50%;filter:blur(90px);will-change:transform}
.orb-a{width:540px;height:540px;left:-140px;top:-120px;background:var(--orb-a);opacity:.34;animation:drift-a 32s var(--ease) infinite alternate}
.orb-b{width:480px;height:480px;right:-120px;top:18%;background:var(--orb-b);opacity:.30;animation:drift-b 38s var(--ease) infinite alternate}
.orb-c{width:440px;height:440px;left:28%;bottom:-160px;background:var(--orb-c);opacity:.28;animation:drift-c 30s var(--ease) infinite alternate}
@keyframes drift-a{from{transform:translate(0,0) scale(1)}to{transform:translate(80px,60px) scale(1.08)}}
@keyframes drift-b{from{transform:translate(0,0) scale(1)}to{transform:translate(-70px,50px) scale(1.05)}}
@keyframes drift-c{from{transform:translate(0,0) scale(1)}to{transform:translate(50px,-60px) scale(1.1)}}
.shell{max-width:1080px;margin:auto;padding:36px 24px 64px;position:relative}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:72px;animation:rise var(--dur-3) var(--ease) both}
.brand{display:flex;align-items:center;gap:12px;font-weight:600;letter-spacing:.12em}
.brand i{width:12px;height:12px;display:block;border-radius:50%;background:var(--accent);box-shadow:0 0 20px var(--accent);animation:pulse-dot 2.4s var(--ease) infinite}
.brand small{display:block;color:var(--muted);font-size:10px;letter-spacing:.08em;font-weight:500;margin-top:4px}
.topbar .actions{display:flex;gap:10px;align-items:center}
button{font:500 14px Inter,ui-sans-serif,system-ui,sans-serif;border-radius:var(--r-ctl);border:1px solid var(--stroke);background:var(--glass);color:var(--ink);padding:10px 18px;cursor:pointer;backdrop-filter:blur(var(--blur));-webkit-backdrop-filter:blur(var(--blur));transition:transform var(--dur-2) var(--ease),border-color var(--dur-2) var(--ease),background var(--dur-2) var(--ease),color var(--dur-2) var(--ease),box-shadow var(--dur-2) var(--ease)}
button:hover{border-color:var(--stroke-hi);background:var(--glass-2);transform:translateY(-1px)}
button:active{transform:scale(.98)}
button.primary{background:linear-gradient(135deg,var(--accent),color-mix(in srgb,var(--accent) 70%,var(--orb-b)));color:var(--accent-ink);border:0;font-weight:600;box-shadow:0 10px 28px color-mix(in srgb,var(--accent) 28%,transparent)}
button.primary:hover{filter:brightness(1.06)}
button.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;padding:0}
button.icon-btn svg{display:block}
.hero{text-align:center;max-width:760px;margin:0 auto 72px;animation:rise var(--dur-3) var(--ease) .06s both}
.hero .kicker{color:var(--accent);font-size:13px;font-weight:600}
.hero h1{font-size:clamp(38px,6vw,64px);line-height:1.04;margin:18px 0 0;letter-spacing:-.04em;font-weight:600}
.hero p{color:var(--muted);margin:20px auto 0;max-width:56ch;font-size:17px}
.hero .cta{display:flex;gap:12px;justify-content:center;margin-top:36px;flex-wrap:wrap}
.features{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;animation:rise var(--dur-3) var(--ease) .12s both}
.feature{background:radial-gradient(60% 45% at 82% 0%,rgba(14,165,233,.10),transparent 60%),radial-gradient(55% 50% at 15% 100%,rgba(139,92,246,.12),transparent 65%),linear-gradient(160deg,rgba(255,255,255,.08),rgba(255,255,255,.03));backdrop-filter:blur(24px) saturate(1.5);-webkit-backdrop-filter:blur(24px) saturate(1.5);border:1px solid var(--stroke);border-radius:var(--r-card);padding:24px;box-shadow:var(--shadow-card),inset 0 1px 0 var(--stroke-hi);transition:transform var(--dur-2) var(--ease),border-color var(--dur-2) var(--ease)}
.feature:hover{transform:translateY(-3px);border-color:var(--stroke-hi)}
.feature .ico{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;background:var(--glass-2);border:1px solid var(--stroke);color:var(--accent);margin-bottom:16px}
.feature h3{margin:0 0 6px;font-size:16px;font-weight:600;letter-spacing:-.01em}
.feature p{margin:0;color:var(--muted);font-size:13.5px}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse-dot{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--accent) 55%,transparent)}70%{box-shadow:0 0 0 9px transparent}100%{box-shadow:0 0 0 0 transparent}}
@media(max-width:800px){.features{grid-template-columns:1fr}.topbar{margin-bottom:48px}.speed{margin-top:48px!important}}
@media (prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}.orb{animation:none}}

.speed{background:radial-gradient(60% 45% at 82% 0%,rgba(14,165,233,.10),transparent 60%),radial-gradient(55% 50% at 15% 100%,rgba(139,92,246,.12),transparent 65%),linear-gradient(160deg,rgba(255,255,255,.08),rgba(255,255,255,.03));backdrop-filter:blur(24px) saturate(1.5);-webkit-backdrop-filter:blur(24px) saturate(1.5);border:1px solid var(--stroke);border-radius:var(--r-card);padding:24px;box-shadow:var(--shadow-card),inset 0 1px 0 var(--stroke-hi);animation:rise var(--dur-3) var(--ease) .18s both;transition:transform var(--dur-2) var(--ease),border-color var(--dur-2) var(--ease);max-width:760px;margin:72px auto 72px}
.speed:hover{transform:translateY(-3px);border-color:var(--stroke-hi)}
.speed__head{display:flex;justify-content:space-between;align-items:start;gap:12px}
.speed h2{font-size:18px;margin:0 0 4px;font-weight:600;letter-spacing:-.02em}
.speed .muted{margin:0;font-size:13px}
.speed__live{display:inline-flex;align-items:center;gap:6px;color:var(--accent);font-size:11px;font-weight:600;letter-spacing:.06em;border:1px solid var(--stroke);border-radius:var(--r-pill);padding:4px 10px;background:var(--glass)}
.speed__live i{width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 10px var(--accent);animation:pulse-dot 2s var(--ease) infinite}
.speed__rates{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin:20px 0 4px}
.speed__label{color:var(--muted);font-size:12px;margin:0 0 2px}
.speed__value{font-size:26px;font-weight:600;letter-spacing:-.02em;margin:0;font-variant-numeric:tabular-nums;white-space:nowrap}
.speed__total{color:var(--muted);font-size:12px;margin:2px 0 0;font-variant-numeric:tabular-nums}
.speed__chart{height:110px;margin:8px 0 4px;position:relative}
.speed__chart svg{width:100%;height:100%;display:block;border-bottom:1px dashed var(--stroke)}
</style></head><body>
<div class="field" aria-hidden="true"><i class="orb orb-a"></i><i class="orb orb-b"></i><i class="orb orb-c"></i></div>
<main class="shell">
<header class="topbar">
<div class="brand"><i></i>ZFTUNNEL<small>BY VELOCITY</small></div>
<div class="actions">
<button class="icon-btn" id="theme" onclick="toggleTheme()" aria-label="Toggle light/dark mode" title="Toggle theme"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg></button>

</div>
</header>
<section class="hero">
<div class="kicker">Secure gateway · Xray core</div>
<h1>Your private connection, under your control.</h1>
<p>A self-hosted Xray gateway with a glass-clear command center. Generate profiles, scan QR codes, monitor traffic and connectivity — all on infrastructure you own.</p>
<div class="cta">
<button class="primary" id="hero-cta" onclick="location.href='__AUTH_HREF__'">__AUTH_HERO__</button>
</div>
</section>
<section class="features">
<article class="feature"><div class="ico"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="m7 9 3 3-3 3M13 15h4"/></svg></div><h3>Live runtime logs</h3><p>Stream the gateway process output in real time, right from the dashboard.</p></article>
<article class="feature"><div class="ico"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.03-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.56-1.03 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.08a1.7 1.7 0 0 0 1.03-1.56V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.08a1.7 1.7 0 0 0 1.56 1.03H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.56 1.03z"/></svg></div><h3>One-click profiles</h3><p>VLESS, VMess, Trojan, Shadowsocks and XHTTP URIs with QR codes — ready to scan.</p></article>
<article class="feature"><div class="ico"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></div><h3>Live connectivity</h3><p>Latency checks to major platforms and real-time traffic counters, refreshed continuously.</p></article>
</section>
<section class="speed">
<div class="speed__head">
<div>
<h2>Network speed</h2>
<p class="muted">Live gateway throughput, refreshed every second.</p>
</div>
<span class="speed__live"><i data-seenry-dot></i>LIVE</span>
</div>
<div class="speed__rates">
<div>
<p class="speed__label">Download</p>
<p class="speed__value" id="speed-down">0 B/s</p>
<p class="speed__total" id="speed-down-total">Total 0 B</p>
</div>
<div>
<p class="speed__label">Upload</p>
<p class="speed__value" id="speed-up">0 B/s</p>
<p class="speed__total" id="speed-up-total">Total 0 B</p>
</div>
</div>
<div class="speed__chart">
<svg viewBox="0 0 100 40" preserveAspectRatio="none" role="img" aria-label="Download / upload speed">
<defs>
<linearGradient id="speed-down-fill" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="var(--accent)" stop-opacity="0.35"/>
<stop offset="1" stop-color="var(--accent)" stop-opacity="0.02"/>
</linearGradient>
</defs>
<line x1="0" y1="14" x2="100" y2="14" stroke="var(--stroke)" stroke-width="0.5" vector-effect="non-scaling-stroke"/><line x1="0" y1="23" x2="100" y2="23" stroke="var(--stroke)" stroke-width="0.5" vector-effect="non-scaling-stroke"/><line x1="0" y1="31" x2="100" y2="31" stroke="var(--stroke)" stroke-width="0.6" vector-effect="non-scaling-stroke"/>
<path id="speed-down-area" fill="url(#speed-down-fill)" d=""/>
<path id="speed-down-line" fill="none" stroke="var(--accent)" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round" d=""/>
<path id="speed-up-line" fill="none" stroke="var(--orb-b)" stroke-width="1.5" vector-effect="non-scaling-stroke" stroke-linejoin="round" d=""/>
</svg>
</div>
</section>
</main>

<script>


function fmtSpeed(bps){if(!isFinite(bps)||bps<=0)return'0 B/s';const u=['B/s','KB/s','MB/s','GB/s','TB/s'];let v=bps,i=0;while(v>=1024&&i<u.length-1){v/=1024;i++}return v.toFixed(v>=100||i===0?0:1)+' '+u[i]}
function fmtBytes(n){if(!isFinite(n)||n<=0)return'0 B';const u=['B','KB','MB','GB','TB'];let v=n,i=0;while(v>=1024&&i<u.length-1){v/=1024;i++}return v.toFixed(1)+' '+u[i]}
const speedCap=30;let speedDown=[],speedUp=[];function ensureSpeedBaseline(){if(!speedDown.length){speedDown=[0];speedUp=[0]}}
function speedPoints(series){const w=100,h=40,plot=h*0.66,max=Math.max(1024,...series);const step=w/Math.max(1,series.length-1);return series.map((v,i)=>[i*step,h-1-(v/max)*plot])}
function speedCurve(series){const p=speedPoints(series);if(p.length<2)return'';let d='M'+p[0][0]+','+p[0][1];for(let i=1;i<p.length-1;i++){const cx=p[i][0],cy=p[i][1],mx=(cx+p[i+1][0])/2,my=(cy+p[i+1][1])/2;d+=' Q'+cx+','+cy+' '+mx+','+my}const lx=p[p.length-1][0],ly=p[p.length-1][1];return d+' L'+lx+','+ly}
function speedDraw(){ensureSpeedBaseline();const dl=speedCurve(speedDown),da=dl?dl+' L100,34 L0,34 Z':'',ul=speedCurve(speedUp);document.querySelector('#speed-down-line').setAttribute('d',dl);document.querySelector('#speed-down-area').setAttribute('d',da);document.querySelector('#speed-up-line').setAttribute('d',ul)}
async function speedTick(){try{const d=await fetch('/api/speed').then(r=>r.json());if(!d||!d.samples)return;speedDown=d.samples.map(x=>x.down);speedUp=d.samples.map(x=>x.up);if(speedDown.length>speedCap){speedDown=speedDown.slice(-speedCap);speedUp=speedUp.slice(-speedCap)}document.querySelector('#speed-down').textContent=fmtSpeed(d.down);document.querySelector('#speed-up').textContent=fmtSpeed(d.up);document.querySelector('#speed-down-total').textContent='Total '+fmtBytes(d.downTotal);document.querySelector('#speed-up-total').textContent='Total '+fmtBytes(d.upTotal);speedDraw()}catch(e){}}
setInterval(speedTick,1000);speedTick();
const savedTheme=localStorage.getItem('zftunnel-theme')||'dark';document.documentElement.dataset.theme=savedTheme;function toggleTheme(){const next=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=next;localStorage.setItem('zftunnel-theme',next);const t=document.querySelector('#theme');t.innerHTML=next==='dark'?'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg>':'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'}const t0=document.querySelector('#theme');t0.innerHTML=savedTheme==='dark'?'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M19.4 4.6l-1.8 1.8M6.4 17.6l-1.8 1.8"/></svg>':'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'</script></body></html>`;
const server = http.createServer(async (req, res) => {
  const requestPath = req.url.split('?')[0];
  if (requestPath === '/dashboard/login' && req.method === 'GET') { if (authenticated(req)) return res.writeHead(302, { location: '/dashboard' }).end(); return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(loginPage); }
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
  if (requestPath === '/api/speed' && req.method === 'GET') { return sendJson(res, 200, { samples: speedSamples, up: speedSamples.length ? speedSamples[speedSamples.length - 1].up : 0, down: speedSamples.length ? speedSamples[speedSamples.length - 1].down : 0, upTotal: traffic.uploaded, downTotal: traffic.downloaded }); }
  if (requestPath === '/') { const authed = authenticated(req); const page = landingPage.replaceAll('__AUTH_HREF__', authed ? '/dashboard' : '/dashboard/login').replaceAll('__AUTH_HERO__', authed ? 'Open dashboard' : 'Sign in'); return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(page); }
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
// Warm the network cache so the first dashboard load is instant
setTimeout(() => networkInformation({ headers: {}, url: '/', method: 'GET' }).catch(() => {}), 500).unref();
