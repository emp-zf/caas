#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const https = require('https');
const AdmZip = require('adm-zip');

const version = '26.7.28';
if (process.platform !== 'linux' || !['x64', 'arm64'].includes(process.arch)) {
  console.log(`Skipping Xray download for ${process.platform}/${process.arch}`); process.exit(0);
}
const asset = process.arch === 'arm64' ? 'Xray-linux-arm64-v8a.zip' : 'Xray-linux-64.zip';
const destination = process.env.XRAY_BIN || path.join(__dirname, 'bin', 'xray');
const archive = path.join('/tmp', `xray-${version}-${process.arch}.zip`);
if (fs.existsSync(destination)) {
  try {
    const probe = require('child_process').spawnSync(destination, ['version'], { encoding: 'utf8', timeout: 10000 });
    const installed = (probe.stdout || probe.stderr || '').split('\n')[0] || '';
    if (installed.includes(version)) { console.log(`Xray ${version} already installed`); process.exit(0); }
    console.log(`Existing Xray binary is ${installed.split(' ')[1] || 'unknown'}; updating to ${version}`);
  } catch (error) {
    console.log(`Existing binary check failed (${error.message}); reinstalling`);
  }
}
fs.mkdirSync(path.dirname(destination), { recursive: true });

function download(url, redirects = 0) {
  if (redirects > 5) return Promise.reject(new Error('Too many redirects while downloading Xray'));
  return new Promise((resolve, reject) => https.get(url, response => {
    if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
      response.resume(); return download(response.headers.location, redirects + 1).then(resolve, reject);
    }
    if (response.statusCode !== 200) { response.resume(); return reject(new Error(`Xray download failed: HTTP ${response.statusCode}`)); }
    const output = fs.createWriteStream(archive); response.pipe(output);
    output.on('finish', () => output.close(resolve)); output.on('error', reject);
  }).on('error', reject));
}

(async () => {
  let downloaded = false;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      await download(`https://github.com/XTLS/Xray-core/releases/download/v${version}/${asset}`);
      downloaded = true;
      break;
    } catch (error) {
      if (attempt === 3) throw error;
      console.log(`Download attempt ${attempt} failed (${error.message}); retrying…`);
      await new Promise(resolve => setTimeout(resolve, 3000 * attempt));
    }
  }
  if (!downloaded) throw new Error('Xray download failed after 3 attempts');
  const zip = new AdmZip(archive);
  const entry = zip.getEntry('xray');
  if (!entry) throw new Error('Xray archive does not contain an xray binary');
  fs.writeFileSync(destination, entry.getData()); fs.chmodSync(destination, 0o755);
  fs.unlinkSync(archive); console.log(`Installed Xray ${version}`);
})().catch(error => {
  if (fs.existsSync(destination)) {
    console.error(`WARNING: ${error.message}; keeping existing binary at ${destination}`);
    process.exit(0);
  }
  console.error(error.message); process.exit(1);
});
