#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const https = require('https');
const AdmZip = require('adm-zip');

const version = '25.12.8';
if (process.platform !== 'linux' || !['x64', 'arm64'].includes(process.arch)) {
  console.log(`Skipping Xray download for ${process.platform}/${process.arch}`); process.exit(0);
}
const asset = process.arch === 'arm64' ? 'Xray-linux-arm64-v8a.zip' : 'Xray-linux-64.zip';
const destination = process.env.XRAY_BIN || path.join(__dirname, 'bin', 'xray');
const archive = path.join('/tmp', `xray-${version}-${process.arch}.zip`);
if (fs.existsSync(destination)) process.exit(0);
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
  await download(`https://github.com/XTLS/Xray-core/releases/download/v${version}/${asset}`);
  const zip = new AdmZip(archive);
  const entry = zip.getEntry('xray');
  if (!entry) throw new Error('Xray archive does not contain an xray binary');
  fs.writeFileSync(destination, entry.getData()); fs.chmodSync(destination, 0o755);
  fs.unlinkSync(archive); console.log(`Installed Xray ${version}`);
})().catch(error => { console.error(error.message); process.exit(1); });
