// One-time developer setup. Run: DEPLOY-CANARY.bat  (or: node canary-server/deploy-canary.js)
// 1) deploys the canary server to your Cloudflare account
// 2) writes the live URL into background.js and manifest.json for you
// Optional: node canary-server/deploy-canary.js --url https://phishalert-canary.NAME.workers.dev
//           (skips the deploy and only patches the extension files)
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const serverDir = __dirname;
const extDir = path.join(__dirname, '..');
const argUrl = process.argv.includes('--url') ? process.argv[process.argv.indexOf('--url') + 1] : null;
const URL_RE = /https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.workers\.dev/i;

let url = argUrl;
if (!url) {
  console.log('Deploying canary server to Cloudflare (a browser window may ask you to log in)...\n');
  const r = spawnSync('npx', ['--yes', 'wrangler', 'deploy'], { cwd: serverDir, shell: true, encoding: 'utf8' });
  const out = (r.stdout || '') + (r.stderr || '');
  console.log(out);
  const m = out.match(URL_RE);
  if (r.status !== 0 || !m) {
    console.error('\nDeploy did not finish. If it asked you to log in, run this again after logging in.');
    process.exit(1);
  }
  url = m[0];
}
url = url.replace(/\/+$/, '');
if (!/^https:\/\//.test(url)) { console.error('URL must start with https://'); process.exit(1); }

function patch(file, re, replacement) {
  const p = path.join(extDir, file);
  const s = fs.readFileSync(p, 'utf8');
  if (!re.test(s)) { console.error('Could not find the canary URL line in ' + file); process.exit(1); }
  fs.writeFileSync(p, s.replace(re, replacement));
}
patch('background.js', /const CANARY_WORKER_URL = '[^']*';/, `const CANARY_WORKER_URL = '${url}';`);
patch('manifest.json', /"https:\/\/phishalert-canary[^"]*\.workers\.dev\/\*"/, `"${url}/*"`);

console.log('\nDone. Canary server: ' + url);
console.log('Now open chrome://extensions and click the reload icon on PhishAlert.');
