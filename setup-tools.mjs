#!/usr/bin/env node
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const ROOT = path.dirname(fileURLToPath(import.meta.url));
function loadLocalEnvironment() {
  if (process.env.NODE_ENV === 'production') return;
  try {
    for (const line of readFileSync(path.join(ROOT, '.env'), 'utf8').split(/\r?\n/u)) {
      const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/u);
      if (match && process.env[match[1]] === undefined) {
        process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/u, '$2');
      }
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}
loadLocalEnvironment();
if (process.platform === 'win32' && process.env.NODE_ENV !== 'production') {
  const configuredApis = ['REASONIX_SQLMAP_API_URL', 'REASONIX_ZAP_API_URL'].filter(key => process.env[key]);
  if (configuredApis.length) {
    try {
      const distro = String(process.env.REASONIX_WSL_DISTRO || 'Ubuntu').trim() || 'Ubuntu';
      const output = execFileSync('wsl.exe', [
        '--distribution', distro, '--user', 'root', '--exec', 'hostname', '-I',
      ], { encoding: 'utf8', timeout: 15000, windowsHide: true });
      const host = output.trim().split(/\s+/u).find(value =>
        /^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/u.test(value));
      if (host) {
        process.env.REASONIX_WSL_API_HOST = host;
        for (const key of configuredApis) {
          const url = new URL(process.env[key]);
          if (['localhost', '127.0.0.1', '::1'].includes(url.hostname.replace(/^\[|\]$/gu, '').toLowerCase())) {
            url.hostname = host;
            process.env[key] = url.href;
          }
        }
        for (const key of configuredApis) {
          const url = new URL(process.env[key]);
          if (['localhost', '127.0.0.1', '::1'].includes(url.hostname.replace(/^\[|\]$/gu, '').toLowerCase())) {
            url.hostname = host;
            process.env[key] = url.href;
          }
        }
      }
    } catch (error) {
      console.warn('Optional WSL API host discovery failed:', error.message);
    }
  }
}
const { toolInventory } = await import('./scan-server.mjs');
const LOCAL_TOOLS_DIR = path.join(ROOT, 'tools');
const args = new Set(process.argv.slice(2));
const installRequested = args.has('--install');
const assumeYes = args.has('--yes');
const refreshAmass = args.has('--refresh-amass');
const distro = process.env.REASONIX_WSL_DISTRO || 'Ubuntu';
const timeout = 20 * 60_000;

const CORE_COMMANDS = ['node', 'npm', 'python', 'python3', 'git', 'go', 'docker'];
const APT_PACKAGES = {
  nmap: 'nmap', nikto: 'nikto', sqlmap: 'sqlmap', whatweb: 'whatweb',
  'gitleaks': 'gitleaks', trivy: 'trivy',
  // Web scanning additions
  w3af: 'w3af', skipfish: 'skipfish', dirb: 'dirb', commix: 'commix',
  // Network additions
  netcat: 'netcat-openbsd', hping3: 'hping3', unicornscan: 'unicornscan', zmap: 'zmap',
  // OSINT / DNS additions
  dnsrecon: 'dnsrecon', fierce: 'fierce', knockpy: 'knockpy', massdns: 'massdns',
  reconng: 'recon-ng',
  // Password / brute force
  hydra: 'hydra', medusa: 'medusa', john: 'john', ncrack: 'ncrack', patator: 'patator',
  // Wireless
  bettercap: 'bettercap', reaver: 'reaver', wifite: 'wifite',
  // Traffic
  tshark: 'tshark', ngrep: 'ngrep',
  // CMS
  wpscan: 'wpscan', joomscan: 'joomscan', droopescan: 'droopescan',
  // Exploitation
  searchsploit: 'exploitdb',
  // Fuzzing / binary / memory
  radamsa: 'radamsa', boofuzz: 'boofuzz', rekall: 'rekall',
  // Secrets / code
  'detect-secrets': 'detect-secrets', brakeman: 'brakeman',
  // Cloud
  'kube-bench': 'kube-bench',
};
const GO_MODULES = {
  ffuf: 'github.com/ffuf/ffuf/v2@latest',
  nuclei: 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
  httpx: 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
  subfinder: 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
  amass: 'github.com/owasp-amass/amass/v4/cmd/amass@latest',
  assetfinder: 'github.com/tomnomnom/assetfinder@latest',
  gobuster: 'github.com/OJ/gobuster/v3@latest',
  // Additions
  feroxbuster: 'github.com/ep1cman/feroxbuster@latest',
  jaeles: 'github.com/jaeles-project/jaeles@latest',
  findomain: 'github.com/findomain/findomain@latest',
  dnsx: 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
  tlsx: 'github.com/projectdiscovery/tlsx/cmd/tlsx@latest',
  chaos: 'github.com/projectdiscovery/chaos-client/cmd/chaos@latest',
  puredns: 'github.com/d3mondev/puredns/v2@latest',
  altdns: 'github.com/infosec-au/altdns@latest',
  rustscan: 'github.com/RustScan/RustScan@latest',
};
const WINGET_PACKAGES = { nmap: 'Insecure.Nmap', gitleaks: 'Gitleaks.Gitleaks', trivy: 'AquaSecurity.Trivy' };
const CHOCO_PACKAGES = { nmap: 'nmap', gitleaks: 'gitleaks', trivy: 'trivy' };
const PIPX_PACKAGES = {
  semgrep: 'semgrep', wapiti: 'wapiti',
  // Additions
  sslyze: 'sslyze', arjun: 'arjun', dirsearch: 'dirsearch',
  xsstrike: 'xsstrike', tplmap: 'tplmap', ssrfmap: 'ssrfmap',
  holehe: 'holehe', h8mail: 'h8mail',
  scoutsuite: 'scoutsuite', cloudsploit: 'cloudsploit',
  cmseek: 'cmseek', droopescan: 'droopescan',
  pacu: 'pacu', terrascan: 'terrascan',
  angr: 'angr',
  snyk: 'snyk', njsscan: 'njsscan',
};

function scrub(value) {
  return String(value || '').slice(0, 1600)
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, '$1[REDACTED]')
    .replace(/((?:password|token|secret|api[_-]?key)=)[^&\s]*/giu, '$1[REDACTED]');
}

async function commandExists(command) {
  const lookup = process.platform === 'win32' ? 'where.exe' : 'which';
  try {
    const { stdout } = await execFileAsync(lookup, [command], { timeout: 5000, windowsHide: true });
    return stdout.trim().split(/\r?\n/u)[0] || null;
  } catch { return null; }
}

async function run(command, commandArgs, options = {}) {
  try {
    const result = await execFileAsync(command, commandArgs, {
      timeout, windowsHide: true, maxBuffer: 2 * 1024 * 1024, ...options,
    });
    return { ok: true, output: scrub(`${result.stdout || ''}${result.stderr || ''}`.trim()) };
  } catch (error) {
    return { ok: false, output: scrub(`${error.stdout || ''}${error.stderr || error.message || error}`.trim()) };
  }
}

async function hasWsl() {
  if (process.platform !== 'win32' || !await commandExists('wsl.exe')) return false;
  const result = await run('wsl.exe', [
    '--distribution', distro, '--exec', 'bash', '-lc', 'true',
  ], { timeout: 15000 });
  return result.ok;
}

async function wslCommandExists(command) {
  if (!await hasWsl()) return false;
  const safeCommand = String(command).replace(/[^A-Za-z0-9_.+-]/gu, '');
  if (!safeCommand) return false;
  const result = await run('wsl.exe', [
    '--distribution', distro, '--exec', 'bash', '-lc',
    `command -v -- '${safeCommand}' >/dev/null 2>&1`,
  ], { timeout: 15000 });
  return result.ok;
}

async function executeApt(packages, target = 'host') {
  const aptArgs = ['apt-get', 'install', '-y', ...packages];
  if (target === 'wsl') {
    const command = `apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ${packages.join(' ')}`;
    return run('wsl.exe', ['--distribution', distro, '--user', 'root', '--', 'bash', '-lc', command]);
  }
  const sudo = process.getuid?.() === 0 ? 'apt-get' : 'sudo';
  return run(sudo, sudo === 'apt-get'
    ? ['update']
    : ['apt-get', 'update']).then(async update => {
      if (!update.ok) return update;
      return run(sudo, sudo === 'apt-get' ? aptArgs : ['apt-get', ...aptArgs]);
    });
}

async function installTool(id) {
  const attempts = [];
  const module = GO_MODULES[id];
  if (module) {
    if (await commandExists('go')) {
      const result = await run('go', ['install', module], {
        env: { ...process.env, GOBIN: LOCAL_TOOLS_DIR },
      });
      attempts.push({ method: 'go install', ...result });
      if (result.ok) return attempts;
    } else if (process.platform === 'win32' && await wslCommandExists('go')) {
      const result = await run('wsl.exe', [
        '--distribution', distro, '--user', 'root', '--exec', 'bash', '-lc',
        `GOBIN=/usr/local/bin go install ${module}`,
      ]);
      attempts.push({ method: `WSL/${distro} go install`, ...result });
      if (result.ok) return attempts;
    } else attempts.push({ method: 'go install', ok: false, output: 'Go is not installed on the host or in the configured WSL distribution.' });
  }

  const aptPackage = APT_PACKAGES[id];
  if (aptPackage) {
    if (process.platform === 'linux') {
      const result = await executeApt([aptPackage]);
      attempts.push({ method: 'apt', ...result });
      if (result.ok) return attempts;
    } else if (process.platform === 'win32' && await hasWsl()) {
      const result = await executeApt([aptPackage], 'wsl');
      attempts.push({ method: `WSL/${distro} apt`, ...result });
      if (result.ok) return attempts;
    }
  }

  if (process.platform === 'win32' && WINGET_PACKAGES[id] && await commandExists('winget')) {
    const result = await run('winget.exe', [
      'install', '--id', WINGET_PACKAGES[id], '--exact', '--silent',
      '--accept-package-agreements', '--accept-source-agreements',
    ]);
    attempts.push({ method: 'winget', ...result });
    if (result.ok) return attempts;
  }
  if (process.platform === 'win32' && CHOCO_PACKAGES[id] && await commandExists('choco')) {
    const result = await run('choco.exe', ['install', CHOCO_PACKAGES[id], '-y']);
    attempts.push({ method: 'Chocolatey', ...result });
    if (result.ok) return attempts;
  }
  if (process.platform === 'darwin' && await commandExists('brew')) {
    const packageName = aptPackage || WINGET_PACKAGES[id]?.toLowerCase();
    if (packageName) {
      const result = await run('brew', ['install', packageName]);
      attempts.push({ method: 'Homebrew', ...result });
      if (result.ok) return attempts;
    }
  }
  if (PIPX_PACKAGES[id] && await commandExists('pipx')) {
    const result = await run('pipx', ['install', PIPX_PACKAGES[id]]);
    attempts.push({ method: 'pipx', ...result });
    if (result.ok) return attempts;
  }
  if (!attempts.length) attempts.push({
    method: 'no safe automatic installer',
    ok: false,
    output: 'Install manually from the project documentation or enable the corresponding package manager. No unverified download was attempted.',
  });
  return attempts;
}

async function confirmInstall() {
  if (assumeYes) return true;
  if (!process.stdin.isTTY) {
    console.error('Installation requires an interactive confirmation; rerun with --install --yes to authorize package changes.');
    return false;
  }
  process.stdout.write('Install missing supported tools using the detected package managers? [y/N] ');
  for await (const line of process.stdin) return /^y(?:es)?$/iu.test(line.trim());
  return false;
}

async function main() {
  const [inventory, hasWslRuntime] = await Promise.all([toolInventory(), hasWsl()]);
  const core = await Promise.all(CORE_COMMANDS.map(async command => ({
    name: command, available: Boolean(await commandExists(command)),
  })));
  const actions = [];
  const eligible = inventory.filter(tool => (tool.status === 'not-installed' ||
    (refreshAmass && tool.id === 'amass')) &&
    (GO_MODULES[tool.id] || APT_PACKAGES[tool.id] || WINGET_PACKAGES[tool.id] || PIPX_PACKAGES[tool.id]));

  if (installRequested && eligible.length) {
    if (!await confirmInstall()) process.exitCode = 1;
    else {
      for (const tool of eligible) {
        process.stdout.write(`\n[INSTALL] ${tool.name} (${tool.id})\n`);
        const attempts = await installTool(tool.id);
        actions.push({ id: tool.id, attempts });
        for (const attempt of attempts) {
          process.stdout.write(`${attempt.ok ? '[OK]' : '[FAILED]'} ${attempt.method}${attempt.output ? ` — ${attempt.output.slice(0, 700)}` : ''}\n`);
        }
      }
    }
  }

  const verifiedTools = installRequested && actions.length ? await toolInventory() : inventory;
  const report = {
    generatedAt: new Date().toISOString(),
    platform: `${process.platform}/${process.arch}`,
    wslDetected: hasWslRuntime,
    wslDistro: hasWslRuntime ? distro : null,
    core,
    tools: verifiedTools.map(tool => ({
      id: tool.id, name: tool.name, category: tool.category, status: tool.status,
      installed: tool.installed === true, note: tool.note || '',
    })),
    installationAttempts: actions,
    limitations: [
      'Optional APIs and services (for example SQLmap API or ZAP API) require separate service configuration and credentials.',
      'The scanner UI reports readiness from live executable/API checks; this JSON is a diagnostic snapshot, not an override.',
      'Unsupported tools are reported with guidance instead of being downloaded from unverified sources.',
    ],
  };
  const reportIndex = process.argv.indexOf('--report');
  const reportValue = reportIndex >= 0 ? process.argv[reportIndex + 1] : '';
  const reportPath = path.resolve(process.cwd(), reportValue && !reportValue.startsWith('--') ? reportValue : 'tool-readiness.json');
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });

  const ready = verifiedTools.filter(tool => tool.status === 'available').length;
  const notRun = verifiedTools.filter(tool => tool.status === 'not-run').length;
  const missing = verifiedTools.filter(tool => tool.status === 'not-installed').length;
  const blocked = verifiedTools.filter(tool => tool.status === 'blocked').length;
  console.log(`\nTool readiness: ${ready} ready, ${notRun} not run (scope/consent required), ${missing} missing, ${blocked} blocked.`);
  console.log(`Report: ${reportPath}`);
  if (missing || blocked) console.log('Missing or blocked tools remain visible as such in the UI; no success state is fabricated.');
  if (args.has('--check') || !installRequested) return;
  if (actions.some(action => action.attempts.every(attempt => !attempt.ok))) process.exitCode = 1;
}

main().catch(error => {
  console.error(`Tool verification failed: ${error.message}`);
  process.exitCode = 1;
});
