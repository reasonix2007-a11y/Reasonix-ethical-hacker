// خادم الفحص الحقيقي — Reasonix Live Scanner
// نفّذ اختبارات فعلية على الهدف عبر HTTP(S) ويعيد أدلة حقيقية (evidence) من الاستجابات.
// تشغيل: node scan-server.mjs  → http://127.0.0.1:7777
// استعلام: POST /scan { target, profile, mods:[...] } → JSON findings حقيقية
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import dns from 'node:dns/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';
import { URL } from 'node:url';
import { AsyncLocalStorage } from 'node:async_hooks';
import { HttpProxyAgent } from 'http-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import {
  buildPipelineTargets,
  analyzeHeuristicResponses,
  createEvidenceObject,
  extractWebDiscovery,
  heuristicProbePayloads,
  isSensitiveParameterName,
  localApiBase,
  optionalIntegrationFailure,
  optionalIntegrationSkip,
  parseNmapXml,
  parseRobotsDiscovery,
  runSqlmapApiScan,
  runZapPassiveScan,
} from './scan-integrations.mjs';

const PORT = Number(process.env.REASONIX_SCAN_PORT) || 17777;
const IS_PRODUCTION = process.env.NODE_ENV === 'production' ||
  (Boolean(process.env.PORT) && process.env.NODE_ENV !== 'development');
const SCAN_JOBS = new Map();
const SCAN_CONTEXT = new AsyncLocalStorage();
const WINDOWS_SCAN_CONSOLE_DIR = path.join(os.tmpdir(), 'reasonix-scan-console');
const QUICK_SCAN_RATE = new Map(); /* ip → {count, resetAt} — حد 5 فحوص/دقيقة */
const QUICK_SCAN_ACTIVE = new Set(); /* نطاقات قيد الفحص السريع الآن */

function safeConsoleText(value) {
  return redactScanSecrets(String(value ?? ''))
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/gu, '')
    .replace(/([?&](?:token|access_token|api[_-]?key|secret|password|session|credential)=)[^&\s]*/giu, '$1[REDACTED]')
    .replace(/[\r\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/gu, '')
    .slice(0, 2000);
}

function formatWindowsConsoleEvent(event) {
  const name = safeConsoleText(event.name || event.id || event.type || 'scan');
  if (event.type === 'tool-output') {
    const stream = event.stream === 'stderr' ? 'stderr' : 'stdout';
    return String(event.text || '').split(/\r?\n/u).filter(Boolean)
      .map(line => `[${name} · ${stream}] ${safeConsoleText(line)}`).join('\n');
  }
  if (event.type === 'pipeline') {
    return `[PIPELINE ${String(event.status || 'unknown').toUpperCase()}] ${name}${event.note ? ` — ${safeConsoleText(event.note)}` : ''}`;
  }
  if (event.type === 'tool') {
    const lines = [`[${String(event.status || 'unknown').toUpperCase()}] ${name}`];
    if (event.command) lines.push(`$ ${safeConsoleText(event.command)}`);
    if (event.message || event.note) lines.push(safeConsoleText(event.message || event.note));
    if (event.summary) lines.push(safeConsoleText(event.summary));
    if (event.error) lines.push(`[ERROR] ${safeConsoleText(event.error)}`);
    return lines.join('\n');
  }
  if (event.type === 'access') {
    return `[ACCESS ${safeConsoleText(event.httpStatus || event.status || 'unknown')}] ${safeConsoleText(event.note || event.name || '')}`;
  }
  return `[${String(event.type || 'EVENT').toUpperCase()}] ${name}${event.message ? ` — ${safeConsoleText(event.message)}` : ''}`;
}

async function openWindowsScanConsole(target, scanId, profile) {
  if (process.platform !== 'win32' || IS_PRODUCTION || process.env.REASONIX_OPEN_SCAN_CONSOLE === 'false') return null;
  const logPath = path.join(WINDOWS_SCAN_CONSOLE_DIR, `${scanId}.log`);
  try {
    await fs.mkdir(WINDOWS_SCAN_CONSOLE_DIR, { recursive: true });
    const hostname = new URL(target).hostname;
    await fs.writeFile(logPath, [
      'Reasonix live scan console',
      `Target: ${hostname}`,
      `Profile: ${profile}`,
      `Scan ID: ${scanId}`,
      'Only events and redacted commands from the running scan are shown.',
      'Metasploit: not integrated; no exploit modules are loaded or run.',
      '---',
    ].join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
    const escapedLogPath = logPath.replace(/'/gu, "''");
    const script = `$Host.UI.RawUI.WindowTitle = 'Reasonix scan ${scanId}'; Get-Content -LiteralPath '${escapedLogPath}' -Wait | ForEach-Object { Write-Host $_; if ($_ -match '^\\[SCAN (COMPLETE|CANCELLED|FAILED)\\]') { break } }; Read-Host 'Scan finished. Press Enter to close'; Remove-Item -LiteralPath '${escapedLogPath}' -Force -ErrorAction SilentlyContinue`;
    const encodedScript = Buffer.from(script, 'utf16le').toString('base64');
    const terminal = spawn('cmd.exe', [
      '/d', '/s', '/c',
      `start "" powershell.exe -NoLogo -NoExit -EncodedCommand ${encodedScript}`,
    ], { detached: true, stdio: 'ignore', windowsHide: true });
    terminal.once('error', error => console.warn('Could not open the scan PowerShell window:', error.message));
    terminal.unref();
    let queue = Promise.resolve();
    return {
      write(line) {
        if (!line) return queue;
        queue = queue.then(() => fs.appendFile(logPath, `${safeConsoleText(line)}\n`, 'utf8'))
          .catch(error => { console.warn('Could not write scan console output:', error.message); });
        return queue;
      },
      async finish(status, message) {
        await this.write(`[SCAN ${status}] ${message}`);
        await queue;
      },
    };
  } catch (error) {
    console.warn('Could not prepare the scan PowerShell window:', error.message);
    return null;
  }
}

function currentScanSignal() {
  const context = SCAN_CONTEXT.getStore();
  if (!context) return undefined;
  return context instanceof AbortSignal ? context : context.signal;
}

function currentScanOptions() {
  const context = SCAN_CONTEXT.getStore();
  return context && !(context instanceof AbortSignal) ? context : {};
}

function normalizeCustomHeaders(value) {
  const raw = String(value || '');
  if (raw.length > 8192) throw new Error('Custom headers exceed the 8 KB limit.');
  const lines = raw.split(/\r?\n/u).map(line => line.trim()).filter(Boolean);
  if (lines.length > 16) throw new Error('At most 16 custom headers are allowed.');
  const headers = {};
  const seen = new Set();
  const reserved = new Set([
    'authorization', 'cookie', 'host', 'content-length', 'transfer-encoding', 'connection',
    'proxy-authorization', 'proxy-connection', 'upgrade', 'keep-alive', 'te', 'trailer',
  ]);
  for (const line of lines) {
    const separator = line.indexOf(':');
    if (separator <= 0) throw new Error('Each custom header must use the format "Name: value".');
    const name = line.slice(0, separator).trim();
    const headerValue = line.slice(separator + 1).trim();
    const key = name.toLowerCase();
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(name) || reserved.has(key))
      throw new Error(`Invalid or reserved custom header name: ${name || '(empty)'}.`);
    if (seen.has(key)) throw new Error(`Duplicate custom header: ${name}.`);
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/u.test(headerValue))
      throw new Error(`Custom header "${name}" contains invalid control characters.`);
    seen.add(key);
    headers[name] = headerValue;
  }
  return headers;
}

function normalizeScanOptions(value = {}) {
  const headers = {};
  const cookie = String(value?.cookie || '').trim();
  const authorization = String(value?.authorization || '').trim();
  if (cookie.length > 8192 || /[\r\n]/u.test(cookie) || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/u.test(cookie))
    throw new Error('قيمة Cookie غير صالحة أو أطول من الحد المسموح.');
  if (authorization.length > 4096 || /[\r\n]/u.test(authorization) || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/u.test(authorization))
    throw new Error('قيمة Authorization غير صالحة أو أطول من الحد المسموح.');
  if (cookie) headers.Cookie = cookie;
  if (authorization) headers.Authorization = authorization;
  Object.assign(headers, normalizeCustomHeaders(value?.customHeaders));
  const headerBytes = Object.entries(headers).reduce((sum, [name, headerValue]) => sum + Buffer.byteLength(name) + Buffer.byteLength(headerValue), 0);
  if (headerBytes > 8192) throw new Error('Combined authentication headers exceed the 8 KB limit.');

  let proxy = '';
  if (value?.proxy) {
    let parsed;
    try { parsed = new URL(String(value.proxy)); }
    catch { throw new Error('عنوان البروكسي غير صالح. استخدم عنوان HTTP محلي مثل http://127.0.0.1:8080.'); }
    const hostname = parsed.hostname.replace(/^\[|\]$/gu, '').toLowerCase();
    if (parsed.protocol !== 'http:' || !['127.0.0.1', '::1', 'localhost'].includes(hostname) ||
        parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash)
      throw new Error('يسمح فقط ببروكسي HTTP محلي على localhost أو 127.0.0.1 أو ::1، دون بيانات دخول مضمّنة.');
    proxy = parsed.origin;
  }
  return {
    headers,
    proxy,
    enableSqlmap: value?.enableSqlmap === true,
    enableZap: value?.enableZap === true,
    enableHeuristicFuzzing: value?.enableHeuristicFuzzing === true,
    activeTestsConfirmed: value?.activeTestsConfirmed === true,
    observedStatusCounts: { 401: 0, 403: 0, 429: 0 },
    ...(proxy ? { httpAgent: new HttpProxyAgent(proxy), httpsAgent: new HttpsProxyAgent(proxy) } : {}),
  };
}

export function runWithScanOptions(options, callback) {
  const signal = currentScanSignal();
  return SCAN_CONTEXT.run({ ...normalizeScanOptions(options), signal }, callback);
}

export function classifyHttpStatus(status) {
  if (status === 401) return 'authentication-required';
  if (status === 403) return 'access-forbidden';
  if (status === 429) return 'rate-limited';
  return 'reachable';
}

function retryAfterMilliseconds(value, attempt) {
  if (value) {
    const seconds = Number(value);
    const dateDelay = Number.isFinite(seconds) ? seconds * 1000 : Date.parse(value) - Date.now();
    if (Number.isFinite(dateDelay) && dateDelay >= 0) return Math.min(dateDelay, 8000);
  }
  return attempt === 0 ? 500 : 1500;
}

function waitForRetry(delay, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('scan-cancelled'));
    const timer = setTimeout(done, delay);
    function done() {
      signal?.removeEventListener('abort', abort);
      resolve();
    }
    function abort() {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reject(new Error('scan-cancelled'));
    }
    signal?.addEventListener('abort', abort, { once: true });
  });
}

const HTTP_REQUESTS_PER_ORIGIN = 4;
const HTTP_REQUEST_START_INTERVAL_MS = 200;
const HTTP_REQUEST_SCHEDULERS = new Map();

function pumpHttpRequests(origin, scheduler) {
  if (scheduler.starting || scheduler.active >= HTTP_REQUESTS_PER_ORIGIN || !scheduler.queue.length) return;
  const entry = scheduler.queue.shift();
  entry.signal?.removeEventListener('abort', entry.onAbort);
  if (entry.signal?.aborted) {
    entry.resolve(null);
    pumpHttpRequests(origin, scheduler);
    return;
  }

  scheduler.active++;
  scheduler.starting = true;
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    scheduler.active--;
    if (scheduler.active === 0 && scheduler.queue.length === 0) HTTP_REQUEST_SCHEDULERS.delete(origin);
    else pumpHttpRequests(origin, scheduler);
  };
  const delay = Math.max(0, scheduler.nextStartAt - Date.now());
  waitForRetry(delay, entry.signal).then(() => {
    scheduler.starting = false;
    if (entry.signal?.aborted) {
      release();
      entry.resolve(null);
      return;
    }
    scheduler.nextStartAt = Date.now() + HTTP_REQUEST_START_INTERVAL_MS;
    entry.resolve(release);
    pumpHttpRequests(origin, scheduler);
  }, () => {
    scheduler.starting = false;
    release();
    entry.resolve(null);
  });
}

function acquireHttpRequestSlot(origin, signal) {
  if (signal?.aborted) return Promise.resolve(null);
  let scheduler = HTTP_REQUEST_SCHEDULERS.get(origin);
  if (!scheduler) {
    scheduler = { active: 0, queue: [], nextStartAt: 0 };
    HTTP_REQUEST_SCHEDULERS.set(origin, scheduler);
  }
  return new Promise(resolve => {
    const entry = { signal, resolve, onAbort: null };
    entry.onAbort = () => {
      const index = scheduler.queue.indexOf(entry);
      if (index >= 0) scheduler.queue.splice(index, 1);
      signal.removeEventListener('abort', entry.onAbort);
      resolve(null);
      if (scheduler.active === 0 && scheduler.queue.length === 0) HTTP_REQUEST_SCHEDULERS.delete(origin);
    };
    signal?.addEventListener('abort', entry.onAbort, { once: true });
    scheduler.queue.push(entry);
    pumpHttpRequests(origin, scheduler);
  });
}

function throwIfScanAborted() {
  if (currentScanSignal()?.aborted) {
    const error = new Error('scan-cancelled');
    error.name = 'AbortError';
    throw error;
  }
}

/* ---------------- أدوات ---------------- */
function isPublicAddress(address) {
  const ip = String(address || '').replace(/^\[|\]$/g, '').split('%')[0];
  const family = net.isIP(ip);
  if (family === 4) {
    const octets = ip.split('.').map(Number);
    const [a, b, c] = octets;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) return false;
    if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  if (family !== 6) return false;
  const groups = ip.toLowerCase().split('::');
  if (groups.length > 2) return false;
  const left = groups[0] ? groups[0].split(':') : [];
  const right = groups[1] ? groups[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (groups.length === 1 && missing !== 0)) return false;
  const full = [...left, ...Array(missing).fill('0'), ...right].map(value => parseInt(value || '0', 16));
  if (full.length !== 8 || full.some(value => !Number.isInteger(value) || value < 0 || value > 0xffff)) return false;
  let value = 0n;
  for (const group of full) value = (value << 16n) | BigInt(group);
  // Allow only globally routable unicast (2000::/3), excluding special-use ranges.
  if ((value >> 125n) !== 1n) return false;
  if ((value >> 112n) === 0x2002n) return false; // 6to4
  if ((value >> 96n) === 0x20010db8n) return false; // documentation
  if ((value >> 105n) === 0x200100n) return false; // IETF special-purpose 2001::/23
  return true;
}

async function lookupTarget(hostname, options = {}) {
  const host = String(hostname).replace(/^\[|\]$/g, '').split('%')[0];
  const family = net.isIP(host);
  const records = family ? [{ address: host, family }] : await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length) throw new Error('Target host did not resolve.');
  if (IS_PRODUCTION && records.some(record => !isPublicAddress(record.address)))
    throw new Error('Target resolves to a non-public address and was blocked.');
  const filtered = options.family ? records.filter(record => record.family === options.family) : records;
  if (!filtered.length) throw new Error('Target has no address matching the requested family.');
  return filtered;
}

function guardedLookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  const settings = typeof options === 'number' ? { family: options } : (options || {});
  const signal = currentScanSignal();
  let settled = false;
  const finish = (error, records) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
    if (error) callback(error);
    else if (settings.all) callback(null, records);
    else callback(null, records[0].address, records[0].family);
  };
  const onAbort = () => finish(new Error('scan-cancelled'));
  const timer = setTimeout(() => finish(new Error('DNS lookup timed out.')), 10_000);
  signal?.addEventListener('abort', onAbort, { once: true });
  if (signal?.aborted) return onAbort();
  lookupTarget(hostname, settings).then(records => {
    finish(null, records);
  }, error => finish(error));
}

const requestOnce = async (url, opt = {}, timeout = 8000) => {
  const signal = opt.signal || currentScanSignal();
  const scanOptions = currentScanOptions();
  const u = new URL(url);
  const releaseSlot = await acquireHttpRequestSlot(u.origin, signal);
  if (!releaseSlot) return { ok: false, error: 'aborted' };
  return new Promise(resolve => {
    if (signal?.aborted) {
      releaseSlot();
      return resolve({ ok: false, error: 'aborted' });
    }
    const isTLS = u.protocol === 'https:';
    const mod = isTLS ? https : http;
    const agent = isTLS ? scanOptions.httpsAgent : scanOptions.httpAgent;
    const p = {
      method: opt.method || 'GET', hostname: u.hostname, path: u.pathname + u.search,
      headers: {
        'User-Agent': 'Mozilla/5.0 (ReasonixEthicalHacker/1.0 LiveProbe)',
        'Accept': '*/*', ...(opt.headers || {}),
        ...(!opt.omitScanHeaders && (!scanOptions.targetOrigin || u.origin === scanOptions.targetOrigin)
          ? scanOptions.headers : {})
      },
      timeout,
      lookup: guardedLookup,
      ...(agent ? { agent } : {}),
      ...(isTLS ? { rejectUnauthorized: opt.rejectUnauthorized !== false } : {}),
      /* منفذ الـ URL يُستخدم افتراضياً (مثل 8099)، و opt.port يتجاوزه إن وُجد */
      ...(u.port ? { port: parseInt(u.port, 10) } : {}),
      ...(opt.port ? { port: opt.port } : {})
    };
    let settled = false;
    let hardTimeout;
    let r;
    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimeout);
      signal?.removeEventListener('abort', onAbort);
      releaseSlot();
      resolve(result);
    };
    const onAbort = () => { r.destroy(); finish({ ok: false, error: 'aborted' }); };
    try {
      r = mod.request(p, res => {
        let body = '';
        let bodyTruncated = false;
        res.setEncoding('utf8');
        res.on('data', chunk => {
          const remaining = 200000 - body.length;
          if (remaining > 0) body += chunk.slice(0, remaining);
          if (chunk.length > remaining) bodyTruncated = true;
        });
        res.on('aborted', () => finish({ ok: false, error: 'response-aborted' }));
        res.on('end', () => {
          if ([401, 403, 429].includes(res.statusCode) && scanOptions.observedStatusCounts)
            scanOptions.observedStatusCounts[res.statusCode]++;
          finish({
            ok: true, status: res.statusCode, accessState: classifyHttpStatus(res.statusCode),
            headers: res.headers, body, url,
            ...(bodyTruncated ? { bodyTruncated: true } : {}),
          });
        });
      });
    } catch (error) {
      releaseSlot();
      resolve({ ok: false, error: error.code || error.message });
      return;
    }
    hardTimeout = setTimeout(() => { r.destroy(); finish({ ok: false, error: 'timeout' }); }, timeout);
    signal?.addEventListener('abort', onAbort, { once: true });
    r.on('timeout', () => { r.destroy(); finish({ ok: false, error: 'timeout' }); });
    r.on('error', e => finish({ ok: false, error: e.code || e.message }));
    r.end(opt.body || undefined);
  });
};

const req = async (url, opt = {}, timeout = 8000) => {
  const method = String(opt.method || 'GET').toUpperCase();
  for (let attempt = 0; attempt < 3; attempt++) {
    const result = await requestOnce(url, opt, timeout);
    if (result.status !== 429 || attempt === 2 || opt.retry429 === false ||
        !['GET', 'HEAD', 'OPTIONS'].includes(method)) return result;
    const delay = retryAfterMilliseconds(result.headers?.['retry-after'], attempt);
    result.retryAfterMs = delay;
    await waitForRetry(delay, opt.signal || currentScanSignal());
  }
  return { ok: false, error: 'unreachable' };
};
export { req };

const tlsInfo = (host, port = 443) => new Promise(resolve => {
  const signal = currentScanSignal();
  if (signal?.aborted) return resolve({ ok: false, error: 'aborted' });
  const s = tls.connect({ host, port, servername: net.isIP(String(host).replace(/^\[|\]$/g, '')) ? undefined : host, lookup: guardedLookup, timeout: 7000, rejectUnauthorized: false }, () => {
    const c = s.getPeerCertificate(true);
    const chain = []; let cur = c;
    let depth = 0;
    while (cur && cur.subject && depth < 5) {
      chain.push({
        subject: cur.subject.CN || cur.subject.O || '?',
        issuer: cur.issuer?.CN || cur.issuer?.O || '?',
        valid_to: cur.valid_to, bits: cur.bits || (cur.pubKey ? 256 : null)
      });
      cur = s.getPeerCertificate(++depth === 1 ? true : depth);
      if (!cur || !cur.subject || chain.some(x => x.subject === (cur?.subject?.CN))) break;
    }
    // تفاصيل التشفير
    let cipher = null, proto = null;
    try { cipher = s.getCipher()?.name; proto = s.getProtocol(); } catch { }
    s.end();
    resolve({ ok: true, chain, cipher, proto });
  });
  const onAbort = () => { s.destroy(); resolve({ ok: false, error: 'aborted' }); };
  signal?.addEventListener('abort', onAbort, { once: true });
  s.once('close', () => signal?.removeEventListener('abort', onAbort));
  s.on('error', e => resolve({ ok: false, error: e.code || e.message }));
  s.on('timeout', () => { s.destroy(); resolve({ ok: false, error: 'timeout' }); });
});

const portOpen = (host, port, timeout = 4000) => new Promise(resolve => {
  const signal = currentScanSignal();
  if (signal?.aborted) return resolve(false);
  const s = net.connect({ host, port, timeout, lookup: guardedLookup });
  const onAbort = () => { s.destroy(); resolve(false); };
  signal?.addEventListener('abort', onAbort, { once: true });
  s.once('close', () => signal?.removeEventListener('abort', onAbort));
  s.on('connect', () => { s.destroy(); resolve(true); });
  s.on('error', () => resolve(false));
  s.on('timeout', () => { s.destroy(); resolve(false); });
});

export function isAdminPanelResponse(body, baselineBody = '') {
  const response = String(body || '').trim();
  if (!response || response === String(baselineBody || '').trim()) return false;
  const heading = response.match(/<(?:title|h1)\b[^>]*>([\s\S]*?)<\/(?:title|h1)\s*>/iu)?.[1]
    ?.replace(/<[^>]*>/gu, ' ').replace(/\s+/gu, ' ').trim() || '';
  if (/\b(?:admin(?:istration)?(?:\s+panel)?|dashboard|control\s+panel|management\s+console)\b/iu.test(heading))
    return true;
  return /<form\b[\s\S]{0,4000}<\/form\s*>/iu.test(response) &&
    /<input\b[^>]*type\s*=\s*["']?password\b/iu.test(response) &&
    /\b(?:sign\s+in|log\s*in|login)\b/iu.test(response);
}

function normalizeSoft404Body(body, pathname = '') {
  return String(body || '').slice(0, 20_000)
    .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/giu, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/giu, '')
    .replace(/<!--[\s\S]*?-->/gu, '')
    .replace(/(csrf|nonce|request[_-]?id|trace[_-]?id)(?:["'\s:=]+)[a-z0-9._~-]{6,}/giu, '$1=[dynamic]')
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/giu, '[uuid]')
    .replace(/\b\d{4}-\d\d-\d\d(?:[t ][0-9:.z+-]+)?\b/giu, '[date]')
    .replace(pathname, '[requested-path]')
    .replace(/>\s+</gu, '><')
    .replace(/\s+/gu, ' ')
    .trim()
    .toLowerCase();
}

function soft404Similarity(left, right) {
  if (left === right) return 1;
  if (Math.min(left.length, right.length) < 80) return 0;
  const shingles = text => {
    const words = text.split(/[^a-z0-9\u0600-\u06ff]+/giu).filter(Boolean);
    const result = new Set();
    for (let index = 0; index + 3 <= words.length; index++) result.add(words.slice(index, index + 3).join(' '));
    return result;
  };
  const leftShingles = shingles(left);
  const rightShingles = shingles(right);
  if (!leftShingles.size || !rightShingles.size) return 0;
  let intersection = 0;
  for (const shingle of leftShingles) if (rightShingles.has(shingle)) intersection++;
  return intersection / (leftShingles.size + rightShingles.size - intersection);
}

export function isSoft404Response(body, status, baseline, responseUrl) {
  if (!baseline || Number(status) !== Number(baseline.status) ||
      Number(status) < 200 || Number(status) >= 400 || [401, 403, 429].includes(Number(status))) return false;
  let canaryPath = '', candidatePath = '';
  try { canaryPath = new URL(baseline.url).pathname; } catch {}
  try { candidatePath = responseUrl ? new URL(responseUrl).pathname : ''; } catch {}
  const candidate = normalizeSoft404Body(body, candidatePath);
  const canary = normalizeSoft404Body(baseline.body, canaryPath);
  return soft404Similarity(candidate, canary) >= 0.88;
}

async function soft404Canary(base, options = {}) {
  const url = new URL(base);
  const path = `/.well-known/reasonix-canary-${crypto.randomUUID()}`;
  const response = await req(`${url.origin}${path}`, options, 6000);
  return response.ok ? { status: response.status, body: response.body, url: response.url || `${url.origin}${path}` } : null;
}

export function sensitiveFileExposure(pathname, body) {
  const path = String(pathname || '').toLowerCase();
  const content = String(body || '').slice(0, 200_000);
  if (!content.trim() || /^\s*(?:<!doctype|<html)\b/iu.test(content)) return null;
  if (path === '/.env' && /^(?:[A-Z_][A-Z0-9_]*\s*=\s*.+\s*){2,}$/imu.test(content) &&
      /(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|DATABASE_URL|PRIVATE_KEY)\s*=/iu.test(content))
    return { severity: 'high', reason: 'Environment file contains secret-like configuration assignments.' };
  if (path === '/.git/config' && /^\s*\[(?:core|remote\s+"[^"]+")\]\s*$/imu.test(content))
    return { severity: 'low', reason: 'Git repository configuration is publicly readable.' };
  if (path === '/.git/head' && /^\s*ref:\s+refs\/(?:heads|tags)\//imu.test(content))
    return { severity: 'low', reason: 'Git repository metadata is publicly readable.' };
  if (/\/(?:backup|db|database)(?:[^/]*)(?:\.sql|\.dump|\.bak)$/iu.test(path) &&
      /\b(?:CREATE\s+TABLE|INSERT\s+INTO|COPY\s+\S+\s+FROM|--\s*(?:MySQL|PostgreSQL)\s+dump)\b/iu.test(content))
    return { severity: 'high', reason: 'Response contains database backup or dump signatures.' };
  if (/\/(?:config\.php(?:\.(?:bak|old|backup))?|web\.config\.(?:bak|old|backup)|[^/]+\.config\.(?:bak|old|backup))$/iu.test(path) &&
      /(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_ -]?KEY)\s*[:=]\s*["']?[^"'\s]{4,}/iu.test(content))
    return { severity: 'high', reason: 'Response contains secret-like configuration values.' };
  if (path === '/server-status' && /\bApache Server Status\b|\bServer uptime\b|\bTotal accesses\b/iu.test(content))
    return { severity: 'medium', reason: 'Apache server-status information is publicly readable.' };
  return null;
}

export function analyzeSecurityHeaders(headers = {}, isHttps = false) {
  const received = Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  const directives = new Map(String(received['content-security-policy'] || '').split(';')
    .map(part => part.trim().split(/\s+/u))
    .filter(([name]) => name)
    .map(([name, ...values]) => [name.toLowerCase(), values.map(value => value.toLowerCase())]));
  const fallbackScriptSources = directives.get('script-src') || directives.get('default-src') || [];
  const scriptElementSources = directives.get('script-src-elem') || fallbackScriptSources;
  const scriptAttributeSources = directives.get('script-src-attr') || fallbackScriptSources;
  const allowsInline = sources => sources.includes("'unsafe-inline'") &&
    !sources.some(source => /^'(?:nonce-|sha(?:256|384|512)-)/iu.test(source));
  const weakCsp = [];
  if (allowsInline(scriptElementSources)) weakCsp.push("script-src permits 'unsafe-inline'");
  if (allowsInline(scriptAttributeSources) && scriptAttributeSources !== scriptElementSources)
    weakCsp.push("script-src-attr permits 'unsafe-inline'");
  if (fallbackScriptSources.includes("'unsafe-eval'")) weakCsp.push("script-src permits 'unsafe-eval'");
  const contentType = String(received['content-type'] || '');
  const isHtml = !contentType || /(?:text\/html|application\/xhtml\+xml)/iu.test(contentType);
  const missing = [
    ...(isHttps ? ['strict-transport-security'] : []),
    ...(isHtml ? ['content-security-policy'] : []),
    'x-content-type-options',
    ...(isHtml && !/frame-ancestors\s+[^;]+/iu.test(String(received['content-security-policy'] || '')) && !received['x-frame-options']
      ? ['x-frame-options or CSP frame-ancestors'] : []),
    'referrer-policy',
  ].filter(name => {
    if (name === 'x-frame-options or CSP frame-ancestors') return true;
    return !received[name];
  });
  const advisoryMissing = ['permissions-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy']
    .filter(name => !received[name]);
  return { missing, weakCsp, advisoryMissing };
}

export function apiEndpointExposure(pathname, contentType, body) {
  const path = String(pathname || '').toLowerCase();
  const content = String(body || '').slice(0, 200_000);
  const isJson = /json/iu.test(String(contentType || '')) || /^\s*[{[]/u.test(content);
  if (!isJson) return null;
  if (path === '/actuator/env' && /"(?:propertySources|activeProfiles)"\s*:/iu.test(content))
    return { severity: 'medium', reason: 'Spring Boot environment endpoint returned a recognizable environment document.' };
  if (['/swagger.json', '/api-docs'].includes(path) && /"(?:openapi|swagger)"\s*:\s*["'][0-9.]+/iu.test(content))
    return { severity: 'info', reason: 'Public API documentation endpoint was confirmed; exposure alone does not prove a vulnerability.' };
  return null;
}

export function findExternalAssetsWithoutSri(html, base) {
  const pageOrigin = new URL(base).origin;
  const assets = [];
  const source = String(html || '').slice(0, 200_000);
  for (const match of source.matchAll(/<(script|link)\b[^>]*>/giu)) {
    const tag = match[1].toLowerCase();
    const element = match[0];
    const attributes = Object.fromEntries([...element.matchAll(/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gu)]
      .map(attribute => [attribute[1].toLowerCase(), attribute[2] ?? attribute[3] ?? attribute[4] ?? '']));
    const rawUrl = tag === 'script' ? attributes.src
      : /\bstylesheet\b/iu.test(attributes.rel || '') ? attributes.href : '';
    if (!rawUrl || attributes.integrity) continue;
    let asset;
    try { asset = new URL(rawUrl, base); } catch { continue; }
    if (!['http:', 'https:'].includes(asset.protocol) || asset.origin === pageOrigin) continue;
    assets.push({
      tag,
      url: `${asset.origin}${asset.pathname}`.slice(0, 500),
    });
    if (assets.length >= 30) break;
  }
  return assets;
}

export function analyzeCookieSecurity(headers = {}, isHttps = false) {
  const values = headers['set-cookie'] ?? headers['Set-Cookie'] ?? [];
  const cookies = Array.isArray(values) ? values : [values];
  const issues = [];
  for (const cookie of cookies) {
    const [pair = '', ...attributes] = String(cookie).split(';');
    const name = pair.split('=', 1)[0].trim();
    if (!name) continue;
    const normalized = attributes.map(attribute => attribute.trim().toLowerCase());
    const isSessionCookie = /(?:session|sid|auth|token|jwt)/iu.test(name);
    const missing = [];
    if (isHttps && !normalized.includes('secure')) missing.push('Secure');
    if (isSessionCookie && !normalized.includes('httponly')) missing.push('HttpOnly');
    if (isSessionCookie && !normalized.some(attribute => attribute.startsWith('samesite='))) missing.push('SameSite');
    if (missing.length) issues.push({ name: name.slice(0, 100), missing });
  }
  return issues;
}

export function analyzeCorsPolicy(headers = {}, probeOrigin) {
  const normalized = Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  const allowedOrigin = String(normalized['access-control-allow-origin'] || '').trim();
  const allowCredentials = /^true$/iu.test(String(normalized['access-control-allow-credentials'] || '').trim());
  const vary = String(normalized.vary || '').split(',').map(value => value.trim().toLowerCase());
  const reflectedOrigin = Boolean(probeOrigin && allowedOrigin === probeOrigin);
  return {
    reflectedOrigin,
    allowCredentials,
    varyByOrigin: vary.includes('origin'),
    riskyReflection: Boolean(reflectedOrigin && allowCredentials),
  };
}

/* ---------------- كاشفات (كل واحدة تُرجع null إن لم تجد شيئاً) ---------------- */
export function compareBehavioralResponses(control, candidate, controlMarker, probeMarker) {
  const controlBody = String(control?.body || '');
  const candidateBody = String(candidate?.body || '');
  const placeholder = '[REASONIX-CONTROLLED-REFLECTION]';
  const normalize = body => body.split(controlMarker).join(placeholder).split(probeMarker).join(placeholder);
  return {
    controlStatus: control?.status || 0,
    probeStatus: candidate?.status || 0,
    statusChanged: control?.status !== candidate?.status,
    controlLength: controlBody.length,
    probeLength: candidateBody.length,
    bodyLengthDelta: candidateBody.length - controlBody.length,
    controlMarkerReflected: controlBody.includes(controlMarker),
    probeMarkerReflectedRaw: candidateBody.includes(probeMarker),
    normalizedBodiesEqual: normalize(controlBody) === normalize(candidateBody),
  };
}

const CHECKS = {

  // 1) لوحة إدارة مكشوفة
  async adminPanel(base) {
    const baseline = await soft404Canary(base);
    for (const p of ['/admin/', '/admin', '/administrator/', '/wp-admin/', '/manager/html', '/phpmyadmin/', '/panel/']) {
      const r = await req(base + p, {}, 6000);
      if (r.ok && r.status === 200 && !isSoft404Response(r.body, r.status, baseline, r.url) &&
          isAdminPanelResponse(r.body, baseline?.body || ''))
        return { k: 'admin-interface-discovered', sev: 'info', confidence: 'moderate',
          title: 'واجهة إدارة مكتشفة — يلزم التحقق من ضوابط الوصول',
          desc: 'اكتشاف الواجهة لا يثبت وجود تجاوز مصادقة أو ثغرة؛ لم تُختبر بيانات الدخول أو صلاحيات المستخدم.',
          ep: p, evidence: [`GET ${p} → HTTP ${r.status}`, 'تمت مطابقة عنوان/محتوى إداري مميز؛ لم تُرسل بيانات اعتماد.']
        };
    }
    return null;
  },

  // 2) ملفات حساسة معروضة
  async sensitiveFiles(base) {
    const baseline = await soft404Canary(base);
    const files = ['/.env', '/.env.local', '/.env.production', '/.git/config', '/.git/HEAD', '/backup.sql', '/db.sql', '/database.sql', '/config.php.bak', '/web.config.bak', '/server-status', '/database.sql.gz', '/site.tar.gz', '/backup.tar.gz', '/settings.py', '/wp-config.php.bak'];
    for (const f of files) {
      const r = await req(base + f, {}, 6000);
      const exposure = r.ok && r.status === 200 && !isSoft404Response(r.body, r.status, baseline, r.url)
        ? sensitiveFileExposure(f, r.body) : null;
      if (exposure) {
        return {
          k: `sensitive-file-${f.replace(/[^a-z0-9]+/giu, '-')}`, sev: exposure.severity,
          confidence: 'high', title: 'ملف أو بيانات حساسة مكشوفة — ' + f,
          desc: exposure.reason,
          ep: f, evidence: [`GET ${f} → HTTP ${r.status}`, 'تم حجب محتوى الاستجابة من التقرير لتجنب تسريب أسرار.']
        };
      }
    }
    return null;
  },

  // 3) ترويسات أمان ناقصة
  async securityHeaders(base) {
    const r = await req(base + '/', {}, 7000);
    if (!r.ok) return null;
    const assessment = analyzeSecurityHeaders(r.headers, new URL(base).protocol === 'https:');
    if (assessment.missing.length || assessment.weakCsp.length)
      return {
        k: 'security-header-policy', sev: assessment.weakCsp.length ? 'medium' : 'low',
        title: 'نقص أو ضعف في سياسة ترويسات الأمان',
        ep: 'HTTP response headers',
        evidence: [`GET / → HTTP ${r.status}`,
          ...assessment.missing.map(header => `الترويسة أو التوجيه غائب: ${header}`),
          ...assessment.weakCsp.map(directive => `CSP policy allows ${directive}`)]
      };
    return null;
  },

  async subresourceIntegrity(base) {
    const response = await req(base + '/', {}, 7000);
    if (!response.ok || !/html/iu.test(String(response.headers['content-type'] || ''))) return null;
    const assets = findExternalAssetsWithoutSri(response.body, base);
    if (!assets.length) return null;
    return {
      k: 'external-assets-without-sri',
      sev: 'info',
      title: 'موارد خارجية بلا تحقق SRI',
      desc: 'عُثر على ملفات JavaScript أو CSS خارجية لا تحمل integrity. راجع موثوقية المضيف وإمكانية استخدام Subresource Integrity.',
      ep: '/',
      evidence: assets.slice(0, 10).map(asset => `${asset.tag} ${asset.url}: integrity attribute absent`),
    };
  },

  // Cookies are inspected as response metadata only; cookie values are never included in evidence.
  async cookieSecurity(base) {
    const r = await req(base + '/', {}, 7000);
    if (!r.ok) return null;
    const issues = analyzeCookieSecurity(r.headers, new URL(base).protocol === 'https:');
    if (!issues.length) return null;
    const sessionIssues = issues.filter(issue => /(?:session|sid|auth|token|jwt)/iu.test(issue.name));
    return {
      k: 'cookie-security-attributes',
      sev: sessionIssues.some(issue => issue.missing.includes('Secure') || issue.missing.includes('HttpOnly')) ? 'medium' : 'low',
      title: 'سمات حماية ناقصة في ملفات الارتباط',
      desc: 'رُصدت سمات ناقصة في Set-Cookie. راجع وظيفة كل ملف ارتباط؛ بعض ملفات الارتباط غير الحساسة قد تحتاج JavaScript أو إعدادات مختلفة.',
      ep: '/',
      evidence: issues.slice(0, 10).map(issue => `Cookie "${issue.name}": missing ${issue.missing.join(', ')}`),
    };
  },

  // A harmless cross-origin GET checks whether a credentialed origin is reflected.
  async corsPolicy(base) {
    const probeOrigins = [`https://${crypto.randomUUID()}.reasonix-cors-check.invalid`, 'null'];
    let finding = null;
    for (const probeOrigin of probeOrigins) {
      const r = await req(base + '/', {
        headers: { Origin: probeOrigin },
        omitScanHeaders: true,
      }, 7000);
      if (!r.ok) continue;
      const assessment = analyzeCorsPolicy(r.headers, probeOrigin);
      if (!assessment.riskyReflection) continue;
      finding = { probeOrigin, status: r.status, varyByOrigin: assessment.varyByOrigin };
      break;
    }
    if (!finding) return null;
    return {
      k: 'cors-credentialed-origin-reflection',
      sev: 'medium',
      title: 'سياسة CORS تعكس Origin غير موثوق مع السماح ببيانات الاعتماد',
      desc: 'الخادم أعاد Origin اختباري غير موثوق كما هو مع Access-Control-Allow-Credentials: true. هذه إشارة إعداد خطرة وليست إثباتاً بأن المورد يكشف بيانات حساسة؛ تحقّق من سياسة السماح وقصرها على مصادر موثوقة.',
      ep: '/',
      evidence: [
        `GET / مع Origin غير موثوق (${finding.probeOrigin === 'null' ? 'null' : 'نطاق عشوائي تحت .invalid'}) → HTTP ${finding.status}`,
        'Access-Control-Allow-Origin طابق Origin الاختباري غير الموثوق حرفياً.',
        'Access-Control-Allow-Credentials: true.',
        `Vary: Origin ${finding.varyByOrigin ? 'موجودة' : 'غير موجودة'}؛ هذا لا يعالج قائمة السماح الواسعة.`,
        'أُرسل الطلب دون Cookie أو Authorization مضافين من إعدادات الفحص.',
      ],
    };
  },

  // 4) كشف خادم / إصدارات
  async serverInfo(base) {
    const r = await req(base + '/', {}, 7000);
    if (!r.ok) return null;
    const ev = [];
    const sv = r.headers['server'] || r.headers['x-powered-by'];
    if (sv) {
      ev.push(`HTTP ${r.status} — Server: ${sv}`);
      if (/\d+\.\d+/.test(sv))
        return {
          k: 'server-version', sev: 'low', title: 'كشف إصدار الخادم', ep: 'Server header',
          evidence: [...ev, `الإصدار مكشوف في الترويسة — ${sv}`]
        };
    }
    const gen = r.body.match(/<meta name="generator" content="([^"]+)"/i);
    if (gen) return {
      k: 'server-version', sev: 'info', title: 'كشف تقنية عبر generator meta',
      ep: '/', evidence: [`<meta name="generator" content="${gen[1]}">`, 'GET / → HTTP ' + r.status]
    };
    return null;
  },

  // 5) أنظمة إدارة المحتوى والمنصات
  async platformFingerprint(base) {
    const r = await req(base + '/', {}, 7000);
    if (!r.ok) return null;
    const sig = [
      [/wp-content|wp-includes/i, 'WordPress', '/wp-login.php'],
      [/Joomla!/i, 'Joomla', '/administrator/'],
      [/Drupal/i, 'Drupal', '/user/login'],
      [/Shopify/i, 'Shopify', null],
      [/laravel_session|csrf-token.*Laravel/i, 'Laravel', null],
      [/express/i, 'Express.js', null],
    ];
    for (const [re, name, path] of sig) {
      if (re.test(r.body)) {
        const ev = [`GET / → HTTP ${r.status}`, 'بصمة مطابقة في HTML: ' + (r.body.match(re)?.[0] || '')];
        if (path) {
          const pr = await req(base + path, {}, 6000);
          if (pr.ok) ev.push(`GET ${path} → HTTP ${pr.status} (تأكيد وجود المنصة)`);
        }
        return { k: 'platform-fingerprint', sev: 'info', title: 'بصمة منصة — ' + name, ep: '/', evidence: ev };
      }
    }
    return null;
  },

  // 6) شهادة TLS
  async tlsCert(base) {
    if (!base.startsWith('https')) return null;
    const u = new URL(base);
    const info = await tlsInfo(u.hostname);
    if (!info.ok) return null;
    const leaf = info.chain[0];
    const ev = [`البروتوكول: TLS ${info.proto}`, `التشفير: ${info.cipher}`,
    `المالك: ${leaf.subject}`, `المُصدر: ${leaf.issuer}`, `ينتهي: ${leaf.valid_to}`];
    const days = Math.round((new Date(leaf.valid_to) - Date.now()) / 86400000);
    if (days < 30)
      return { k: 'tls-expiring', sev: 'medium', title: days < 0 ? 'شهادة TLS منتهية الصلاحية' : `شهادة TLS تنتهي قريباً (${days} يوم)`, ep: 'TLS handshake', evidence: ev };
    return { k: 'tls-info', sev: 'info', title: 'شهادة TLS سليمة', ep: 'TLS handshake', evidence: ev };
  },

  // 7) منافذ شائعة مفتوحة
  async openPorts(base) {
    if (!/^https?:/.test(base)) return null;
    const u = new URL(base);
    let ip;
    try { ip = (await lookupTarget(u.hostname))[0].address; } catch { return null; }
    const ev = [`الهدف: ${u.hostname} → ${ip}`];
    const interesting = [[21, 'FTP'], [22, 'SSH'], [23, 'Telnet'], [25, 'SMTP'], [80, 'HTTP'], [443, 'HTTPS'], [3306, 'MySQL'], [3389, 'RDP'], [6379, 'Redis'], [8080, 'HTTP-alt'], [27017, 'MongoDB']];
    const open = [];
    await Promise.all(interesting.map(async ([p, n]) => { if (await portOpen(u.hostname, p)) open.push([p, n]); }));
    open.forEach(([p, n]) => ev.push(`PORT ${p}/tcp OPEN — ${n}`));
    const risky = open.filter(([p]) => ![80, 443].includes(p));
    if (risky.length)
      return { k: 'open-ports', sev: 'medium', title: 'منافذ خدمية مفتوحة — ' + risky.map((r2) => r2[0]).join(', '), ep: `tcp/${ip}`, evidence: ev };
    return open.length ? { k: 'open-ports', sev: 'info', title: 'منافذ مفتوحة (قياسية فقط)', ep: `tcp/${ip}`, evidence: ev } : null;
  },

  // 8) خيارات HTTP مفتوحة (OPTIONS)
  async httpOptions(base) {
    const r = await req(base + '/', { method: 'OPTIONS' }, 6000);
    if (!r.ok || r.status >= 400) return null;
    const allow = r.headers['allow'] || r.headers['public'];
    if (allow && /(PUT|DELETE|TRACE|CONNECT|PATCH)/i.test(allow))
      return {
        k: 'http-methods', sev: 'medium', title: 'طرق HTTP خطيرة مسموحة',
        ep: 'HTTP OPTIONS /', evidence: [`OPTIONS / → HTTP ${r.status}`, `Allow: ${allow}`]
      };
    return null;
  },

  // 9) قوائم الدليل (directory listing)
  async directoryListing(base) {
    const baseline = await soft404Canary(base);
    for (const p of ['/uploads/', '/backup/', '/files/', '/static/', '/assets/']) {
      const r = await req(base + p, {}, 6000);
      if (r.ok && !isSoft404Response(r.body, r.status, baseline, r.url) &&
          /<title>Index of \/|Directory listing for/i.test(r.body))
        return {
          k: 'dir-listing', sev: 'medium', title: 'عرض محتويات دليل مكشوف — ' + p,
          ep: p, evidence: [`GET ${p} → HTTP ${r.status}`, 'استجابة تحتوي: ' + (r.body.match(/<title>[^<]+/i)?.[0] || '')]
        };
    }
    return null;
  },

  // 10) الملفات الشخصية عبر نقاط API شائعة
  async apiExposure(base) {
    const baseline = await soft404Canary(base, { headers: { Accept: 'application/json' } });
    for (const p of ['/swagger.json', '/api-docs', '/actuator/env']) {
      const r = await req(base + p, { headers: { Accept: 'application/json' } }, 6000);
      if (r.ok && r.status === 200 && !isSoft404Response(r.body, r.status, baseline, r.url)) {
        const exposure = apiEndpointExposure(p, r.headers['content-type'], r.body);
        if (exposure) {
          return {
            k: `api-exposed-${p.replace(/[^a-z0-9]+/giu, '-')}`, sev: exposure.severity,
            title: 'نقطة API مؤكدة — ' + p,
            desc: exposure.reason,
            ep: p, evidence: [`GET ${p} → HTTP ${r.status} (${r.headers['content-type'] || 'JSON'})`,
              'تم التحقق من بنية الاستجابة دون نسخ محتواها إلى التقرير.']
          };
        }
      }
    }
    return null;
  },
};

/* ---------------- تشغيل الفحص ---------------- */
const QUICK_SKIPPED_PROBES = new Map([
  ['openPorts', 'تعداد المنافذ مؤجل في النمط السريع.'],
  ['directoryListing', 'فحص الأدلة المتعددة مؤجل في النمط السريع.'],
  ['apiExposure', 'استكشاف مسارات API مؤجل في النمط السريع.'],
  ['subdomainOSINT', 'الاستطلاع السلبي مؤجل في النمط السريع.'],
  ['emailSecurity', 'فحص سجلات البريد مؤجل في النمط السريع.'],
  ['sensitiveFiles', 'فحص المسارات الحساسة مؤجل في النمط السريع.'],
]);

export const PROBE_ACTIVITY = Object.freeze({
  adminPanel: { method: 'GET', scope: 'مسارات الإدارة الشائعة مع canary عشوائي لمقارنة Soft-404' },
  sensitiveFiles: { method: 'GET', scope: 'ملفات إعداد/نسخ احتياطية معروفة ومقارنة canary؛ لا تُحمّل النتائج كاملة' },
  securityHeaders: { method: 'GET', scope: 'ترويسات استجابة الصفحة الرئيسية' },
  subresourceIntegrity: { method: 'GET', scope: 'موارد JavaScript/CSS خارجية دون integrity' },
  cookieSecurity: { method: 'GET', scope: 'سمات Set-Cookie دون تسجيل قيم ملفات الارتباط' },
  corsPolicy: { method: 'GET', scope: 'اختبار انعكاس Origin تجريبي دون بيانات اعتماد' },
  serverInfo: { method: 'GET', scope: 'ترويسات Server/X-Powered-By ووسم generator' },
  platformFingerprint: { method: 'GET', scope: 'مؤشرات تقنية ظاهرة في HTML ومسارات تأكيد عامة' },
  tlsCert: { method: 'TLS handshake', scope: 'شهادة TLS وصلاحيتها' },
  openPorts: { method: 'TCP connect', scope: 'قائمة منافذ محدودة ومعروفة؛ لا يُنفّذ استغلال' },
  httpOptions: { method: 'OPTIONS', scope: 'طرق HTTP المعلنة على الجذر' },
  directoryListing: { method: 'GET', scope: 'أدلة عامة شائعة ومقارنة canary للتحقق من فهرسة المحتويات' },
  apiExposure: { method: 'GET', scope: 'نقاط API ووثائق عامة مع canary يطابق Accept: application/json' },
  subdomainOSINT: { method: 'DNS/CT lookup', scope: 'مصادر استطلاع سلبية عامة' },
  emailSecurity: { method: 'DNS lookup', scope: 'سجلات SPF/DMARC العامة' },
});

export function normalizeScanProfile(value) {
  return ['quick', 'full', 'deep'].includes(value) ? value : 'full';
}

async function baseScan(target, onProgress, requestedProfile = 'full') {
  const profile = normalizeScanProfile(requestedProfile);
  throwIfScanAborted();
  let base = target.trim();
  if (!/^https?:\/\//i.test(base)) {
    /* افتراض http على منافذ غير قياسية (خارج 443) و https على المنفذ القياسي/البدونه */
    const mPort = base.match(/:(\d+)$/);
    const port = mPort ? parseInt(mPort[1], 10) : null;
    base = (port && port !== 443 && port !== 8443 ? 'http://' : 'https://') + base;
  }
  const u = new URL(base);
  const emit = event => { if (onProgress) onProgress({ ...event, at: Date.now() }); };
  emit({ type: 'probe', id: 'target', name: 'تحقق الوصول للهدف', status: 'running' });
  const reachability = await req(`${u.protocol}//${u.host}/`, {}, 12000);
  throwIfScanAborted();
  if (!reachability.ok) throw new Error(currentScanOptions().proxy
    ? `تعذر الوصول عبر البروكسي المحلي (${reachability.error})؛ لم يُجرّب الاتصال المباشر حتى لا يتجاوز إعداد البروكسي.`
    : `الهدف غير قابل للوصول عبر HTTP: ${reachability.error}`);
  emit({ type: 'probe', id: 'target', name: 'تحقق الوصول للهدف', status: 'completed' });
  const t0 = Date.now();
  const accessState = classifyHttpStatus(reachability.status);
  const accessMessages = {
    'authentication-required': 'الهدف يطلب تسجيل الدخول (401). ستُستخدم بيانات المصادقة التي أدخلتها؛ يستمر الفحص دون تخطي ضوابط الوصول.',
    'access-forbidden': 'الهدف رفض الوصول (403). قد تكون الصلاحيات غير كافية أو توجد سياسة وصول؛ لم تتم محاولة تجاوزها ويستمر الفحص ضمن المسموح.',
    'rate-limited': 'الهدف حدّ معدل الطلبات (429). أُعيدت طلبات GET/HEAD الآمنة بعد انتظار Retry-After بحد أقصى، ويستمر الفحص دون تبديل الهوية.',
  };
  const observedStatusCounts = currentScanOptions().observedStatusCounts || { 401: 0, 403: 0, 429: 0 };
  const endpointAccessNote = observedStatusCounts[401] || observedStatusCounts[403]
    ? `ظهرت أثناء المجسات استجابات 401 (${observedStatusCounts[401]}) و403 (${observedStatusCounts[403]})؛ لم تتم محاولة تجاوزها.`
    : '';
  const accessNote = [accessMessages[accessState], endpointAccessNote].filter(Boolean).join(' ');
  if (accessNote) emit({ type: 'access', id: 'target-access', name: 'حالة الوصول', status: accessState, httpStatus: reachability.status, note: accessNote });
  const probeCoverage = [{ id: 'target', name: 'تحقق الوصول للهدف', status: 'completed' }];
  const results = await Promise.all(Object.entries(CHECKS).map(async ([id, fn]) => {
    throwIfScanAborted();
    if (profile === 'quick' && QUICK_SKIPPED_PROBES.has(id)) {
      const reason = QUICK_SKIPPED_PROBES.get(id);
      probeCoverage.push({ id, name: id, status: 'not-run', reason });
      emit({ type: 'probe', id, name: id, status: 'not-run', reason, note: reason });
      return null;
    }
    const activity = PROBE_ACTIVITY[id] || { method: 'HTTP/TLS/DNS probe', scope: 'فحص سلبي محدود' };
    emit({ type: 'probe', id, name: id, status: 'running',
      message: `بدء ${activity.method}: ${activity.scope}` });
    try {
      const finding = await fn(`${u.protocol}//${u.host}`);
      probeCoverage.push({ id, name: id, status: 'completed', finding: Boolean(finding) });
      emit({ type: 'probe', id, name: id, status: 'completed', finding: Boolean(finding),
        ...(finding ? { findingSummary: { title: String(finding.title || id).slice(0, 240), severity: finding.sev || 'info' },
          message: `تم رصد نتيجة تحتاج مراجعة: ${String(finding.title || id).slice(0, 240)}` }
          : { message: 'اكتمل المجس دون رصد نتيجة مطابقة.' }) });
      return finding;
    } catch (error) {
      if (currentScanSignal()?.aborted) throw error;
      probeCoverage.push({ id, name: id, status: 'error', error: error.message });
      emit({ type: 'probe', id, name: id, status: 'error', error: error.message });
      return null;
    }
  }));
  const findings = results.filter(Boolean);
  return {
    target: base, host: u.hostname, live: true,
    elapsed: Date.now() - t0,
    findings, real: true, profile, coverage: {
      probes: probeCoverage,
      access: { status: reachability.status, state: accessState, note: accessNote, observedStatusCounts },
      authenticated: Boolean(Object.keys(currentScanOptions().headers || {}).length),
      credentialsScopedToTargetOrigin: Boolean(currentScanOptions().targetOrigin),
      proxyEnabled: Boolean(currentScanOptions().proxy),
    },
    engine: 'reasonix-live-probe v1.0 (HTTP/TLS/DNS)',
  };
}

/* ---------------- الخادم ---------------- */
function redactSensitiveSource(value) {
  return String(value || '')
    .replace(/AKIA[A-Z0-9]{16}/g, '[REDACTED AWS KEY]')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{30,})\b/g, '[REDACTED TOKEN]')
    .replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, '[REDACTED PRIVATE KEY]')
    .replace(/((?:api[_-]?key|client[_-]?secret|password|token|secret)\s*[=:]\s*["']?)[^"'\s,;]{8,}/ig, '$1[REDACTED]');
}

export async function analyzeUploadedArtifact(buffer, fileName) {
  const files = new Map();
  const artifactTools = [];
  const findings = [];
  let archiveOnlyInventory = false;
  const isZip = buffer.length > 4 && buffer.readUInt32LE(0) === 0x04034b50;
  // MobSF runs as a local Docker service (Docker Engine in WSL/Ubuntu). Keep
  // the uploaded artifact in memory and only send supported mobile/source files.
  const extension = path.extname(fileName).toLowerCase();
  const mobsfEligible = ['.apk', '.aab', '.ipa', '.zip'].includes(extension);
  if (mobsfEligible && process.env.MOBSF_API_KEY) {
    const started = Date.now();
    const base = String(process.env.MOBSF_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');
    const headers = { 'X-Mobsf-Api-Key': process.env.MOBSF_API_KEY };
    const post = async (route, body, contentType) => {
      const response = await fetch(`${base}/api/v1/${route}`, {
        method: 'POST', headers: { ...headers, ...(contentType ? { 'Content-Type': contentType } : {}) },
        body, signal: AbortSignal.timeout(10 * 60 * 1000),
      });
      const text = await response.text();
      let data; try { data = JSON.parse(text); } catch { data = { error: text.slice(0, 1000) }; }
      if (!response.ok) throw new Error(`MobSF ${route} returned HTTP ${response.status}: ${String(data.error || data.message || '').slice(0, 500)}`);
      if (data.error) throw new Error(`MobSF ${route}: ${String(data.error).slice(0, 500)}`);
      return data;
    };
    try {
      const form = new FormData();
      form.append('file', new Blob([buffer]), path.basename(fileName));
      const uploaded = await post('upload', form);
      if (!uploaded.hash) throw new Error('MobSF upload response did not include a file hash.');
      const hash = String(uploaded.hash);
      const encoded = new URLSearchParams({ hash });
      await post('scan', encoded, 'application/x-www-form-urlencoded');
      const report = await post('report_json', new URLSearchParams({ hash }), 'application/x-www-form-urlencoded');
      const score = report.security_score ?? report.appsec?.security_score;
      const mobFindings = [];
      const seen = new Set();
      let visited = 0;
      const collect = value => {
        if (!value || typeof value !== 'object' || visited++ > 10000 || mobFindings.length >= 40) return;
        if (Array.isArray(value)) { for (const item of value) collect(item); return; }
        const severity = String(value.severity || value.level || value.risk || '').toLowerCase();
        const title = value.title || value.name || value.check || value.issue;
        const detail = value.description || value.details || value.message || value.summary;
        if (title && severity && (detail || value.file_name || value.path)) {
          const identity = `${severity}|${title}|${value.file_name || value.path || ''}`;
          if (!seen.has(identity)) {
            seen.add(identity);
            mobFindings.push({ severity, title: String(title).slice(0, 240), detail: String(detail || '').slice(0, 800), file: String(value.file_name || value.path || '').slice(0, 300) });
          }
        }
        for (const child of Object.values(value)) collect(child);
      };
      collect(report);
      for (const item of mobFindings.slice(0, 30)) {
        const sev = /critical|high/i.test(item.severity) ? 'high' : /medium|warning/i.test(item.severity) ? 'medium' : 'low';
        findings.push({ k: 'mobsf', sev, cwe: 'CWE-Unknown', cvss: sev === 'high' ? 7.5 : sev === 'medium' ? 5.3 : 2.0, title: item.title, desc: item.detail || `MobSF severity: ${item.severity}`, evidence: [item.file ? `${item.file}: MobSF finding` : `MobSF severity: ${item.severity}`], fix: ['راجع تفاصيل النتيجة في تقرير MobSF قبل اتخاذ إجراء.'], ep: item.file || fileName, real: true });
      }
      const summary = {
        platform: report.scan_type || report.app_type || 'mobile application',
        security_score: score ?? null,
        findings: mobFindings.length,
        top_findings: mobFindings.slice(0, 20),
        report_sections: Object.keys(report).slice(0, 40),
        report_id: hash,
      };
      artifactTools.push({ id: 'mobsf', name: 'MobSF (Docker · Ubuntu)', category: 'artifact', installed: true, status: 'ok', elapsed: Date.now() - started, output: JSON.stringify(summary).slice(0, 4000) });
      findings.push({ k: 'mobsf-report', sev: 'info', cwe: 'CWE-Unknown', cvss: 0, title: 'اكتمل تحليل MobSF للتطبيق', desc: `اكتمل التحليل الساكن باستخدام MobSF. درجة الأمان: ${score ?? 'غير متاحة'}؛ راجع تقرير الأداة المرفق للتفاصيل.`, evidence: [`MobSF report hash: ${hash}`], fix: ['راجع أقسام تقرير MobSF وقيّم كل نتيجة ضمن سياق التطبيق.'], ep: fileName, real: true });
    } catch (error) {
      artifactTools.push({ id: 'mobsf', name: 'MobSF (Docker · Ubuntu)', category: 'artifact', installed: true, status: error.name === 'TimeoutError' || error.name === 'AbortError' ? 'timeout' : 'error', elapsed: Date.now() - started, output: String(error.message).slice(0, 2000) });
      console.warn('MobSF static analysis failed:', error.message);
    }
  }
  if (isZip) {
    const archiveNames = [];
    const start = Math.max(0, buffer.length - 65_557);
    const eocd = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]), start + 65_535);
    if (eocd < 0) throw new Error('ملف ZIP غير مكتمل أو غير صالح.');
    const count = Math.min(buffer.readUInt16LE(eocd + 10), 5000);
    let offset = buffer.readUInt32LE(eocd + 16), total = 0;
    for (let i = 0; i < count && offset + 46 <= buffer.length; i++) {
      if (buffer.readUInt32LE(offset) !== 0x02014b50) break;
      const method = buffer.readUInt16LE(offset + 10), compressed = buffer.readUInt32LE(offset + 20);
      const nameLen = buffer.readUInt16LE(offset + 28), extraLen = buffer.readUInt16LE(offset + 30), commentLen = buffer.readUInt16LE(offset + 32);
      const localOffset = buffer.readUInt32LE(offset + 42);
      const name = buffer.subarray(offset + 46, offset + 46 + nameLen).toString('utf8').replaceAll('\\', '/');
      if (name && archiveNames.length < 500) archiveNames.push(name.slice(0, 240));
      offset += 46 + nameLen + extraLen + commentLen;
      if (!name || name.startsWith('/') || name.split('/').includes('..') || !(/\.(html?|xml|json|ya?ml|properties|gradle|kt|java|smali|plist|swift|m|h|cjs|mjs|jsx|js|tsx|ts|py|rb|pl|sh|php|cs|go|lock|txt|toml|cfg|ini|env|pem|key|conf|crt)$/i.test(name) || /(^|\/)dockerfile(?:\.[^/]*)?$/i.test(name))) continue;
      if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) continue;
      const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
      if (dataStart + compressed > buffer.length) continue;
      try {
        const data = method === 0 ? buffer.subarray(dataStart, dataStart + compressed) : method === 8 ? inflateRawSync(buffer.subarray(dataStart, dataStart + compressed), { maxOutputLength: 2 * 1024 * 1024 }) : null;
        if (!data) continue;
        if (data.includes(0)) continue;
        total += data.length; if (data.length > 2 * 1024 * 1024 || total > 20 * 1024 * 1024) continue;
        files.set(name, data.toString('utf8'));
      } catch { /* ignore unsupported or oversized archive entries */ }
    }
    if (!files.size && archiveNames.length) {
      archiveOnlyInventory = true;
      files.set('Application package inventory', archiveNames.join('\n'));
    }
  } else {
    const extension = path.extname(fileName).toLowerCase();
    if (['.exe','.dll','.so','.dylib','.bin'].includes(extension)) {
      const ascii = buffer.toString('latin1').match(/[\x20-\x7e]{6,}/g) || [];
      const unicode = buffer.toString('utf16le').match(/[\x20-\x7e]{6,}/g) || [];
      files.set(`Extracted strings: ${fileName}`, [...ascii, ...unicode].slice(0, 50_000).join('\n') + `\nBinary format marker: ${buffer.subarray(0, 2).toString('ascii')}`);
      const r2 = await whichTool('r2');
      if (r2) {
        const tempDir = await fs.mkdtemp(path.join(process.env.TEMP || process.cwd(), 'reasonix-bin-'));
        try {
          const binaryPath = path.join(tempDir, path.basename(fileName)); await fs.writeFile(binaryPath, buffer);
          const result = await execTool(r2, ['-q', '-c', 'iI', binaryPath], { timeout: 120_000 });
          artifactTools.push({ id: 'radare2', name: 'Radare2', category: 'artifact', installed: true, status: result.killed ? 'timeout' : result.error || result.code !== 0 ? 'error' : 'ok', output: (result.stdout || result.stderr || result.error || '').slice(0, 8000) });
        } finally { await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {}); }
      }
    } else {
      if (buffer.includes(0)) throw new Error('هذا النوع الثنائي غير مدعوم حالياً. ارفع APK أو IPA أو ZIP أو EXE/DLL أو ملف شيفرة نصياً.');
      files.set(fileName.split(/[\\/]/).pop(), buffer.toString('utf8'));
    }
  }
  if (/\.apk$/i.test(fileName) && fsSync.existsSync(path.join(TOOLS_DIR, 'mobile-venv', 'Scripts', 'python.exe'))) {
    const tempDir = await fs.mkdtemp(path.join(process.env.TEMP || process.cwd(), 'reasonix-apk-'));
    try {
      const apkPath = path.join(tempDir, 'input.apk'); await fs.writeFile(apkPath, buffer);
      const py = path.join(TOOLS_DIR, 'mobile-venv', 'Scripts', 'python.exe');
      const parser = await execTool(py, ['-c', 'import sys; from androguard.core.apk import APK; a=APK(sys.argv[1]); print(a.get_android_manifest_axml().get_xml())', apkPath], { timeout: 120_000 });
      artifactTools.push({ id: 'androguard', name: 'Androguard', category: 'artifact', installed: true, status: parser.error || parser.code !== 0 ? 'error' : 'ok', output: (parser.stdout || parser.stderr || parser.error || '').slice(0, 8000) });
      if (!parser.error && parser.code === 0 && parser.stdout.trim()) files.set('AndroidManifest.xml (Androguard decoded)', parser.stdout);
      const jadx = await whichTool('jadx');
      if (jadx?.startsWith('JAVA:')) {
        const [java, jar] = jadx.slice(5).split('|'), outDir = path.join(tempDir, 'jadx');
        const result = await execTool(java, ['-jar', jar, '--no-res', '-d', outDir, apkPath], { timeout: 180_000 });
        artifactTools.push({ id: 'jadx', name: 'JADX', category: 'artifact', installed: true, status: result.killed ? 'timeout' : result.error || result.code !== 0 ? 'error' : 'ok', output: (result.stdout || result.stderr || result.error || 'APK decompilation completed.').slice(0, 8000) });
        if (!result.error && result.code === 0) {
          let added = 0;
          const walk = async dir => { for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) await walk(full);
            else if (added < 250 && /\.(java|xml|json|txt|properties)$/i.test(entry.name)) {
              const stat = await fs.stat(full); if (stat.size <= 512 * 1024) { files.set(`JADX: ${path.relative(outDir, full)}`, await fs.readFile(full, 'utf8')); added++; }
            }
          } };
          await walk(outDir);
        }
      }
      const apktool = await whichTool('apktool');
      if (apktool?.startsWith('JAVA:')) {
        const [java, jar] = apktool.slice(5).split('|'), outDir = path.join(tempDir, 'apktool');
        const result = await execTool(java, ['-jar', jar, 'd', '-f', apkPath, '-o', outDir], { timeout: 180_000 });
        artifactTools.push({ id: 'apktool', name: 'Apktool', category: 'artifact', installed: true, status: result.killed ? 'timeout' : result.error || result.code !== 0 ? 'error' : 'ok', output: (result.stdout || result.stderr || result.error || '').slice(0, 8000) });
        if (!result.error && result.code === 0) {
          let added = 0;
          const walk = async dir => { for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) await walk(full);
            else if (added < 200 && /\.(xml|smali|properties|txt)$/i.test(entry.name)) {
              const stat = await fs.stat(full); if (stat.size <= 256 * 1024) { files.set(`Apktool: ${path.relative(outDir, full)}`, await fs.readFile(full, 'utf8')); added++; }
            }
          } };
          await walk(outDir);
        }
      }
      const qark = path.join(TOOLS_DIR, 'mobile-venv', 'Scripts', 'qark.exe');
      if (fsSync.existsSync(qark)) {
        const reportDir = path.join(tempDir, 'qark-report');
        const result = await execTool(qark, ['--apk', apkPath, '--report-type', 'json', '--build-path', reportDir, '--no-exploit-apk'], { timeout: 180_000 });
        artifactTools.push({ id: 'qark', name: 'QARK', category: 'artifact', installed: true, status: result.killed ? 'timeout' : result.error || result.code !== 0 ? 'error' : 'ok', output: (result.stdout || result.stderr || result.error || 'QARK analysis completed.').slice(0, 8000) });
        const output = (result.stdout || result.stderr || '').trim();
        if (output) files.set('QARK static analysis output', output.slice(0, 100_000));
      }
    } catch (error) { console.warn('Androguard manifest decoding failed:', error.message); }
    finally { await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {}); }
  }
  if (archiveOnlyInventory && files.size > 1) { files.delete('Application package inventory'); archiveOnlyInventory = false; }
  if (!files.size) throw new Error('لم أتمكن من قراءة محتوى الملف. ارفع حزمة APK أو AAB أو IPA أو ZIP صالحة، أو ملف شيفرة نصياً.');
  const all = [...files].map(([name, content]) => ({ name, content }));
  const add = (sev, id, title, desc, evidence, file, sourceIndex, matchText) => {
    const source = all.find(entry => entry.name === file)?.content || '';
    const sourceLines = source.split(/\r?\n/);
    const line = source ? source.slice(0, sourceIndex).split(/\r?\n/).length : 0;
    const start = line ? Math.max(0, line - 3) : 0;
    const sourceCode = line ? redactSensitiveSource(sourceLines.slice(start, Math.min(sourceLines.length, line + 2)).join('\n').slice(0, 4000)) : '';
    let correctedMatch = '';
    if (id === 'android-backup') correctedMatch = matchText.replace(/(android:allowBackup\s*=\s*)"true"/i, '$1"false"');
    else if (id === 'android-debuggable') correctedMatch = matchText.replace(/(android:debuggable\s*=\s*)"true"/i, '$1"false"');
    else if (id === 'cleartext-traffic') correctedMatch = /android:usesCleartextTraffic/i.test(matchText)
      ? matchText.replace(/(android:usesCleartextTraffic\s*=\s*)"true"/i, '$1"false"')
      : matchText.replace(/<true\s*\/?>/i, '<false/>');
    const fixedCode = correctedMatch && correctedMatch !== matchText ? sourceCode.replace(matchText, correctedMatch).slice(0, 4000) : '';
    findings.push({
      k: id, sev, cwe: id === 'embedded-secret' ? 'CWE-798' : 'CWE-16',
      cvss: sev === 'high' ? 7.5 : sev === 'medium' ? 5.3 : 2.0, title, desc,
      evidence: [`${file}:${line || '?'}: ${id === 'embedded-secret' ? '[secret redacted]' : redactSensitiveSource(evidence.slice(0, 800))}`],
      fix: ['راجع السياق يدوياً، وأزل الإعداد غير الآمن أو السر من التطبيق ثم أعد البناء.'],
      ep: file, file, line, sourceCode, fixedCode, real: true
    });
  };
  const patterns = [
    { re: /(android:allowBackup\s*=\s*"true")/ig, sev: 'medium', id: 'android-backup', title: 'Android backup is enabled', desc: 'قد تسمح النسخ الاحتياطية باستخراج بيانات التطبيق على أجهزة أو نسخ احتياطية غير موثوقة.' },
    { re: /(android:usesCleartextTraffic\s*=\s*"true"|NSAllowsArbitraryLoads\s*<\/key>\s*<true\s*\/?>)/ig, sev: 'high', id: 'cleartext-traffic', title: 'Unencrypted network traffic is allowed', desc: 'إعداد يسمح باتصالات غير مشفرة ويعرض البيانات للاعتراض.' },
    { re: /(setJavaScriptEnabled\s*\(\s*true\s*\)|javaScriptEnabled\s*:\s*true)/ig, sev: 'medium', id: 'webview-javascript', title: 'WebView JavaScript enabled', desc: 'تفعيل JavaScript في WebView يحتاج مراجعة مصادر المحتوى والجسور الأصلية.' },
    { re: /(android:exported\s*=\s*"true")/ig, sev: 'medium', id: 'exported-component', title: 'Exported Android component', desc: 'مكوّن معلن للتطبيقات الأخرى؛ تحقق من وجود صلاحيات وحماية مناسبة.' },
    { re: /(android:debuggable\s*=\s*"true")/ig, sev: 'high', id: 'android-debuggable', title: 'Android app is debuggable', desc: 'نسخة التطبيق تسمح بالتصحيح؛ تحقق من أن هذا الإعداد غير موجود في إصدار الإنتاج.' },
    { re: /(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|URLDownloadToFileA?)/ig, sev: 'info', id: 'desktop-api-indicator', title: 'Sensitive desktop API string found', desc: 'ظهرت سلسلة مرتبطة بواجهة Windows حساسة داخل الملف. قد تستخدمها تطبيقات مشروعة؛ لا يكفي ذلك لإثبات سلوك ضار.' },
    { re: /(AKIA[0-9A-Z]{16}|(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{30,})|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:api[_-]?key|client[_-]?secret|password|access[_-]?token|auth[_-]?token|secret)\s*[=:]\s*["'][^"'\s]{20,}["'])/ig, sev: 'high', id: 'embedded-secret', title: 'Possible embedded credential or private key', desc: 'عُثر على نص يشبه سراً ثابتاً داخل الحزمة. قد تكون نتيجة موجبة كاذبة؛ دوّر السر إذا تأكد.' },
    { re: /(implementation\s+['"][^'"]+:[^'"]+:[0-9][^'"]*['"]|"(?:name|version)"\s*:\s*"[^\"]+"|<dependency>)/ig, sev: 'info', id: 'dependency-manifest', title: 'Dependency manifest found', desc: 'تم العثور على بيان اعتماديات. يلزم Dependency-Check أو قاعدة ثغرات محدثة لفحص CVE؛ هذا التحليل لا يدعي ذلك.' },
  ];
  const candidates = all.filter(({ name }) => (
    /\.(java|kt|swift|m|h|cjs|mjs|jsx?|tsx?|py|rb|pl|sh|php|cs|go|tf|ya?ml|toml|gradle|json|properties|xml|plist)$/i.test(name.replace(/^JADX:\s*/i, '')) ||
    /(^|\/)dockerfile(?:\.[^/]*)?$/i.test(name)
  ) && !/^(QARK|Extracted strings):/i.test(name));
  for (const entry of all.filter(({ name }) => /\.html?$/i.test(name))) {
    let scriptIndex = 0;
    for (const match of entry.content.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
      const attributes = match[1] || '', code = match[2] || '';
      if (/\bsrc\s*=/i.test(attributes) || !code.trim()) continue;
      const type = attributes.match(/\btype\s*=\s*["']?([^"'\s>]+)/i)?.[1];
      if (type && !/^(?:module|(?:text|application)\/(?:java|ecma)script)$/i.test(type)) continue;
      const codeOffset = match.index + match[0].indexOf(code);
      const startLine = entry.content.slice(0, codeOffset).split(/\r?\n/).length;
      candidates.push({
        name: `${entry.name}.inline-${++scriptIndex}.js`,
        sourceName: entry.name,
        content: `${'\n'.repeat(Math.max(0, startLine - 1))}${code}`
      });
    }
  }
  const infrastructureCandidates = candidates.filter(({ name, content }) => (
    /\.(?:tf|ya?ml|dockerfile)$/i.test(name) || /(^|\/)dockerfile(?:\.[^/]*)?$/i.test(name) ||
    (/\.json$/i.test(name) && /"(?:AWSTemplateFormatVersion|Resources|terraform|apiVersion|kind)"\s*:/i.test(content))
  ));
  const secretCandidates = all.filter(({ name }) => /(^|\/)(?:\.env(?:\.[^/]*)?|[^/]+\.(?:pem|key|p12|pfx|crt|cer|conf|ini|cfg|properties|lock))$/i.test(name));
  const htmlCandidates = all.filter(({ name }) => /\.html?$/i.test(name));
  const scanCandidates = [...new Map([...candidates, ...secretCandidates, ...htmlCandidates].map(entry => [entry.name, entry])).values()];
  const redactLikelySecrets = redactSensitiveSource;
  if (scanCandidates.length) {
    const root = await fs.mkdtemp(path.join(process.env.TEMP || process.cwd(), 'reasonix-src-'));
    try {
      const safeWorkspacePath = value => {
        const raw = String(value || '');
        const relative = path.relative(root, path.resolve(root, raw));
        return relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)
          ? relative.replaceAll(path.sep, '/') : path.basename(raw.replaceAll('\\', '/')) || 'source';
      };
      for (const entry of scanCandidates.slice(0, 500)) {
        const rel = entry.name.replace(/^JADX:\s*/i, '').replaceAll('\\', '/');
        if (!rel || rel.startsWith('/') || rel.includes(':') || rel.split('/').includes('..')) continue;
        const dest = path.resolve(root, ...rel.split('/'));
        if (!dest.startsWith(root + path.sep)) continue;
        await fs.mkdir(path.dirname(dest), { recursive: true }); await fs.writeFile(dest, entry.content, 'utf8');
      }
      const run = async (id, name, bin, args, timeout = 120_000, options = {}) => {
        const started = Date.now(); let command = await whichTool(bin), actualArgs = args;
        if (!command) {
          artifactTools.push({ id, name, category: 'repository', installed: false, status: 'not-installed',
            output: `سبب عدم الفحص: الأداة ${bin} غير مثبتة.` });
          return null;
        }
        if (command.startsWith('NODE:')) { actualArgs = [command.slice(5), ...args]; command = process.execPath; }
        const result = await execTool(command, actualArgs, { timeout, cwd: root });
        const status = result.killed ? 'timeout' : result.error || result.code !== 0 ? 'error' : 'ok';
        const tool = { id, name, category: 'repository', installed: true, status, elapsed: Date.now() - started,
          command: displayCommand(name, args),
          output: (result.stdout || result.stderr || result.error || (status === 'ok' ? '(no output)' : `Exit code: ${result.code}`)).slice(0, 10_000) };
        if (options.reportPath) {
          try {
            const reportStat = await fs.stat(options.reportPath);
            if (reportStat.size > 5 * 1024 * 1024) throw new Error('Report exceeded the 5 MB parsing limit.');
            tool.report = await fs.readFile(options.reportPath, 'utf8');
          }
          catch (error) {
            if (status === 'ok') tool.status = 'error';
            tool.output = `تعذر قراءة تقرير الأداة: ${String(error.message || error).slice(0, 500)}`;
          }
        }
        artifactTools.push(tool);
        return result;
      };
      if (candidates.some(({ name }) => /\.(java|kt|swift|m|h|cjs|mjs|jsx?|tsx?|py|rb|pl|sh|php|cs|go|xml)$/i.test(name))) {
        const semgrepStart = Date.now(), semgrepPath = await whichTool('semgrep');
        const patterns = [
          { id: 'reasonix.javascript.dynamic-eval', pattern: 'eval(...)', lang: 'js', include: ['*.js','*.jsx','*.ts','*.tsx','.mjs'] },
          { id: 'reasonix.javascript.disabled-tls', pattern: 'rejectUnauthorized: false', lang: 'js', include: ['*.js','*.jsx','*.ts','*.tsx','.mjs'] },
          { id: 'reasonix.python.dynamic-eval', pattern: 'eval(...)', lang: 'python', include: ['*.py'] },
          { id: 'reasonix.python.disabled-tls', pattern: 'requests.$METHOD(..., verify=False, ...)', lang: 'python', include: ['*.py'] },
          { id: 'reasonix.android.debuggable', pattern: 'android:debuggable="true"', lang: 'xml', include: ['*.xml'] },
        ];
        const applicablePatterns = patterns.filter(rule => candidates.some(({ name }) => rule.include.some(glob => glob.startsWith('.') ? name.toLowerCase().endsWith(glob) : name.toLowerCase().endsWith(glob.slice(1)) || name.toLowerCase().endsWith(glob))));
        if (!applicablePatterns.length) {
          artifactTools.push({ id: 'semgrep', name: 'Semgrep', category: 'repository', installed: Boolean(semgrepPath), status: 'not-applicable',
            output: 'سبب عدم الفحص: لا توجد قاعدة محلية مناسبة للغات ملفات المصدر المرفوعة.' });
        } else if (process.platform === 'win32') {
          const localRules = [
            { id: 'reasonix.javascript.dynamic-eval', files: /\.(?:jsx?|tsx?|mjs)$/i, pattern: /(?<!["'`])\beval\s*\(/g },
            { id: 'reasonix.python.dynamic-eval', files: /\.py$/i, pattern: /(?<!["'`])\beval\s*\(/g },
            { id: 'reasonix.javascript.disabled-tls', files: /\.(?:jsx?|tsx?|mjs)$/i, pattern: /(?<!["'`])\brejectUnauthorized\s*:\s*false\b/gi },
            { id: 'reasonix.python.disabled-tls', files: /\.py$/i, pattern: /(?<!["'`])\brequests\s*\.\s*[A-Za-z_]\w*\s*\([^)]*\bverify\s*=\s*False\b[^)]*\)/gi },
            { id: 'reasonix.android.debuggable', files: /\.xml$/i, pattern: /(?<!["'`])\bandroid:debuggable\s*=\s*["']true["']/gi },
          ];
          for (const rule of localRules.filter(item => applicablePatterns.some(applicable => applicable.id === item.id))) {
            for (const entry of candidates.filter(item => rule.files.test(item.name))) {
              for (const match of entry.content.matchAll(new RegExp(rule.pattern.source, rule.pattern.flags))) {
                if (findings.length >= 100) break;
                const line = entry.content.slice(0, match.index).split(/\r?\n/).length;
                const lines = entry.content.split(/\r?\n/);
                const sourceCode = redactLikelySecrets(lines.slice(Math.max(0, line - 3), line + 2).join('\n').slice(0, 4000));
                const safePath = entry.name.replace(/^JADX:\s*/i, '').replaceAll('\\', '/');
                const displayPath = entry.sourceName || safePath;
                const dynamicEval = rule.id.includes('dynamic-eval');
                const fixedCode = dynamicEval ? '' : sourceCode
                  .replace(/(rejectUnauthorized\s*:\s*)false\b/gi, '$1true')
                  .replace(/(verify\s*=\s*)False\b/g, '$1True');
                findings.push({
                  k: rule.id, sev: dynamicEval ? 'high' : 'medium',
                  cwe: dynamicEval ? 'CWE-95' : 'CWE-295', cvss: dynamicEval ? 7.8 : 5.3,
                  title: dynamicEval ? 'Dynamic evaluation of input' : 'TLS certificate verification is disabled',
                  desc: dynamicEval ? 'A local source pattern found the eval function. Validate and parse input rather than evaluating it as code.'
                    : 'A local source pattern found TLS certificate verification disabled.',
                  evidence: [`${displayPath}:${line}: ${sourceCode.slice(0, 400)}`],
                  fix: dynamicEval ? ['تجنب eval واستخدم محللاً أو قائمة سماح للعمليات والقيم المقبولة.']
                    : ['فعّل التحقق من شهادات TLS واستخدم مخزن الشهادات الموثوق.'],
                  ep: displayPath, file: displayPath, line, sourceCode, fixedCode, real: true
                });
              }
            }
          }
          artifactTools.push({
            id: 'semgrep', name: 'Semgrep', category: 'repository', installed: Boolean(semgrepPath),
            status: semgrepPath ? 'disabled' : 'not-installed',
            output: semgrepPath
              ? 'سبب عدم تشغيل Semgrep: غلاف Windows يترك عمليات فرعية تعمل بعد مهلة الفحص المعزول؛ عُطّل لمنع عمليات يتيمة. نُفذت قواعد محلية محدودة لـ eval وتعطيل TLS وAndroid debuggable دون تشغيل Semgrep.'
              : 'سبب عدم الفحص: Semgrep غير مثبتة. نُفذت قواعد محلية محدودة لـ eval وتعطيل TLS وAndroid debuggable.'
          });
        } else if (!semgrepPath) artifactTools.push({ id: 'semgrep', name: 'Semgrep', category: 'repository', installed: false, status: 'not-installed', output: 'سبب عدم الفحص: Semgrep غير مثبتة.' });
        else {
          const semgrepStatus = [];
          for (const rule of applicablePatterns) {
            const started = Date.now();
            const include = rule.include.flatMap(glob => ['--include', glob]);
            const args = ['scan', '--pattern', rule.pattern, '--lang', rule.lang, '--json', '--metrics', 'off', '--quiet',
              '--jobs', '1', '--timeout', '5', '--timeout-threshold', '1', '--max-memory', '512', '--max-target-bytes', '500000',
              '--no-git-ignore', ...include, '.'];
            const execution = semgrepPath.startsWith('NODE:')
              ? await execTool(process.execPath, [semgrepPath.slice(5), ...args], { timeout: 20_000, cwd: root })
              : await execTool(semgrepPath, args, { timeout: 20_000, cwd: root });
            const status = execution.killed ? 'timeout' : execution.error || execution.code !== 0 ? 'error' : 'ok';
            semgrepStatus.push({ status, elapsed: Date.now() - started, code: execution.code, error: execution.error || '' });
            if (status !== 'ok') continue;
            try {
              const text = execution.stdout || '';
              const reportStart = text.indexOf('{"version"');
              const report = JSON.parse(reportStart >= 0 ? text.slice(reportStart) : text);
              if (!Array.isArray(report?.results)) throw new Error('Semgrep JSON did not contain a results array.');
              for (const f of report.results.slice(0, 40)) {
                const relative = path.relative(root, path.resolve(root, String(f.path || ''))).replaceAll(path.sep, '/');
                const safePath = relative && !relative.startsWith('../') ? relative : path.basename(String(f.path || 'source'));
                const source = candidates.find(entry => entry.name.replace(/^JADX:\s*/i, '').replaceAll('\\', '/') === safePath);
                const displayPath = source?.sourceName || safePath;
                const sourceLines = source?.content.split(/\r?\n/) || [];
                const line = Number.isInteger(f.start?.line) ? f.start.line : 0;
                const sourceCode = redactLikelySecrets(line ? sourceLines.slice(Math.max(0, line - 3), line + 2).join('\n').slice(0, 4000) : String(f.extra?.lines || '').slice(0, 4000));
                let fixedCode = typeof f.extra?.fix === 'string' ? redactLikelySecrets(f.extra.fix.slice(0, 4000)) : '';
                if (!fixedCode && /disabled-tls/.test(rule.id)) {
                  fixedCode = sourceCode.replace(/(verify\s*=\s*)False\b/i, '$1True').replace(/(rejectUnauthorized\s*:\s*)false\b/i, '$1true');
                  if (fixedCode === sourceCode) fixedCode = '';
                }
                findings.push({
                  k: rule.id, sev: /dynamic-eval/.test(rule.id) ? 'high' : 'medium',
                  cwe: /dynamic-eval/.test(rule.id) ? 'CWE-95' : 'CWE-295', cvss: /dynamic-eval/.test(rule.id) ? 7.8 : 5.3,
                  title: String(f.extra?.message || rule.id).slice(0, 240),
                  desc: String(f.extra?.message || 'Semgrep static analysis finding.').slice(0, 1000),
                  evidence: [`${displayPath}:${f.start?.line || 1}: ${sourceCode.slice(0, 400)}`],
                  fix: ['راجع السياق والنتيجة قبل اعتماد الإصلاح المقترح.'], ep: displayPath, file: displayPath,
                  line, sourceCode, fixedCode, real: true
                });
              }
            } catch (error) {
              semgrepStatus[semgrepStatus.length - 1].status = 'error';
              const failed = artifactTools.find(tool => tool.id === 'semgrep');
              if (failed) failed.output = `تعذر تحليل تقرير Semgrep: ${String(error.message || error).slice(0, 500)}`;
            }
            if (Date.now() - started > 20_000) semgrepStatus[semgrepStatus.length - 1].status = 'timeout';
          }
          if (!artifactTools.some(tool => tool.id === 'semgrep')) {
            const status = semgrepStatus.some(item => item.status === 'timeout') ? 'timeout' : semgrepStatus.some(item => item.status === 'error') ? 'error' : 'ok';
            artifactTools.push({ id: 'semgrep', name: 'Semgrep', category: 'repository', installed: true, status,
              elapsed: Date.now() - semgrepStart, command: 'Semgrep local inline rules (bounded, no metrics)',
              output: status === 'ok' ? `Semgrep completed locally with ${applicablePatterns.length} bounded rule(s). Source code was not uploaded.`
                : `Semgrep did not complete every local rule: ${semgrepStatus.map(item => `${item.status} (${item.elapsed} ms, exit ${item.code}${item.error ? `: ${item.error.slice(0, 200)}` : ''})`).join('; ')}.` });
          }
        }
      }
      if (candidates.some(({ name }) => /\.(java|kt|swift|m|h|cjs|mjs|jsx?|tsx?|py|rb|pl|sh|php|cs|go)$/i.test(name))) {
        if (candidates.some(({ name }) => /\.py$/i.test(name))) {
          const bandit = await run('bandit', 'Bandit', 'bandit', ['-r', root, '-f', 'json', '-q']);
          try {
            if (bandit && artifactTools.at(-1)?.status === 'ok') {
            const report = JSON.parse(bandit.stdout || 'null');
            if (!Array.isArray(report?.results)) throw new Error('Bandit JSON did not contain a results array.');
            for (const f of report.results.slice(0, 40)) {
              const relative = path.relative(root, path.resolve(root, String(f.filename || ''))).replaceAll(path.sep, '/');
              const safePath = relative && !relative.startsWith('../') ? relative : path.basename(String(f.filename || 'source'));
              const sourceCode = redactLikelySecrets(String(f.code || '').slice(0, 4000));
              findings.push({
                k: 'bandit', sev: /high/i.test(f.issue_severity) ? 'high' : /medium/i.test(f.issue_severity) ? 'medium' : 'low',
                cwe: 'CWE-Unknown', cvss: 5.3, title: String(f.test_name || 'Bandit finding').slice(0, 240),
                desc: String(f.issue_text || '').slice(0, 1000), evidence: [`${safePath}:${f.line_number}: ${sourceCode.slice(0, 400)}`],
                fix: ['راجع نتيجة Bandit والسياق المحيط بها.'], ep: safePath, file: safePath,
                line: Number.isInteger(f.line_number) ? f.line_number : 0, sourceCode, fixedCode: '', real: true
              });
            }
            const banditTool = artifactTools.find(item => item.id === 'bandit');
            if (banditTool?.status === 'ok') banditTool.output = 'Bandit completed locally. Source code was not uploaded.';
            }
          } catch (error) {
            const tool = artifactTools.find(item => item.id === 'bandit');
            if (tool) { tool.status = 'error'; tool.output = `تعذر تحليل تقرير Bandit: ${String(error.message || error).slice(0, 500)}`; }
          }
        }
        if (candidates.some(({ name }) => /\.(cjs|mjs|jsx?|tsx?|json)$/i.test(name))) await run('retirejs', 'Retire.js', 'retire', ['--path', root, '--outputformat', 'json']);
      }
      const hasNpmManifest = candidates.some(({ name }) => /(^|\/)package\.json$/i.test(name.replaceAll('\\', '/')));
      const hasNpmLock = scanCandidates.some(({ name }) => /(^|\/)(?:package-lock|npm-shrinkwrap)\.json$/i.test(name.replaceAll('\\', '/')));
      if (hasNpmManifest && hasNpmLock) {
        const started = Date.now(), npmCommand = await whichTool('npm');
        if (!npmCommand) artifactTools.push({ id: 'npm-audit', name: 'npm audit (offline)', category: 'repository', installed: false, status: 'not-installed',
          output: 'سبب عدم الفحص: npm غير مثبتة.' });
        else {
          const windows = process.platform === 'win32';
          const command = windows ? (process.env.ComSpec || 'cmd.exe') : npmCommand;
          const args = windows ? ['/d', '/s', '/c', 'npm audit --offline --json --ignore-scripts']
            : ['audit', '--offline', '--json', '--ignore-scripts'];
          const result = await execTool(command, args, { timeout: 90_000, cwd: root });
          const tool = { id: 'npm-audit', name: 'npm audit (offline)', category: 'repository', installed: true,
            status: result.killed ? 'timeout' : result.code === 0 || result.code === 1 ? 'ok' : 'error', elapsed: Date.now() - started,
            command: 'npm audit --offline --json --ignore-scripts',
            output: '' };
          if (tool.status === 'ok') {
            try {
              const report = JSON.parse(result.stdout || 'null');
              if (!Number.isInteger(report?.auditReportVersion) || !report?.metadata?.vulnerabilities || typeof report.vulnerabilities !== 'object') {
                throw new Error(report?.error?.summary || report?.error?.detail || 'npm audit did not return a complete audit report.');
              }
              const advisories = Object.values(report.vulnerabilities).slice(0, 100);
              for (const advisory of advisories) {
                const severity = String(advisory.severity || '').toLowerCase();
                const sev = severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : severity === 'moderate' ? 'medium' : 'low';
                const via = (Array.isArray(advisory.via) ? advisory.via : []).filter(item => item && typeof item === 'object');
                const details = via.map(item => [item.title, item.url].filter(Boolean).join(' — ')).filter(Boolean).slice(0, 5);
                const fixAvailable = advisory.fixAvailable === true ? 'A compatible update is available.'
                  : advisory.fixAvailable && typeof advisory.fixAvailable === 'object' ? `A fix is available in ${String(advisory.fixAvailable.name || advisory.name)}@${String(advisory.fixAvailable.version || 'a compatible version')}.`
                    : 'No compatible automatic fix was reported.';
                findings.push({
                  k: 'npm-audit', sev, cwe: 'CWE-Unknown',
                  cvss: Math.max(0, ...via.map(item => Number(item.cvss?.score) || 0)),
                  title: `Vulnerable dependency: ${String(advisory.name || 'unknown package').slice(0, 180)}`,
                  desc: details.join('; ').slice(0, 1000) || `npm reported ${severity || 'an unspecified severity'} in this dependency.`,
                  evidence: [`package-lock.json: ${String(advisory.name || 'unknown package')} ${String(advisory.range || '')}`.trim()],
                  fix: [fixAvailable], ep: 'package-lock.json', file: 'package-lock.json', line: 0, sourceCode: '', fixedCode: '', real: true
                });
              }
              const counts = report.metadata.vulnerabilities;
              const advisoryCount = Object.values(counts).reduce((sum, count) => sum + Number(count || 0), 0);
              const affectedPackages = Object.keys(report.vulnerabilities).length;
              const dependencies = Number(report.metadata.dependencies?.total);
              tool.output = `npm audit completed offline; ${advisoryCount} advisory(ies) in ${affectedPackages} vulnerable package(s)${Number.isFinite(dependencies) ? ` among ${dependencies} dependencies` : ''}. Network access and lifecycle scripts were disabled.`;
            } catch (error) {
              tool.status = /ENOAUDIT|offline|cache/i.test(String(error.message)) ? 'blocked' : 'error';
              tool.output = `تعذر إكمال npm audit دون اتصال: ${String(error.message || error).slice(0, 600)}`;
            }
          } else {
            tool.output = `تعذر تشغيل npm audit دون اتصال: ${String(result.error || result.stderr || `exit code ${result.code}`).slice(0, 600)}`;
          }
          artifactTools.push(tool);
        }
      } else {
        artifactTools.push({ id: 'npm-audit', name: 'npm audit (offline)', category: 'repository', status: 'not-applicable',
          output: 'سبب عدم الفحص: يلزم وجود package.json مع package-lock.json أو npm-shrinkwrap.json.' });
      }
      if (scanCandidates.length) {
        const reportDir = await fs.mkdtemp(path.join(process.env.TEMP || process.cwd(), 'reasonix-gitleaks-'));
        const gitleaksReport = path.join(reportDir, 'report.json');
        try {
          const gitleaks = await run('gitleaks', 'Gitleaks', 'gitleaks',
            ['detect', '--source', root, '--no-git', '--report-format', 'json', '--report-path', gitleaksReport, '--redact', '--exit-code', '0'],
            90_000, { reportPath: gitleaksReport });
          const gitleaksTool = artifactTools.find(item => item.id === 'gitleaks');
          if (gitleaks && gitleaksTool?.status === 'ok') {
            try {
              const leaks = JSON.parse(gitleaksTool.report || '[]');
              for (const leak of (Array.isArray(leaks) ? leaks : []).slice(0, 40)) {
                const safePath = safeWorkspacePath(leak.File);
                const sourceEntry = candidates.find(entry => entry.name.replaceAll('\\', '/') === safePath || entry.name.endsWith('/' + safePath)) ||
                  all.find(entry => entry.name.replaceAll('\\', '/') === safePath || entry.name.endsWith('/' + safePath));
                const displayPath = sourceEntry?.sourceName || safePath;
                const source = sourceEntry?.content || '';
                const line = Number.isInteger(leak.StartLine) ? leak.StartLine : 0;
                const safeSource = line ? source.split(/\r?\n/).slice(Math.max(0, line - 3), line + 2)
                  .map(text => String(leak.Secret || '') ? text.replace(String(leak.Secret), '[REDACTED]') : text)
                  .map(redactLikelySecrets).join('\n').slice(0, 4000) : '';
                findings.push({
                  k: 'gitleaks', sev: 'high', cwe: 'CWE-798', cvss: 7.5,
                  title: `Possible secret detected (${String(leak.RuleID || 'rule').slice(0, 100)})`,
                  desc: 'A local secret-scanning rule matched this file. The detected secret value is intentionally redacted.',
                  evidence: [`${displayPath || 'source'}:${line || '?'}: ${String(leak.RuleID || 'secret rule')} [secret redacted]`],
                  fix: ['تعامل مع القيمة على أنها مكشوفة، ودوّر بيانات الاعتماد بعد التحقق منها. أزل السر من السجل ومصدر الشيفرة.'],
                  ep: displayPath || 'source', file: displayPath || 'source', line, sourceCode: safeSource, fixedCode: '', real: true
                });
              }
              gitleaksTool.output = `Gitleaks completed locally; ${Array.isArray(leaks) ? leaks.length : 0} finding(s). Secret values redacted.`;
            } catch (error) {
              gitleaksTool.status = 'error';
              gitleaksTool.output = `تعذر تحليل تقرير Gitleaks: ${String(error.message || error).slice(0, 500)}`;
            }
          }
          if (gitleaksTool) delete gitleaksTool.report;
        } finally { await fs.rm(reportDir, { recursive: true, force: true }); }
      }
      if (infrastructureCandidates.length) {
        const reportDir = await fs.mkdtemp(path.join(process.env.TEMP || process.cwd(), 'reasonix-trivy-'));
        const trivyReport = path.join(reportDir, 'report.json');
        let trivy;
        try {
          trivy = await run('trivy', 'Trivy misconfiguration scan', 'trivy',
            ['fs', '--scanners', 'misconfig', '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--quiet', '--format', 'json', '--output', trivyReport, '--exit-code', '0', root],
            120_000, { reportPath: trivyReport });
        } finally { await fs.rm(reportDir, { recursive: true, force: true }); }
        const trivyTool = artifactTools.find(item => item.id === 'trivy');
        if (trivy && trivyTool?.status === 'ok') {
          try {
            const report = JSON.parse(trivyTool.report || '{}');
            for (const result of (report.Results || []).slice(0, 20)) for (const item of (result.Misconfigurations || []).slice(0, 40)) {
              const safePath = safeWorkspacePath(result.Target);
              const line = Number.isInteger(item.CauseMetadata?.StartLine) ? item.CauseMetadata.StartLine : 0;
              const lines = Array.isArray(item.CauseMetadata?.Code?.Lines) ? item.CauseMetadata.Code.Lines : [];
              const sourceCode = lines.map(sourceLine => String(sourceLine.Content || '')).join('\n').slice(0, 4000);
              const sev = /critical|high/i.test(item.Severity) ? 'high' : /medium/i.test(item.Severity) ? 'medium' : 'low';
              findings.push({
                k: 'trivy', sev, cwe: 'CWE-16', cvss: sev === 'high' ? 7.5 : sev === 'medium' ? 5.3 : 2.0,
                title: String(item.Title || item.ID || 'Trivy misconfiguration').slice(0, 240),
                desc: String(item.Message || item.Description || '').slice(0, 1000),
                evidence: [`${safePath || result.Target || 'source'}:${line || '?'}: ${String(item.ID || 'misconfiguration')}`],
                fix: [String(item.Resolution || 'Review and remediate the configuration in context.').slice(0, 1000)],
                ep: safePath || 'source', file: safePath || 'source', line, sourceCode, fixedCode: '', real: true
              });
            }
            delete trivyTool.report;
            trivyTool.output = 'Trivy completed an offline local misconfiguration scan. No source was uploaded.';
          } catch (error) {
            trivyTool.status = 'error';
            trivyTool.output = `تعذر تحليل تقرير Trivy: ${String(error.message || error).slice(0, 500)}`;
            delete trivyTool.report;
          }
        } else if (trivyTool) delete trivyTool.report;
      }
      if (infrastructureCandidates.length) {
        const started = Date.now(), py = path.join(TOOLS_DIR, 'mobile-venv', 'Scripts', 'python.exe');
        if (fsSync.existsSync(py)) {
          const r = await execTool(py, ['-m', 'checkov.main', '--directory', root, '--output', 'json', '--quiet'], { timeout: 180_000, cwd: root });
          const checkovTool = { id: 'checkov', name: 'Checkov', category: 'repository', installed: true,
            status: r.killed ? 'timeout' : r.error || r.code !== 0 ? 'error' : 'ok', elapsed: Date.now() - started,
            command: 'Checkov --directory [uploaded project] --output json', output: '' };
          if (checkovTool.status === 'ok') {
            try {
              const report = JSON.parse(r.stdout || 'null');
              const checks = report?.results?.failed_checks;
              if (!Array.isArray(checks)) throw new Error('Checkov JSON did not contain failed_checks.');
              for (const check of checks.slice(0, 40)) {
                const file = safeWorkspacePath(check.file_path);
                const line = Number.isInteger(check.file_line_range?.[0]) ? check.file_line_range[0] : 0;
                const sourceCode = redactLikelySecrets((check.code_block || []).map(row => Array.isArray(row) ? String(row[1] || '') : String(row || '')).join('\n').slice(0, 4000));
                findings.push({
                  k: `checkov.${String(check.check_id || 'finding').replace(/[^a-z0-9._-]/gi, '_').slice(0, 80)}`,
                  sev: /critical|high/i.test(String(check.severity || '')) ? 'high' : /medium/i.test(String(check.severity || '')) ? 'medium' : 'low',
                  cwe: 'CWE-16', cvss: 5.3, title: String(check.check_name || check.check_id || 'Checkov finding').slice(0, 240),
                  desc: String(check.guideline || check.resource || '').slice(0, 1000),
                  evidence: [`${file || 'source'}:${line || '?'}: ${String(check.check_id || 'configuration check')}`],
                  fix: ['راجع إرشادات Checkov وتأكد من أثر التغيير قبل تعديل إعدادات البنية التحتية.'],
                  ep: file || 'source', file: file || 'source', line, sourceCode, fixedCode: '', real: true
                });
              }
              checkovTool.output = `Checkov completed locally; ${checks.length} failed check(s). Source code was not uploaded.`;
            } catch (error) {
              checkovTool.status = 'error';
              checkovTool.output = `تعذر تحليل تقرير Checkov: ${String(error.message || error).slice(0, 500)}`;
            }
          } else checkovTool.output = `سبب تعذر الفحص: ${String(r.error || r.stderr || `exit code ${r.code}`).slice(0, 1000)}`;
          artifactTools.push(checkovTool);
        }
      }
      const skippedForInput = [
        ['bandit', 'Bandit', candidates.some(({ name }) => /\.py$/i.test(name)), 'لا توجد ملفات Python لتشغيل Bandit عليها.'],
        ['retirejs', 'Retire.js', candidates.some(({ name }) => /\.(cjs|mjs|jsx?|tsx?|json)$/i.test(name)), 'لا توجد ملفات JavaScript أو package.json لفحص اعتماديات الواجهة.'],
        ['trivy', 'Trivy', infrastructureCandidates.length > 0, 'لا توجد ملفات إعداد مدعومة لـ Trivy Misconfiguration.'],
        ['checkov', 'Checkov', infrastructureCandidates.length > 0, 'لا توجد ملفات IaC مدعومة لـ Checkov.'],
        ['npm-audit', 'npm audit (offline)', hasNpmManifest && hasNpmLock, 'لا توجد package.json وملف قفل npm معًا.'],
      ];
      for (const [id, name, applicable, reason] of skippedForInput) {
        if (!applicable && !artifactTools.some(tool => tool.id === id)) {
          artifactTools.push({ id, name, category: 'repository', status: 'not-applicable', output: `سبب عدم الفحص: ${reason}` });
        }
      }
    } catch (error) { artifactTools.push({ id: 'artifact-tools', name: 'Local source tools', category: 'artifact', installed: false, status: 'error', output: String(error.message).slice(0, 1000) }); }
    finally { await fs.rm(root, { recursive: true, force: true }).catch(() => {}); }
  }
  const reportedManifestFiles = new Set();
  for (const { name, content } of all) for (const pattern of patterns) {
    if (/^android-/.test(pattern.id) && !/\.(xml|plist)$/i.test(name)) continue;
    if (pattern.id === 'desktop-api-indicator' && !/^Extracted strings:/i.test(name)) continue;
    if (pattern.id === 'dependency-manifest' && !/(^|\/)(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|pom\.xml|build\.gradle(?:\.kts)?|requirements\.txt|Pipfile(?:\.lock)?|Gemfile(?:\.lock)?|go\.mod|composer\.json)$/i.test(name)) continue;
    if (pattern.id === 'dependency-manifest' && reportedManifestFiles.has(name)) continue;
    pattern.re.lastIndex = 0; let match;
    while ((match = pattern.re.exec(content)) && findings.length < 100) {
      if (pattern.id === 'embedded-secret' && /(?:your[-_ ]?(?:api[-_ ]?)?key|change[-_ ]?me|example|sample|placeholder|dummy|fake|not[-_ ]?a[-_ ]?secret|<[^>]+>)/i.test(match[0])) continue;
      if (pattern.id === 'embedded-secret') {
        const line = content.slice(0, match.index).split(/\r?\n/).length;
        if (findings.some(finding => finding.k === 'gitleaks' && finding.file === name && finding.line === line)) continue;
      }
      add(pattern.sev, pattern.id, pattern.title, pattern.desc, match[0], name, match.index, match[0]);
      if (pattern.id === 'dependency-manifest') { reportedManifestFiles.add(name); break; }
    }
  }
  if (!findings.length) findings.push({ k: 'artifact-inventory', sev: 'info', cwe: 'CWE-Unknown', cvss: 0, title: archiveOnlyInventory ? 'Application package received' : 'Static artifact analysis completed', desc: archiveOnlyInventory ? 'تم استلام الحزمة وقراءة فهرسها، لكن محتواها لا يتضمن ملفات نصية قابلة للتحليل بهذه القواعد. لم يتم تشغيل التطبيق.' : `تمت قراءة ${files.size} ملفاً نصياً دون تشغيل التطبيق. لم تظهر المؤشرات المحددة في قواعد الفحص الحالية.`, evidence: [`File: ${fileName}`, archiveOnlyInventory ? `Archive entries inspected: ${[...files.values()][0].split('\n').slice(0, 40).join(', ')}` : `Analyzed text files: ${files.size}`], fix: ['ارفع ملفات المصدر أو نسخة مفكوكة من المشروع لتحليل أعمق، أو استخدم أداة مخصصة لتحليل الحزمة الثنائية.'], ep: fileName, real: true });
  if (/\.(exe|dll)$/i.test(fileName) && buffer.subarray(0, 2).toString('ascii') === 'MZ' && findings.length < 100) findings.push({ k: 'windows-pe-inventory', sev: 'info', cwe: 'CWE-Unknown', cvss: 0, title: 'Windows PE binary detected', desc: 'تم التعرف على ملف Windows PE وفحص السلاسل النصية القابلة للطباعة؛ التحليل البنيوي الكامل يتطلب Ghidra أو x64dbg.', evidence: [`File: ${fileName}`, `Size: ${buffer.length} bytes`, `Detected format: PE/MZ`], fix: ['استخدم Ghidra للتحليل الساكن العميق وx64dbg في بيئة اختبار معزولة للتحليل الديناميكي.'], ep: fileName, real: true });
  return { findings, tools: artifactTools };
}

export async function completeArtifactToolReport(fileName, reportedTools) {
  const extension = path.extname(fileName).toLowerCase();
  const sourceExtensions = new Set(['.java','.kt','.swift','.m','.h','.cjs','.mjs','.jsx','.js','.tsx','.ts','.py','.rb','.pl','.sh','.php','.cs','.go','.tf','.yml','.yaml','.toml','.gradle','.json','.properties','.xml','.plist','.html','.htm']);
  const mobileExtensions = new Set(['.apk','.aab','.ipa']);
  const binaryExtensions = new Set(['.exe','.dll','.so','.dylib','.bin']);
  const isProject = extension === '.zip' || sourceExtensions.has(extension);
  const isMobile = mobileExtensions.has(extension);
  const isBinary = binaryExtensions.has(extension);
  const actual = new Map(reportedTools.map(tool => [tool.id, tool]));
  const addToolReason = tool => {
    if (tool.status === 'ok' || /سبب (?:عدم الفحص|تعذر|توقف)/u.test(String(tool.output || ''))) return tool;
    const reason = String(tool.error || tool.note || tool.install || 'لم تُنفذ الأداة ضمن هذا الفحص.').slice(0, 1000);
    const prefix = tool.status === 'timeout'
      ? `سبب توقف الأداة: ${reason}؛ استمر باقي الفحص.`
      : ['error', 'blocked'].includes(tool.status)
        ? `سبب تعذر الأداة: ${reason}؛ استمر باقي الفحص.`
        : `سبب عدم الفحص: ${reason}`;
    return { ...tool, output: [prefix, tool.output].filter(Boolean).join('\n') };
  };
  const results = await Promise.all(REQUESTED_TOOL_CATALOG.map(async item => {
    const [id, name, category, bin, description] = item;
    if (actual.has(id)) return addToolReason(actual.get(id));
    let applicable = false;
    let reason = '';
    if (category === 'repository') {
      applicable = isProject;
      reason = applicable
        ? 'هذه الأداة غير موصولة بعد بمسار تحليل الملفات/المستودعات الحالي.'
        : 'لم يُرفع ملف مصدر أو مستودع يناسب هذه الأداة.';
    } else if (category === 'artifact') {
      if (id === 'clamav') applicable = true;
      else if (['mobsf','jadx','apktool','qark','androguard'].includes(id)) applicable = isMobile || (id === 'mobsf' && extension === '.zip');
      else if (['drozer','frida','objection'].includes(id)) {
        applicable = isMobile;
        reason = 'لم تُشغّل: تتطلب جهازاً/محاكياً متصلاً وإعداداً خاصاً؛ لم يُقدَّم جهاز للفحص الديناميكي.';
      } else if (['radare2','ghidra','x64dbg'].includes(id)) applicable = isBinary;
      else if (id === 'binwalk' || id === 'firmadyne') applicable = extension === '.bin';
      else if (id === 'volatility') applicable = ['.dmp','.raw','.mem'].includes(extension);
      reason ||= applicable
        ? 'هذه الأداة لم تُشغّل في مسار تحليل هذا النوع من الملفات بعد.'
        : 'نوع الملف المرفوع لا يناسب مدخلات هذه الأداة.';
    } else {
      reason = 'هذه الأداة تحتاج هدفاً أو مدخلات من نوع آخر، وليس الملف المرفوع.';
    }
    if (!applicable) {
      return { id, name, category, status: 'not-applicable', note: description, output: `سبب عدم الفحص: ${reason}` };
    }
    if (id === 'mobsf' && !process.env.MOBSF_API_KEY) {
      return { id, name, category, status: 'not-run', installed: false, note: description,
        output: 'سبب عدم الفحص: إعداد MOBSF_API_KEY غير موجود؛ لم يُرسل الملف إلى MobSF.' };
    }
    let checked;
    try { checked = await checkTool(bin); }
    catch (error) {
      return { id, name, category, installed: false, status: 'error', note: description,
        output: `سبب تعذر التحقق من الأداة: ${String(error.message || error).slice(0, 500)}` };
    }
    if (!checked.installed) {
      return { id, name, category, installed: false, status: 'not-installed', note: description,
        install: `الأداة المطلوبة: ${bin}`, output: `سبب عدم الفحص: الأداة ${bin} غير مثبتة.` };
    }
    if (!checked.runnable) {
      return { id, name, category, installed: true, status: 'blocked', note: description,
        output: `سبب عدم الفحص: الأداة موجودة لكن تعذر تشغيل فحص التثبيت: ${String(checked.error || 'unknown error').slice(0, 500)}` };
    }
    return { id, name, category, installed: true, status: 'not-run', note: description,
      output: `سبب عدم الفحص: ${reason}` };
  }));
  const knownIds = new Set(REQUESTED_TOOL_CATALOG.map(([id]) => id));
  return [...results, ...reportedTools.filter(tool => !knownIds.has(tool.id))];
}

const scannerHttpServer = http.createServer(async (rq, rs) => {
  const identity = trustedScanIdentity(rq);
  const clientIp = identity?.ip || rq.socket.remoteAddress;
  const owner = identity?.user || 'local';
  if (rq.method === 'OPTIONS') { rs.writeHead(405, { 'Content-Type': 'application/json; charset=utf-8' }); return rs.end(JSON.stringify({ error: 'method-not-allowed' })); }
  rs.setHeader('Content-Type', 'application/json; charset=utf-8');
  rs.setHeader('Cache-Control', 'no-store');
  rs.setHeader('X-Content-Type-Options', 'nosniff');
  if (rq.method === 'TRACE') { rs.statusCode = 405; rs.setHeader('Allow', 'GET, POST, OPTIONS'); return rs.end(JSON.stringify({ error: 'method-not-allowed' })); }
  if (rq.url === '/health') return rs.end(JSON.stringify({
    ok: true, consentRequired: true, tenantScopeEnforced: true,
    tenantConfigured: Boolean(TENANT_ID), allowedDomainCount: ALLOWED_SCAN_DOMAINS.length,
  }));
  if (rq.url === '/tools' && rq.method === 'GET') return rs.end(JSON.stringify({ tools: await toolInventory() }));
  if (rq.url === '/knowledge' && rq.method === 'GET') return rs.end(JSON.stringify({
    vulnerabilities: Object.entries(REALMETA).map(([id, item]) => ({ id, ...item }))
  }));
  if (rq.url === '/file-scan' && rq.method === 'POST') {
    try {
      const chunks = []; let size = 0;
      for await (const chunk of rq) { size += chunk.length; if (size > 52 * 1024 * 1024) throw new Error('الملف أكبر من الحد المسموح (50 MB).'); chunks.push(chunk); }
      const raw = Buffer.concat(chunks);
      const boundary = String(rq.headers['content-type'] || '').match(/boundary=(?:"([^"]+)"|([^;]+))/i);
      if (!boundary) throw new Error('تعذر قراءة الملف المرفوع.');
      const marker = Buffer.from('--' + (boundary[1] || boundary[2]));
      let file = null, fileName = 'uploaded-file';
      let cursor = 0;
      while ((cursor = raw.indexOf(marker, cursor)) >= 0) {
        const headStart = cursor + marker.length + 2;
        const headEnd = raw.indexOf(Buffer.from('\r\n\r\n'), headStart);
        if (headEnd < 0) break;
        const headers = raw.subarray(headStart, headEnd).toString('utf8');
        const dataStart = headEnd + 4;
        const next = raw.indexOf(marker, dataStart);
        if (next < 0) break;
        if (/name="file"/i.test(headers)) {
          fileName = headers.match(/filename="([^"]*)"/i)?.[1] || fileName;
          file = raw.subarray(dataStart, Math.max(dataStart, next - 2)); break;
        }
        cursor = next;
      }
      if (!file?.length) throw new Error('لم يتم اختيار ملف صالح.');
      const analysis = await analyzeUploadedArtifact(file, fileName);
      const findings = analysis.findings;
      await auditLog({ action: 'file-static-analysis', file: fileName.slice(0, 180), bytes: file.length,
        findings: findings.length, owner, tenantId: identity?.tenantId || 'untrusted-local', ip: clientIp });
      const tools = await completeArtifactToolReport(fileName, analysis.tools);
      rs.end(JSON.stringify({ ok: true, fileName: fileName.split(/[\\/]/).pop().slice(0, 180), bytes: file.length, findings, tools,
        engine: 'Reasonix Local Artifact Analyzer', disclaimer: 'تحليل ساكن محلي للمؤشرات فقط؛ راجع النتائج يدوياً، ولا يشغّل الملف.' }));
    } catch (error) { rs.statusCode = error.message.includes('الحد المسموح') ? 413 : 400; rs.end(JSON.stringify({ error: error.message })); }
    return;
  }
  if (rq.url.startsWith('/scan/status') && rq.method === 'GET') {
    const url = new URL(rq.url, `http://127.0.0.1:${PORT}`);
    const job = SCAN_JOBS.get(url.searchParams.get('id'));
    if (!identity || !job || job.owner !== owner) return rs.end(JSON.stringify({ error: 'scan-not-found' }));
    const after = Number(url.searchParams.get('after') || 0);
    return rs.end(JSON.stringify({
      id: job.id, status: job.status, events: job.events.filter(event => event.seq > after),
      sequence: job.sequence, result: job.status === 'completed' ? job.result : undefined,
      error: ['failed', 'cancelled'].includes(job.status) ? job.error : undefined,
    }));
  }
  if (rq.url === '/scan/cancel' && rq.method === 'POST') {
    let body = '';
    rq.on('data', chunk => {
      body += chunk;
      if (body.length > 4096) { rq.destroy(); }
    });
    rq.on('end', async () => {
      try {
        const { scanId } = JSON.parse(body);
        const job = SCAN_JOBS.get(String(scanId || ''));
        if (!identity || !job || job.owner !== owner) {
          rs.statusCode = 404;
          rs.end(JSON.stringify({ error: 'scan-not-found' }));
          return;
        }
        if (job.status === 'running') {
          await auditLog({ action: 'scan-cancelled', owner, tenantId: identity.tenantId,
            target: job.target, ip: clientIp, scanId: job.id, consentId: job.consentId });
          job.status = 'cancelled';
          job.error = 'scan-cancelled';
          job.finishedAt = Date.now();
          job.controller.abort();
          await job.console?.finish('CANCELLED', 'Stopped by user.');
        }
        rs.end(JSON.stringify({ ok: true, status: job.status }));
      } catch (error) {
        rs.statusCode = error.message?.includes('audit') ? 503 : 400;
        rs.end(JSON.stringify({ error: error.message || 'invalid-request' }));
      }
    });
    return;
  }
  if (rq.url === '/consent/accept' && rq.method === 'POST') {
    const chunks = []; let size = 0;
    for await (const chunk of rq) {
      size += chunk.length;
      if (size > 16_384) { rs.statusCode = 413; return rs.end(JSON.stringify({ error: 'request-too-large' })); }
      chunks.push(chunk);
    }
    let input;
    try { input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
    catch { rs.statusCode = 400; return rs.end(JSON.stringify({ error: 'invalid-json' })); }
    if (!identity) { rs.statusCode = 401; return rs.end(JSON.stringify({ error: 'authenticated-session-required' })); }
    if (input.accepted !== true) { rs.statusCode = 400; return rs.end(JSON.stringify({ error: 'explicit-consent-required' })); }
    if (!TENANT_ID) { rs.statusCode = 503; return rs.end(JSON.stringify({ error: 'tenant-configuration-required' })); }
    if (!AUDIT_KEY) { rs.statusCode = 503; return rs.end(JSON.stringify({ error: 'audit-key-unavailable' })); }
    const now = Date.now();
    for (const [key, consent] of ACTIVE_CONSENTS) if (consent.expiresAt <= now) ACTIVE_CONSENTS.delete(key);
    if (ACTIVE_CONSENTS.size >= 10_000) { rs.statusCode = 503; return rs.end(JSON.stringify({ error: 'consent-capacity-reached' })); }
    const consentId = crypto.randomUUID();
    const token = crypto.randomBytes(32).toString('base64url');
    const acceptedAt = new Date(now).toISOString();
    const expiresAt = now + CONSENT_TTL_MS;
    const signedContent = [CONSENT_VERSION, consentId, identity.tenantId, identity.user, acceptedAt, identity.ip].join('\n');
    const consentSignature = crypto.createHmac('sha256', AUDIT_KEY).update(signedContent).digest('hex');
    try {
      await auditLog({ action: 'legal-consent-accepted', owner: identity.user, tenantId: identity.tenantId,
        ip: identity.ip, consentId, consentVersion: CONSENT_VERSION, acceptedAt, consentSignature });
    } catch (error) {
      console.error('consent audit failed:', error.message);
      rs.statusCode = 503;
      return rs.end(JSON.stringify({ error: 'consent-audit-unavailable' }));
    }
    ACTIVE_CONSENTS.set(crypto.createHash('sha256').update(token).digest('hex'), {
      user: identity.user, tenantId: identity.tenantId, consentId, consentSignature, acceptedAt, expiresAt,
    });
    rs.statusCode = 201;
    return rs.end(JSON.stringify({ ok: true, token, consentId, signature: consentSignature,
      acceptedAt, expiresAt: new Date(expiresAt).toISOString(), version: CONSENT_VERSION }));
  }
  /* حماية الفحص السريع: حد معدل + قفل لكل هدف (بدون فحص مزدوج أو إغراق) */
  if (rq.url === '/quick-scan' && rq.method === 'POST') {
    const now = Date.now();
    for (const [key, entry] of QUICK_SCAN_RATE) if (entry.resetAt <= now) QUICK_SCAN_RATE.delete(key);
    const rateKey = identity?.ip || clientIp;
    const rateEntry = QUICK_SCAN_RATE.get(rateKey);
    if (rateEntry && rateEntry.count >= 5 && rateEntry.resetAt > now) {
      rs.statusCode = 429;
      return rs.end(JSON.stringify({ error: 'تم تجاوز الحد المسموح للفحص السريع؛ أعد المحاولة بعد دقيقة.' }));
    }
    let body = '';
    rq.on('data', chunk => { body += chunk; if (body.length > 4096) rq.destroy(); });
    rq.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        const target = normalizeScanTarget(payload?.target);
        if (!target) return rs.end(JSON.stringify({ error: 'هدف غير صالح — أدخل نطاقاً أو عنوان IP صحيحاً' }));
        /* فحص تجريبي بدون حساب وبدون قيود نطاق: أي هدف صالح (نطاق عام أو محلي) يُقبل.
           الحماية تبقى عبر: حد معدل لكل IP + قفل هدف + تسجيل تدقيق. */
        const scope = tenantScopeFor(target, identity?.tenantId || TENANT_ID);
        const domain = scope.domain || domainOf(target) || new URL(target).hostname;
        if (QUICK_SCAN_ACTIVE.has(domain)) {
          rs.statusCode = 409;
          return rs.end(JSON.stringify({ error: 'يوجد فحص سريع جارٍ على هذا الهدف بالفعل؛ انتظر انتهائه.' }));
        }
        const rate = rateEntry || { count: 0, resetAt: now + 60_000 };
        if (!rateEntry) QUICK_SCAN_RATE.set(rateKey, rate);
        rate.count++;
        const scopeDomain = domain;
        void auditLog({ action: 'quick-scan-started', owner, tenantId: identity?.tenantId || 'unauthenticated', target, ip: clientIp, domain }).catch(() => {});
        QUICK_SCAN_ACTIVE.add(domain);
        const tools = [];
        const findings = [];
        /* --- Nmap --- */
        {
          const startedAt = Date.now();
          const nmapPath = await whichTool('nmap') || path.join(TOOLS_DIR, 'nmap', 'nmap.exe');
          if (!fsSync.existsSync(nmapPath)) {
            tools.push({ id: 'nmap', name: 'nmap', installed: false, status: 'not-installed', note: 'فحص المنافذ والخدمات', output: 'Nmap غير مثبت في tools/nmap.' });
          } else {
            const r = await execTool(nmapPath, nmapArgs(target), { timeout: 180000, env: { NMAPDIR: path.join(TOOLS_DIR, 'nmap') } });
            const status = r.killed ? 'timeout' : (r.error || r.code !== 0) ? 'error' : 'ok';
            const extra = status === 'ok' ? parseNmapXml(r.stdout, target) : [];
            findings.push(...extra);
            tools.push({ id: 'nmap', name: 'nmap', installed: true, status,
              command: redactScanSecrets(displayCommand('nmap', nmapArgs(target))),
              note: 'فحص محدود لأكثر 100 منفذ وإصدارات الخدمات (سكربتات safe فقط)',
              elapsed: Date.now() - startedAt,
              output: status === 'ok'
                ? `Nmap: ${extra.length} منفذ مفتوح (مؤشر جرد وليس ثغرة).`
                : `تعذر تشغيل Nmap: ${String(r.error || r.stderr || `exit ${r.code}`).slice(0, 400)}` });
          }
        }
        /* --- SQLmap (فقط إذا كان الهدف يحتوي معاملات استعلام) --- */
        {
          const startedAt = Date.now();
          const hasParams = [...new URL(target).searchParams.keys()].length > 0;
          const pythonPath = path.join(TOOLS_DIR, 'python', 'python.exe');
          const sqlmapPath = path.join(TOOLS_DIR, 'sqlmap', 'sqlmap.py');
          if (!hasParams) {
            tools.push({ id: 'sqlmap', name: 'sqlmap', installed: true, status: 'not-applicable',
              note: 'اختبار SQL injection محدود', output: 'sqlmap يحتاج رابطاً يحتوي معاملات استعلام (مثل ?id=1)؛ تم تخطيه لهذا الهدف.' });
          } else if (!fsSync.existsSync(pythonPath) || !fsSync.existsSync(sqlmapPath)) {
            tools.push({ id: 'sqlmap', name: 'sqlmap', installed: false, status: 'not-installed', note: 'اختبار SQL injection محدود', output: 'sqlmap أو Python غير مثبتين محلياً.' });
          } else {
            const args = [sqlmapPath, '-u', target, '--batch', '--smart', '--level=1', '--risk=1',
              '--threads=1', '--timeout=5', '--retries=1', '--technique=BEU', '--forms=false', '--crawl=0',
              '--output-dir', path.join(os.tmpdir(), 'reasonix-quickscan'), '-v', '0'];
            const r = await execTool(pythonPath, args, { timeout: 120000 });
            const status = r.killed ? 'timeout' : (r.error && !r.stdout) ? 'error' : 'ok';
            const stdout = r.stdout || '';
            const injectable = [...stdout.matchAll(/Type:\s*([^\r\n]+)\s*Title:\s*([^\r\n]+)\s*Payload:\s*([^\r\n]+)/giu)].slice(0, 5);
            const paramMatch = stdout.match(/Parameter:\s*([^\r\n]+)/i);
            for (const hit of injectable) {
              const parameter = String(paramMatch?.[1] || 'input').replace(/[^a-zA-Z0-9_.[\]-]/gu, '').slice(0, 100) || 'input';
              const technique = String(hit[1]).trim().slice(0, 80);
              const evidence = [`Parameter: ${parameter}`, `Technique: ${technique}`, `Payload: ${String(hit[3]).trim().slice(0, 200)}`, 'لم يُستخرج أي محتوى من قاعدة البيانات.'];
              findings.push({ k: `sql-injection-quick-${parameter.toLowerCase()}`, sev: 'high', cwe: 'CWE-89', cvss: 0,
                title: `إشارة SQL injection في المعامل "${parameter}" (sqlmap)`,
                desc: 'أبلغ sqlmap عن نجاح إحدى تقنيات الحقن المحصورة (Boolean/Error/Union). تحقق يدوياً قبل اعتماد النتيجة كثغرة مؤكدة.',
                fix: ['استخدم استعلامات معلمة (parameterized queries) وتحقق من نوع المدخل.'],
                ep: target.slice(0, 500), evidence, real: true, source: 'sqlmap (local CLI)' });
            }
            tools.push({ id: 'sqlmap', name: 'sqlmap', installed: true, status: status === 'ok' && !injectable.length ? 'ok' : status,
              command: redactScanSecrets(displayCommand('python', args)),
              note: 'فحص Boolean/Error/Union محدود؛ لا استخراج بيانات', elapsed: Date.now() - startedAt,
              output: status === 'ok'
                ? (injectable.length ? `sqlmap: ${injectable.length} إشارة حقن محتملة.` : 'sqlmap اكتمل دون إشارات حقن ضمن الحدود المسموحة.')
                : `تعذر تشغيل sqlmap: ${String(r.error || r.stderr || `exit ${r.code}`).slice(0, 400)}` });
          }
        }
        const counts = findings.reduce((acc, f) => (acc[f.sev] = (acc[f.sev] || 0) + 1, acc), {});
        void auditLog({ action: 'quick-scan-executed', owner, tenantId: identity?.tenantId || 'unauthenticated', target, ip: clientIp, findings: findings.length }).catch(() => {});
        rs.end(JSON.stringify({ ok: true, target, tools, findings, counts,
          disclaimer: 'فحص سريع محدود (Nmap + SQLmap) بمخرجات الأدوات الظاهرة فقط. عدم ظهور نتائج لا يثبت خلو الهدف من الثغرات؛ استخدم الفحص الكامل لاستكمال التحليل.' }));
      } catch (error) {
        rs.statusCode = error instanceof SyntaxError ? 400 : 500;
        rs.end(JSON.stringify({ error: error instanceof SyntaxError ? 'invalid-json' : String(error?.message || 'quick-scan failed').slice(0, 300) }));
      } finally {
        try { QUICK_SCAN_ACTIVE.delete(scopeDomain); } catch { }
      }
    });
    return;
  }
  if (rq.url === '/scan/start' && rq.method === 'POST') {
    let body = '';
    rq.on('data', chunk => body += chunk);
    rq.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const target = normalizeScanTarget(payload?.target);
        const profile = normalizeScanProfile(payload?.profile);
        const scanOptions = normalizeScanOptions({
          ...(payload?.auth || {}),
          activeTestsConfirmed: payload?.activeTestsConfirmed,
        });
        if (!target) {
          rs.end(JSON.stringify({ error: 'هدف غير صالح — أدخل نطاقاً صحيحاً مثل example.com' }));
          return;
        }
        if (!identity) {
          rs.statusCode = 401;
          rs.end(JSON.stringify({ error: 'authenticated-session-required' }));
          return;
        }
        const scope = tenantScopeFor(target, identity.tenantId);
        if (!scope.ok) {
          await auditLog({ action: 'scan-refused-out-of-scope', owner, tenantId: identity.tenantId,
            target, ip: clientIp, reason: scope.reason });
          rs.statusCode = 403;
          rs.end(JSON.stringify({ error: 'target-outside-tenant-scope' }));
          return;
        }
        const consent = findConsent(payload?.consentToken, identity);
        if (!consent) {
          await auditLog({ action: 'scan-refused-no-consent', owner, tenantId: identity.tenantId, target, ip: clientIp });
          rs.statusCode = 428;
          rs.end(JSON.stringify({ error: 'legal-consent-required' }));
          return;
        }
        if (requiresActiveConfirmation(profile) && !scanOptions.activeTestsConfirmed) {
          await auditLog({ action: 'scan-refused-no-active-test-confirmation', owner, tenantId: identity.tenantId, target, ip: clientIp, profile });
          rs.statusCode = 428;
          rs.end(JSON.stringify({ error: 'active-test-confirmation-required' }));
          return;
        }
        const runningJobs = [...SCAN_JOBS.values()].filter(item => item.status === 'running').length;
        if (runningJobs >= 2) { rs.statusCode = 429; rs.end(JSON.stringify({ error: 'scan-capacity-reached' })); return; }
        const pruneBefore = Date.now() - 15 * 60_000;
        for (const [jobId, item] of SCAN_JOBS) if (item.finishedAt && item.finishedAt < pruneBefore) SCAN_JOBS.delete(jobId);
        const id = crypto.randomUUID();
        const scanConsole = await openWindowsScanConsole(target, id, profile);
        const controller = new AbortController();
        const job = { id, owner, tenantId: identity.tenantId, consentId: consent.consentId,
          target, profile, status: 'running', events: [], sequence: 0, result: null, error: null,
          controller, console: scanConsole, startedAt: Date.now() };
        SCAN_JOBS.set(id, job);
        while (SCAN_JOBS.size > 20) {
          const oldest = [...SCAN_JOBS].find(([, item]) => item.status !== 'running')?.[0];
          if (!oldest) break;
          SCAN_JOBS.delete(oldest);
        }
        try {
          await auditLog({ action: 'scan-started', owner, tenantId: identity.tenantId, target, ip: clientIp,
            scanId: id, profile, activeTestsConfirmed: scanOptions.activeTestsConfirmed,
            scopeEnforced: true, consentId: consent.consentId, consentSignature: consent.consentSignature });
          consumeConsent(payload.consentToken);
        } catch (error) {
          SCAN_JOBS.delete(id);
          console.error('scan start audit failed:', error.message);
          rs.statusCode = 503;
          rs.end(JSON.stringify({ error: 'audit-unavailable-scan-not-started' }));
          return;
        }
        rs.end(JSON.stringify({ scanId: id, status: job.status }));
        SCAN_CONTEXT.run({ ...scanOptions, signal: controller.signal }, () => scan(target, event => {
          job.events.push({ seq: ++job.sequence, ...event });
          if (job.events.length > 500) job.events.shift();
          if (job.console) void job.console.write(formatWindowsConsoleEvent(event));
        }, profile)).then(async result => {
          if (job.status !== 'running') return;
          result.disclaimer = DISCLAIMER;
          result.scopeAuthorized = true;
          result.audit = 'سجل تدقيق مشفر ومترابط ببصمات HMAC؛ ليس تخزيناً WORM، ويظل حذف الملف من مسؤوليات مشغل الخادم.';
          await auditLog({ action: 'scan-executed', owner, tenantId: identity.tenantId, target, ip: clientIp,
            scanId: id, findings: result.findings.length, scopeEnforced: true, consentId: consent.consentId });
          job.result = result;
          job.status = 'completed';
          job.finishedAt = Date.now();
          await job.console?.finish('COMPLETE', `Scan finished with ${result.findings.length} finding(s).`);
        }).catch(async error => {
          if (job.status === 'running') {
            job.error = error.message;
            job.status = 'failed';
            job.finishedAt = Date.now();
            await job.console?.finish('FAILED', error.message || 'Scan failed.');
            try {
              await auditLog({ action: 'scan-failed', owner, tenantId: identity.tenantId, target, ip: clientIp,
                scanId: id, consentId: consent.consentId, error: error.message });
            } catch (auditError) {
              job.error = 'scan-failed-and-audit-unavailable';
              console.error('scan failure audit failed:', auditError.message);
            }
          }
        }).finally(() => {
          job.controller = null;
        });
      } catch (error) {
        rs.statusCode = error instanceof SyntaxError ? 400 : 503;
        rs.end(JSON.stringify({ error: error instanceof SyntaxError ? 'invalid-json' : 'audit-or-scan-service-unavailable' }));
      }
    });
    return;
  }
  if (rq.url === '/scan' && rq.method === 'POST') {
    let body = '';
    rq.on('data', c => body += c);
    rq.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const target = normalizeScanTarget(payload?.target);
        const profile = normalizeScanProfile(payload?.profile);
        const scanOptions = normalizeScanOptions({
          ...(payload?.auth || {}),
          activeTestsConfirmed: payload?.activeTestsConfirmed,
        });
        if (!target) {
          rs.end(JSON.stringify({ error: 'هدف غير صالح — أدخل نطاقاً صحيحاً مثل example.com' }));
          return;
        }
        /* === بوابة الامتثال: تسجيل دخول ونطاق خادمي وموافقة صريحة === */
        if (!identity) { rs.statusCode = 401; rs.end(JSON.stringify({ error: 'authenticated-session-required' })); return; }
        const scope = tenantScopeFor(target, identity.tenantId);
        const consent = findConsent(payload?.consentToken, identity);
        if (!scope.ok || !consent) {
          await auditLog({ action: !scope.ok ? 'scan-refused-out-of-scope' : 'scan-refused-no-consent',
            owner, tenantId: identity.tenantId, target, ip: clientIp, reason: scope.reason || null });
          rs.statusCode = !scope.ok ? 403 : 428;
          rs.end(JSON.stringify({ error: !scope.ok ? 'target-outside-tenant-scope' : 'legal-consent-required' }));
          return;
        }
        if (requiresActiveConfirmation(profile) && !scanOptions.activeTestsConfirmed) {
          await auditLog({ action: 'scan-refused-no-active-test-confirmation', owner, tenantId: identity.tenantId, target, ip: clientIp, profile });
          rs.statusCode = 428;
          rs.end(JSON.stringify({ error: 'active-test-confirmation-required' }));
          return;
        }
        await auditLog({ action: 'scan-started', owner, tenantId: identity.tenantId, target, ip: clientIp,
          profile, activeTestsConfirmed: scanOptions.activeTestsConfirmed,
          scopeEnforced: true, consentId: consent.consentId, consentSignature: consent.consentSignature });
        consumeConsent(payload.consentToken);
        const out = await SCAN_CONTEXT.run(scanOptions, () => scan(target, undefined, profile));
        out.disclaimer = DISCLAIMER;
        out.scopeAuthorized = true;
        out.audit = 'سجل الفحص مشفر ومترابط ببصمات HMAC؛ ليس تخزيناً WORM، ويظل حذف الملف من مسؤوليات مشغل الخادم.';
        await auditLog({ action: 'scan-executed', owner, tenantId: identity.tenantId, target, ip: clientIp,
          findings: out.findings.length, scopeEnforced: true, consentId: consent.consentId });
        rs.end(JSON.stringify(out));
      } catch (e) { rs.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }
  rs.end(JSON.stringify({ error: 'POST /scan {target}' }));
});
scannerHttpServer.on('error', error => console.error('scan-server listen error:', error.message));
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  scannerHttpServer.listen(PORT, '127.0.0.1', () => console.log(`live-scan ready → http://127.0.0.1:${PORT}`));
}
export default scannerHttpServer;

/* ======================================================================
   v2 — كاشفات حقيقية إضافية + بيانات ثغرات كاملة (CWE/CVSS/وصف/إصلاح)
   كل كاشف يُرجع دليلاً حقيقياً فقط من استجابات الهدف الفعلية.
   ====================================================================== */

/* ---------------- كاشفات إضافية ---------------- */
Object.assign(CHECKS, {

  // 13) بروتوكولات TLS قديمة (TLSv1.0/1.1)
  async legacyTls(base) {
    if (!base.startsWith('https')) return null;
    const u = new URL(base);
    const probe = (secureProtocol) => new Promise(resolve => {
      const s = tls.connect({ host: u.hostname, port: Number(u.port) || 443, servername: u.hostname, secureProtocol, rejectUnauthorized: false, timeout: 5000 }, () => { s.end(); resolve(true); });
      s.on('error', () => resolve(false));
      s.on('timeout', () => { s.destroy(); resolve(false); });
    });
    const v10 = await probe('TLSv1_method');
    const v11 = !v10 && await probe('TLSv1_1_method');
    if (v10 || v11)
      return { k: 'tls-legacy', sev: 'high', title: `بروتوكول TLS قديم مقبول من الخادم (${v10 ? 'TLS 1.0' : 'TLS 1.1'})`,
        ep: 'TLS handshake',
        evidence: [`اتصال ناجح بـ ${v10 ? 'TLSv1.0' : 'TLSv1.1'} على ${u.hostname}:443`,
          'PCI-DSS و NIST SP 800-52 يمنعان TLS < 1.2'] };
    return null;
  },

  // 14) بريد إلكتروني: SPF و DMARC (سجلات DNS حقيقية)
  async emailSecurity(base) {
    const u = new URL(base);
    const dom = u.hostname.replace(/^www\./, '');
    if (net.isIP(dom.replace(/^\[|\]$/g, '')) || isLocalTarget(dom)) return null;
    let spf = false, dmarc = false, ev = [];
    try {
      const txt = await dns.resolveTxt(dom);
      const flat = txt.map(t => t.join(''));
      spf = flat.some(t => /^v=spf1/i.test(t));
      ev.push(...flat.filter(t => /^v=spf1/i.test(t)).slice(0, 2).map(t => `TXT ${dom} → ${t.slice(0, 120)}`));
    } catch { }
    try {
      const dm = await dns.resolveTxt('_dmarc.' + dom);
      const flat = dm.map(t => t.join(''));
      dmarc = flat.some(t => /^v=DMARC1/i.test(t));
      ev.push(...flat.filter(t => /^v=DMARC1/i.test(t)).slice(0, 1).map(t => `TXT _dmarc.${dom} → ${t.slice(0, 120)}`));
    } catch { }
    if (!spf || !dmarc)
      return { k: 'email-spoofing', sev: 'medium', title: `حماية بريد ناقصة ${!spf ? '— SPF غائب' : ''}${!dmarc ? ' — DMARC غائب' : ''}`,
        ep: 'DNS TXT', evidence: [`استعلام DNS حقيقي للنطاق ${dom}`, ...ev, !spf ? 'لا يوجد سجل SPF — انتحال مرسل ممكن' : '', !dmarc ? 'لا يوجد سجل DMARC — لا سياسة رفض للرسائل المزورة' : ''].filter(Boolean) };
    return null;
  },

  // 15) نطاقات فرعية عبر سجل الشفافية crt.sh (OSINT حقيقي)
  async subdomainOSINT(base) {
    const u = new URL(base);
    const dom = u.hostname.replace(/^www\./, '');
    if (net.isIP(dom.replace(/^\[|\]$/g, '')) || isLocalTarget(dom)) return null;
    try {
      const r = await req(`https://crt.sh/?q=%25.${encodeURIComponent(dom)}&output=json`, {}, 12000);
      if (!r.ok || !r.body.startsWith('[')) return null;
      const rows = JSON.parse(r.body);
      const subs = [...new Set(rows.flatMap(x => String(x.name_value).split('\n')))
        ].filter(n => n.endsWith('.' + dom) && !n.startsWith('*.')).slice(0, 40);
      if (subs.length >= 3)
        return { k: 'subdomain-osint', sev: 'info', title: `سطح الهجوم: ${subs.length} نطاقاً فرعياً من شهادات CT`,
          ep: 'crt.sh Certificate Transparency',
          evidence: [`crt.sh → ${rows.length} شهادة مسجلة للنطاق ${dom}`, 'نطاقات فرعية كشفت شهادات TLS:', ...subs.slice(0, 15).map(s => '▸ ' + s)] };
    } catch { }
    return null;
  },

  // 16) كشف WAF / CDN (معلومة دفاعية حقيقية)
  async wafDetect(base) {
    const r = await req(base + '/', {}, 7000);
    if (!r.ok) return null;
    const h = JSON.stringify(r.headers).toLowerCase() + JSON.stringify(r.headers['set-cookie'] || '').toLowerCase();
    const wafs = [
      [/cf-ray|__cfduid|server: ?cloudflare/, 'Cloudflare'],
      [/x-sucuri-id/, 'Sucuri'],
      [/x-akamai|akamaighost/, 'Akamai'],
      [/x-iinfo|incapsula/, 'Imperva Incapsula'],
      [/x-cdn|keycdn|stackpath/, 'CDN/WAF عام'],
      [/x-waf|sec[^u]{0,3}waf/, 'WAF مخصص'],
      [/x-powered-by: ?aws|amplify/, 'AWS'],
      [/x-vercel-id/, 'Vercel'],
      [/x-fastly|varnish/, 'Fastly/Varnish'],
    ];
    for (const [re, name] of wafs)
      if (re.test(h)) return { k: 'waf-detected', sev: 'info', title: 'حماية أمامية مكتشفة — ' + name,
        ep: 'HTTP headers', evidence: [`GET / → HTTP ${r.status}`, 'مؤشرات في الترويسات: ' + name] };
    return null;
  },

  // 17) ملفات معلومات/اختبار مكشوفة (phpinfo)
  async infoFiles(base) {
    const baseline = await soft404Canary(base);
    for (const f of ['/phpinfo.php', '/info.php', '/test.php', '/server-info', '/.DS_Store', '/composer.lock', '/package.json', '/npm-debug.log']) {
      const r = await req(base + f, {}, 6000);
      if (r.ok && r.status === 200 && !isSoft404Response(r.body, r.status, baseline, r.url) && r.body.length > 50 &&
        (/<title>phpinfo|PHP Version|_SERVER\[|dependencies|devDependencies/i.test(r.body) || f === '/.DS_Store' || /\d/.test(r.body.slice(0, 3))))
        return { k: 'info-file', sev: 'low', title: 'ملف معلومات مكشوف — ' + f,
          ep: f, evidence: [`GET ${f} → HTTP ${r.status}`, 'محتوى: ' + r.body.slice(0, 120).replace(/\s+/g, ' ')] };
    }
    return null;
  },

  // 18) انعكاس مدخل المستخدم (كشف حمّالات XSS محتملة — بدون استغلال)
  async inputReflection(base) {
    const id = Math.random().toString(36).slice(2, 9);
    const controlMarker = `rsx-control-${id}`;
    const probeMarker = `<rsx-probe-${id}>`;
    for (const parameter of ['q', 'search', 's', 'query', 'name', 'id', 'page', 'keyword', 'term']) {
      const controlUrl = `${base}/?${parameter}=${encodeURIComponent(controlMarker)}`;
      const probeUrl = `${base}/?${parameter}=${encodeURIComponent(probeMarker)}`;
      const control = await req(controlUrl, {}, 6000);
      const candidate = await req(probeUrl, {}, 6000);
      if (!control.ok || !candidate.ok) continue;
      const comparison = compareBehavioralResponses(control, candidate, controlMarker, probeMarker);
      const contentType = String(candidate.headers['content-type'] || '').toLowerCase();
      if (comparison.probeMarkerReflectedRaw && contentType.includes('text/html')) {
        const endpoint = `/?${parameter}=`;
        return {
          k: 'input-reflection', sev: 'info', cwe: 'CWE-79', cvss: 0,
          title: 'انعكاس HTML خام يحتاج مراجعة سياقية',
          desc: 'اختلفت استجابة الاختبار المقارن وأعادت علامة HTML آمنة دون ترميز. هذا ليس إثباتًا لـ XSS؛ يلزم فحص سياق الإدراج في المتصفح.',
          ep: endpoint,
          param: parameter,
          payload: probeMarker,
          responseExcerpt: candidate.body.slice(
            Math.max(0, candidate.body.indexOf(probeMarker) - 100),
            Math.min(candidate.body.length, candidate.body.indexOf(probeMarker) + probeMarker.length + 100),
          ),
          source: 'Reasonix safe reflection probe',
          evidence: [
            `Control: HTTP ${control.status}, ${control.body.length} chars; probe: HTTP ${candidate.status}, ${candidate.body.length} chars.`,
            `نوع المحتوى: ${contentType}; علامة الاختبار أعيدت حرفيًا: ${comparison.probeMarkerReflectedRaw ? 'نعم' : 'لا'}.`,
            `شكل الاستجابة بعد توحيد العلامات: ${comparison.normalizedBodiesEqual ? 'متطابق' : 'مختلف'}.`,
          ],
          note: 'مقارنة سلوكية بين طلب GET ضابط وآخر بعلامة غير تنفيذية؛ لا يُرسل JavaScript ولا تُنفّذ حمولة.',
        };
      }
    }
    return null;
  },

  async heuristicAnomaly(base) {
    const id = Math.random().toString(36).slice(2, 9);
    const parameter = '__reasonix_probe';
    const controlMarker = `rsx-control-${id}`;
    const controlUrl = new URL(base + '/');
    controlUrl.searchParams.set(parameter, controlMarker);
    const control = await req(controlUrl.toString(), {}, 6000);
    if (!control.ok || [401, 403, 429].includes(control.status)) return null;
    const payloads = heuristicProbePayloads(`rsx-${id}`);
    for (const probe of payloads) {
      const probeMarker = `rsx-${id}`;
      const candidateUrl = new URL(base + '/');
      candidateUrl.searchParams.set(parameter, probe.parameterMode === 'value' ? probe.payload : controlMarker);
      if (probe.parameterMode === 'add-param') candidateUrl.searchParams.set(probe.parameter, probe.payload);
      const candidate = await req(candidateUrl.toString(), {}, 6000);
      if (!candidate.ok || [401, 403, 429].includes(candidate.status)) continue;
      const analysis = analyzeHeuristicResponses(control, candidate, {
        probeMarker: probe.kind === 'ssti-arithmetic' ? '' : probeMarker,
        expectedOutput: probe.expectedOutput || '',
      });
      if (!analysis.anomalous) continue;
      const labels = {
        'new-stack-trace': 'new stack trace in response',
        'unexpected-server-error': 'unexpected 5xx response',
        'template-expression-evaluated': 'arithmetic template expression appears evaluated',
        'large-response-size-delta': 'unusually large response-length change',
        'unexpected-status-change': 'unexpected HTTP status change',
      };
      const details = analysis.signals.map(signal => labels[signal] || signal);
      const finding = {
        k: `heuristic-anomaly-${probe.kind}`,
        sev: 'info',
        cwe: probe.kind === 'ssti-arithmetic' && analysis.signals.includes('template-expression-evaluated') ? 'CWE-1336' : 'CWE-Unknown',
        cvss: 0,
        title: `Heuristic anomaly signal: ${probe.kind}`,
        desc: 'A bounded, non-destructive input probe caused an unusual response. This is a lead for manual review, not a confirmed vulnerability or zero-day.',
        ep: candidateUrl.pathname + candidateUrl.search.replace(/rsx-[^&]*/gu, '[marker]'),
        param: probe.parameterMode === 'add-param' ? probe.parameter : parameter,
        payload: probe.payload,
        responseExcerpt: analysis.responseExcerpt,
        source: 'Reasonix bounded heuristic probe',
        evidence: [
          `Probe kind: ${probe.kind}; payload is inert and does not execute commands or modify application data.`,
          `Control HTTP ${analysis.controlStatus}, ${analysis.controlLength} chars; probe HTTP ${analysis.probeStatus}, ${analysis.probeLength} chars.`,
          `Signals: ${details.join(', ')}; automated confidence: ${analysis.confidence}.`,
          'No records or database contents were extracted.',
        ],
      };
      return finding;
    }
    return null;
  },

  // 19) robots.txt / sitemap.xml — كشف مسارات (info)
  async robotsExposure(base) {
    const r = await req(base + '/robots.txt', {}, 6000);
    if (r.ok && r.status === 200 && /^\s*(user-agent|disallow|sitemap)/im.test(r.body)) {
      const dis = (r.body.match(/^disallow:\s*(\S+)/gim) || []).slice(0, 6);
      const sm = r.body.match(/^sitemap:\s*(\S+)/im)?.[1];
      return { k: 'robots-exposure', sev: 'info', title: 'robots.txt يكشف مسارات مخفية',
        ep: '/robots.txt', evidence: [`GET /robots.txt → HTTP ${r.status}`, ...dis, sm ? 'Sitemap: ' + sm : ''].filter(Boolean) };
    }
    return null;
  },

  // 20) TRACE مفتوح (Cross-Site Tracing)
  async traceMethod(base) {
    const r = await req(base + '/', { method: 'TRACE' }, 5000);
    if (r.ok && r.status === 200)
      return { k: 'trace-open', sev: 'medium', title: 'طريقة TRACE مفتوحة (XST)',
        ep: 'HTTP TRACE /', evidence: ['TRACE / → HTTP ' + r.status, 'الخادم يعيد echo للطلب — يسمح بسرقة كوكيز HttpOnly عبر XST'] };
    return null;
  },

  // 22) CORS متقدم: wildcard * مع الاعتمادات، انعكاس النطاقات الفرعية غير الموثوقة
  async corsDeepCheck(base) {
    const probes = [
      { label: 'wildcard', origin: 'https://reasonix-wildcard-check.invalid' },
      { label: 'subdomain', origin: `https://evil-${new URL(base).hostname.replace(/[^a-z0-9]/giu, '')}.reasonix-subdomain-check.invalid` },
    ];
    for (const probe of probes) {
      const r = await req(base + '/', { headers: { Origin: probe.origin } }, 6000);
      if (!r.ok) continue;
      const acao = String(r.headers['access-control-allow-origin'] || '').trim();
      const acac = /^true$/iu.test(String(r.headers['access-control-allow-credentials'] || '').trim());
      if (!acao || !acac) continue;
      if (acao === '*')
        return { k: 'cors-misconfig', sev: 'high', cwe: 'CWE-942', cvss: 7.4, title: 'CORS: Access-Control-Allow-Origin: * مع Allow-Credentials: true',
          desc: 'المتصفح يرفض فعلياً هذه التركيبة، لكن وجودها يؤشر على إعداد CORS متساهل؛ لو حُوّلت إلى انعكاس Origin لاحقاً ستصبح قابلة للاستغلال لسرقة بيانات اعتماد متطابقة عبر مواقع أخرى.',
          ep: '/', evidence: [`GET / مع Origin: ${probe.origin} → HTTP ${r.status}`, `Access-Control-Allow-Origin: ${acao}`, 'Access-Control-Allow-Credentials: true'] };
      if (acao === probe.origin && probe.label === 'subdomain')
        return { k: 'cors-misconfig', sev: 'high', cwe: 'CWE-942', cvss: 7.4, title: 'CORS: انعكاس نطاق فرعي غير موثوق مع الاعتمادات',
          desc: 'الخادم يعكس Origin غير موثوق تماماً ويُصدّق اعتماداته — يسمح لأي موقع بقراءة الردود المميزة (Authenticated responses) باسم ضحية عبر تخصيص subdomain تحكمي.',
          ep: '/', evidence: [`GET / مع Origin: ${probe.origin} → HTTP ${r.status}`, `Access-Control-Allow-Origin: ${acao} (منعكس)`, 'Access-Control-Allow-Credentials: true'] };
    }
    return null;
  },

  // 23) CSP متقدم: wildcards ومصادر HTTP/خارجية غير آمنة في script-src
  async cspAdvanced(base) {
    const r = await req(base + '/', {}, 7000);
    if (!r.ok) return null;
    const csp = String(r.headers['content-security-policy'] || '');
    if (!csp) return null;
    const scripts = [...csp.matchAll(/(?:^|;)\s*script-src\s+([^;]+)/giu)].map(match => match[1].trim());
    const problems = [];
    for (const list of scripts) {
      const sources = list.split(/\s+/u);
      for (const source of sources) {
        if (source === '*' || /^\*\./iu.test(source)) problems.push(`wildcard source: ${source}`);
        else if (/^https?:\/\/(?:[0-9.]+|[^/]*\.invalid)/iu.test(source)) problems.push(`hardcoded untrusted host: ${source}`);
        else if (/^http:\/\//iu.test(source)) problems.push(`insecure (plaintext HTTP) source: ${source}`);
      }
    }
    if (!problems.length) return null;
    return { k: 'csp-wildcard', sev: 'medium', cwe: 'CWE-79', cvss: 5.4, title: 'CSP: مصادر script غير مقيدة',
      desc: 'سياسة CSP تسمح بمصادر wildcards أو plain-HTTP في script-src؛ أي مهاجم يستطيع السيطرة على مسار داخل هذه النطاقات يحقن سكربتات دائمة (Stored script injection).',
      ep: 'HTTP response headers', evidence: [`GET / → HTTP ${r.status}`, 'Content-Security-Policy: ' + csp.slice(0, 300), ...problems.slice(0, 8).map(p => 'مصدر مشكوك فيه: ' + p)] };
  },

  // 24) أسرار مسرّبة في ملفات JavaScript الخاصة بالواجهة (تحليل ثابت آمن ومُموَّه)
  async jsSecretScan(base) {
    const page = await req(base + '/', {}, 7000);
    if (!page.ok) return null;
    const srcs = [...page.body.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/giu)]
      .map(match => match[1]).filter(raw => { try { return new URL(raw, base).origin === new URL(base).origin; } catch { return false; } }).slice(0, 6);
    const bodies = [page.body];
    for (const src of srcs) {
      const r = await req(new URL(src, base).href, {}, 8000);
      if (r.ok && r.body.length < 400_000) bodies.push(r.body);
    }
    const patterns = [
      { label: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/u, severity: 'critical' },
      { label: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/u, severity: 'high' },
      { label: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u, severity: 'critical' },
      { label: 'JWT secret/token', re: /\bey(?:J[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,})\.[A-Za-z0-9_-]{10,}/u, severity: 'medium' },
      { label: 'Hardcoded credential literal', re: /(?:api[_-]?key|apikey|client[_-]?secret|auth[_-]?token)\s*[:=]\s*["'][A-Za-z0-9._~+/=-]{16,}["']/iu, severity: 'medium' },
      { label: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/u, severity: 'high' },
    ];
    const hits = [];
    for (const body of bodies) {
      for (const pattern of patterns) {
        const match = body.match(pattern.re);
        if (match) hits.push({ label: pattern.label, severity: pattern.severity, excerpt: `${String(match[0]).slice(0, 4)}…[REDACTED]` });
      }
    }
    if (!hits.length) return null;
    const worst = hits.some(hit => hit.severity === 'critical') ? 'critical' : hits.some(hit => hit.severity === 'high') ? 'high' : 'medium';
    return { k: 'js-secret-leak', sev: worst, cwe: 'CWE-798', cvss: worst === 'critical' ? 9.1 : 7.4, title: 'أسرار أو مفاتيح مكشوفة في JavaScript الواجهة',
      desc: 'تحليل ثابت لملفات JS المُقدَّمة للعميل رصد أنماط مفاتيح/توكنات. القيم مُموَّهت عمداً؛ تدوير المفتاح إلزامي لأن أي شيء وصل للمتصفح يُعتبر مكشوفاً.',
      ep: srcs.length ? srcs[0] : '/', evidence: ['تحليل ثابت لـ ' + bodies.length + ' ملف/مصدر JS (بدون أي إرسال حمولات)',
        ...hits.slice(0, 8).map(hit => `${hit.label}: ${hit.excerpt}`)],
      note: 'القيم الحقيقية لا تُخزَّن ولا تُعاد؛ فقط نوع النمط ومقتطف مموّه.' };
  },

  // 25) تدقيق معالجة الأخطاء: كشف تسرب Stack Traces/مسارات/إصدارات
  async errorHandlingAudit(base) {
    const marker = crypto.randomUUID();
    const probes = [
      `${base}/?reasonix-error-probe=${marker}`,
      `${base}/${encodeURIComponent(`'${marker}`)}`,
      `${base}/?reasonix-error-probe%5B%5D=${marker}`,
    ];
    const leakPatterns = [
      { label: 'Stack trace', re: /(?:Traceback \(most recent call last\)|at [\w$.]+ \([^)]*:\d+:\d+\)|#\d+\s+\S+\.\w+\(\S*\.(?:php|py|js|rb))\b/u },
      { label: 'مسار نظام داخلي', re: /(?:[A-Z]:\\(?:Users|Windows|inetpub|www)[\\\w .]+|\/home\/\w+|\/var\/www\/[\w/-]+|\/app\/[\w/-]+)/u },
      { label: 'إصدار إطار/DB', re: /(?:Express\s+v?\d+\.\d+|Django\s+\d+\.\d+|Laravel\s+\d+\.\d+|MySQL\s+\d+\.\d+|PostgreSQL\s+\d+\.\d+|PHP\s+\d+\.\d+\.\d+)/u },
      { label: 'تفاصيل استثناء', re: /(?:PDOException|SQLSTATE\[[A-Z0-9]+\]|mysqli?_[a-z_]+\(\)|org\.hibernate\.|NullPointer(?:Exception)?\b)/u },
    ];
    for (const probeUrl of probes) {
      const r = await req(probeUrl, {}, 6000);
      if (!r.ok) continue;
      const found = leakPatterns.filter(pattern => pattern.re.test(r.body));
      if (found.length)
        return { k: 'error-handling-leak', sev: 'medium', cwe: 'CWE-209', cvss: 5.0, title: 'تسرب معلومات تقنية في رسائل الخطأ',
          desc: 'طلب غير صالح (علامة فريدة غير ضارة) أُعيدت استجابته وتضم تفاصيل تقنية — المهاجم يستخدمها لتخصيص الهجمات. لا شيء مُستخرج من قاعدة بيانات ولا أُرسلت حمولات.',
          ep: new URL(probeUrl).pathname + '?reasonix-error-probe=[marker]', evidence: [`GET ${new URL(probeUrl).pathname} → HTTP ${r.status}`,
            ...found.map(pattern => 'نمط مسرّب: ' + pattern.label), 'مقتطف: ' + r.body.slice(0, 160).replace(/\s+/gu, ' ')] };
    }
    return null;
  },

  // 21) النسخ الاحتياطية وأرشيفات المصدر
  async backups(base) {
    for (const f of ['/backup.zip', '/site.zip', '/www.zip', '/web.zip', '/dump.sql.gz', '/database.sql', '/.svn/entries', '/.DS_Store']) {
      const r = await req(base + f, { headers: { Range: 'bytes=0-200' } }, 6000);
      if (r.ok && r.status === 200 && r.body.length > 10)
        return { k: 'backup-exposed', sev: 'high', title: 'نسخة احتياطية/أرشيف مكشوف — ' + f,
          ep: f, evidence: [`GET ${f} → HTTP ${r.status} (${r.headers['content-length'] || '?'} bytes)`, 'النوع: ' + (r.headers['content-type'] || 'غير محدد')] };
    }
    return null;
  },
});

/* ---------------- بيانات الثغرات الحقيقية (CWE/CVSS/وصف/إصلاح) ---------------- */
const REALMETA = {
  'admin-exposed': { cwe: 'CWE-1188', cvss: 8.2, desc: 'لوحة إدارة أو واجهة خدمة إدارية متاحة للعامة عبر HTTP. هذا يوسع سطح الهجوم ويجعل كلمات السر وثغرات اللوحات مستهدفة مباشرة من الإنترنت.',
    fix: ['اقصر الوصول على شبكة داخلية أو VPN/قائمة IP.','فرض مصادقة قوية + 2FA على مسارات الإدارة.','أخفِ المسارات وأضف قواعد deny في الـ reverse proxy.'], ai: 'لوحة إدارة مكشوفة مؤكدة من استجابة HTTP فعلية — أولوية عالية للإغلاق.' },
  'sensitive-file': { cwe: 'CWE-538', cvss: 9.1, desc: 'ملف يحتوي أسراراً أو إعدادات (بيئات، مفاتيح، قواعد بيانات) قابل للتنزيل عبر الويب.',
    fix: ['احذف الملف من جذر الويب فوراً ودوّر كل الأسرار المكشوفة فيه.','أضف قواعد حجب (deny) لكل الملفات النقطية والنسخ في الخادم.','افحص سجلات الوصول لتحديد من حمّله.'], ai: 'ملف أسرار مكشوف — تدوير المفاتيح إلزامي وليس اختيارياً.' },
  'missing-headers': { cwe: 'CWE-693', cvss: 5.3, desc: 'ترويسات أمان HTTP غير مضبوطة، ما يرفع خطورة XSS/Clickjacking/MIME-sniffing على المتصفح.',
    fix: ['أضف: Strict-Transport-Security، Content-Security-Policy، X-Content-Type-Options، X-Frame-Options، Referrer-Policy.','ابدأ بـ CSP وضعية Report-Only قبل الإلزام.'], ai: 'ترويسات غائبة مؤكدة من الاستجابة — إصلاح بتكوين الخادم فقط.' },
  'cors-misconfig': { cwe: 'CWE-942', cvss: 7.4, desc: 'سياسة CORS متساهلة (wildcard أو انعكاس Origin مع الاعتمادات) تسمح لمواقع أخرى بقراءة الردود المميزة باسم الضحية.',
    fix: ['قيّد Access-Control-Allow-Origin إلى قائمة نطاقات موثوقة صريحة.','لا تدمج أبداً Allow-Credentials مع wildcard أو انعكاس Origin عشوائي.','تحقق من سياسة النطاقات الفرعية قبل استخدام wildcard الفرعيات.'], ai: 'إعداد CORS خطير مؤكد من استجابة فعلية لطلب GET ضابط — أغلق الانعكاس فوراً.' },
  'csp-wildcard': { cwe: 'CWE-79', cvss: 5.4, desc: 'script-src يسمح بـ wildcards أو مصادر plain-HTTP، ما يمكّن حقن سكربتات عبر أي مضيف مسيطر عليه داخل النطاق المسموح.',
    fix: ['استبدل wildcards بقائمة نطاقات صريحة (allowlist).','استخدم مصادر HTTPS حصراً وفقّر النطاقات إلى نسخ محلية كلما أمكن.','أضف nonces أو hashes بدلاً من قوائم مضيفين واسعة.'], ai: 'CSP واسع مؤكد من الترويسات — قلّصه ليطابق مصادر الموارد الفعلية فقط.' },
  'js-secret-leak': { cwe: 'CWE-798', cvss: 9.1, desc: 'مفاتيح أو توكنات مضمّنة في JavaScript يوصلها الخادم للمتصفح؛ أي مستخدم (أو آلي) يستطيع استخراجها.',
    fix: ['دوّر جميع المفاتيح المكتشفة فوراً.','انقل الأسرار إلى خادم خلفي واستخدم بروكسي API بدل تضمينها في الواجهة.','أضف فحص أسرار إلى CI لمنع التسرب مستقبلاً.'], ai: 'أسرار في الواجهة مكشوفة — الدوران إلزامي وليس اختيارياً.' },
  'error-handling-leak': { cwe: 'CWE-209', cvss: 5.0, desc: 'رسائل الخطأ تكشف مسارات النظام أو إصدارات الإطارات أو تتبعات المكدس، فيختصر وقت المهاجم في التخطيط.',
    fix: ['أرجع صفحات خطأ عامة (404/500 generic) للمستخدم النهائي.','سجّل التفاصيل التقنية في logs الخادم فقط وأطفئ debug في الإنتاج.','أضف معالجات أخطاء مركزية تمنع تمرير الاستثناءات الخام.'], ai: 'تسرب معلومات من معالجة الأخطاء مؤكد — أطفئ الإظهار التفصيلي في الإنتاج.' },
  'server-version': { cwe: 'CWE-200', cvss: 3.1, desc: 'كشف إصدار الخادم أو التقنية يسمح بمطابقة الثغرات المعروفة (CVE) بدقة.',
    fix: ['خفّض server_tokens (nginx) أو ServerTokens Prod (Apache).','أزل X-Powered-By.'], ai: 'معلومة إصبعية صغيرة لكنها تختصر بحث المهاجم.' },
  'platform-fingerprint': { cwe: 'CWE-200', cvss: 3.5, desc: 'المنصة/CMS مطابقة من بصمات HTML — يساعد في توجيه فحص إضافاتها المعروفة.',
    fix: ['أزل علامات الإصدار من القوالب.','راقب إعلانات أمان المنصة وحدّث فوراً.'], ai: 'بصمة منصة حقيقية — حدّث مكوناتها فوراً.' },
  'tls-expiring': { cwe: 'CWE-298', cvss: 5.0, desc: 'شهادة TLS قاربت أو تجاوزت نهاية صلاحيتها — المستعرضات سترفض الاتصال.',
    fix: ['جدّد الشهادة الآن (ACME/Let\'s Encrypt مع تجديد آلي).','راقب الصلاحية برصد آلي.'], ai: 'انتهاء وشيك مؤكد من نطاق الشهادة نفسها.' },
  'open-ports': { cwe: 'CWE-1188', cvss: 5.0, desc: 'خدمات غير ويب مكشوفة على الإنترنت (قواعد بيانات، إدارة عن بُعد…).',
    fix: ['اقفل المنافذ بجدار ناري واقصرها على نطاقات موثوقة.','لا تُعرض قواعد بيانات/كاش للإنترنت مطلقاً.'], ai: 'منافذ خدمية مكشوفة مؤكدة بمصافحة TCP فعلية.' },
  'http-methods': { cwe: 'CWE-650', cvss: 5.4, desc: 'طرق HTTP خطيرة (PUT/DELETE/TRACE…) مسموحة وقد تسمح برفع/حذف محتوى.',
    fix: ['اقصر الطرق على GET/POST/HEAD في تكوين الخادم.','عطّل TRACE دائماً.'], ai: 'سلوك مؤكد من استجابة OPTIONS فعلية.' },
  'dir-listing': { cwe: 'CWE-548', cvss: 5.3, desc: 'عرض محتويات دليل يكشف ملفات ومسارات داخلية للتنزيل المباشر.',
    fix: ['أطفئ autoindex/Directory Browsing.','أعد توجيه الأدلة إلى 403.'], ai: 'قائمة دليل مؤكدة من عنوان الصفحة الفعلي.' },
  'api-exposed': { cwe: 'CWE-1059', cvss: 4.3, desc: 'توثيق أو نقاط API إدارية مكشوفة دون مصادقة.',
    fix: ['فعّل المصادقة على نقاط الوثائق والإنتاج.','أطفئ actuator/swagger في بيئة الإنتاج.'], ai: 'استجابة JSON حقيقية من نقطة مكشوفة — قصرها على الشبكة الداخلية.' },
  'cookie-flags': { cwe: 'CWE-1004', cvss: 5.5, desc: 'كوكيز الجلسة بلا Secure/HttpOnly/SameSite — قابلة للسرقة عبر XSS أو الإرسال عبر HTTP.',
    fix: ['أضف: Secure; HttpOnly; SameSite=Lax لكل كوكيز الجلسة.','فعّل HSTS حتى لا يُرسل الكوكي عبر HTTP.'], ai: 'سمات ناقصة مؤكدة من ترويسات Set-Cookie الفعلية.' },
  'cors-open': { cwe: 'CWE-942', cvss: 6.5, desc: 'الخادم يعكس أي Origin أو يسمح * — أي موقع يمكنه قراءة استجابات API باسم المستخدم.',
    fix: ['قائمة بيضاء صريحة للنطاقات.','لا تعكس Origin أبدًا مع Allow-Credentials.'], ai: 'انعكاس Origin مؤكد باختبار فعلي — أغلق القائمة البيضاء.' },
  'tls-legacy': { cwe: 'CWE-327', cvss: 7.4, desc: 'الخادم يقبل بروتوكولات TLS قديمة قابلة للكسر (POODLE/BAR-MITZVAH).',
    fix: ['اقصر على TLS 1.2+ و 1.3 فقط.','أزل الشفرات الضعيفة.'], ai: 'اتصال TLS قديم ناجح فعلياً — إغلاق فوري.' },
  'email-spoofing': { cwe: 'CWE-290', cvss: 5.8, desc: 'غياب SPF/DMARC يسمح بانتحال نطاقك في الرسائل (تصيّد باسمك).',
    fix: ['أضف سجل SPF يحدد المرسلين الشرعيين.','أضف DMARC p=quarantine ثم p=reject.','فكّر في DKIM أيضاً.'], ai: 'غياب مؤكد عبر استعلام DNS حقيقي.' },
  'subdomain-osint': { cwe: 'CWE-200', cvss: 2.0, desc: 'شهادات TLS العامة كشفت نطاقات فرعية — سطح هجوم موثّق.',
    fix: ['راجع كل نطاق فرعي: مملوك ومؤمّن أم مهجور؟','راقب CT logs لنطاقك.'], ai: 'بيانات CT حقيقية — استخدمها لجرد الأصول.' },
  'waf-detected': { cwe: 'CWE-200', cvss: 0.0, desc: 'كشف طبقة WAF/CDN أمام الهدف (معلومة، ليست ثغرة).',
    fix: ['إن وُجد WAF: اضبط قواعد وضع الحجب.','إن لم يوجد: أضف طبقة حماية أمامية.'], ai: 'من ترويسات الاستجابة الفعلية.' },
  'info-file': { cwe: 'CWE-200', cvss: 4.0, desc: 'ملف معلومات (phpinfo/قفل تبعيات) يكشف إصدارات ومسارات النظام.',
    fix: ['احذف ملفات phpinfo من الإنتاج.','أضف قواعد حجب للملفات التقنية.'], ai: 'محتوى حقيقي مُثبت من الاستجابة.' },
  'input-reflection': { cwe: 'CWE-79', cvss: 6.1, desc: 'مدخل المستخدم يعود في الاستجابة دون ترميز — بيئة محتملة لـ XSS (يحتاج تحقق سياق يدوي).',
    fix: ['رمّز المخرجات حسب السياق (HTML/attr/JS).','أضف CSP يمنع inline scripts.','تحقق يدوياً من سياق الانعكاس قبل تصنيفه XSS مؤكد.'], ai: 'انعكاس مؤكد بعلامة فريدة — بلا أي حمولة هجومية.' },
  'robots-exposure': { cwe: 'CWE-538', cvss: 2.0, desc: 'robots.txt يعلن مسارات يفترض أنها مخفية.',
    fix: ['لا تعتمد على robots.txt كسر — الحجب فعلي بالخادم.','أزل مسارات الإدارة منه.'], ai: 'ملف حقيقي مُحلل.' },
  'trace-open': { cwe: 'CWE-650', cvss: 5.4, desc: 'TRACE مفتوح يتيح XST لتجاوز HttpOnly مع سكربتات قديمة.',
    fix: ['عطّل TRACE في الخادم.'], ai: 'سلوك مؤكد باستجابة فعلية.' },
  'backup-exposed': { cwe: 'CWE-530', cvss: 8.6, desc: 'أرشيف/نسخة احتياطية للموقع أو قاعدة البيانات قابلة للتنزيل — كود مصدري وأسرار كاملة.',
    fix: ['احذف من جذر الويب فوراً ونقلها لتخزين خاص.','افحص محتواها لأسرار ودوّرها.'], ai: 'وجود مؤكد بـ HTTP 200 فعلي — تدوير الأسرار إلزامي.' },
};

const REMEDIATION_EXAMPLES = {
  'missing-headers': {
    language: 'Node.js / Express',
    vulnerableCode: "// Illustrative: security headers are not configured.",
    remediatedCode: "app.use((req, res, next) => {\n  res.setHeader('X-Content-Type-Options', 'nosniff');\n  res.setHeader('X-Frame-Options', 'DENY');\n  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');\n  res.setHeader('Content-Security-Policy', \"default-src 'self'; object-src 'none'; frame-ancestors 'none'\");\n  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');\n  next();\n});",
    note: 'Illustrative configuration, not source code retrieved from the target. Validate CSP directives and HTTPS/proxy settings before deployment.',
  },
  'cookie-flags': {
    language: 'Node.js / Express',
    vulnerableCode: "res.cookie('session', sessionId);",
    remediatedCode: "res.cookie('session', sessionId, {\n  httpOnly: true,\n  secure: process.env.NODE_ENV === 'production',\n  sameSite: 'lax',\n  path: '/',\n});",
    note: 'Illustrative only. Select SameSite and cookie scope according to the application flow; do not store session identifiers in JavaScript-accessible storage.',
  },
  'cors-open': {
    language: 'Node.js / Express',
    vulnerableCode: "app.use(cors({ origin: '*' }));",
    remediatedCode: "const allowedOrigins = new Set(['https://app.example.com']);\napp.use(cors({\n  origin(origin, callback) {\n    if (!origin || allowedOrigins.has(origin)) return callback(null, true);\n    return callback(new Error('Origin is not allowed'));\n  },\n  credentials: true,\n}));",
    note: 'Illustrative only. Replace the example origin with an explicit server-side allowlist; never combine credentialed requests with a wildcard origin.',
  },
  'input-reflection': {
    language: 'Browser JavaScript',
    vulnerableCode: "element.innerHTML = userSuppliedValue;",
    remediatedCode: "element.textContent = userSuppliedValue;",
    note: 'Illustrative only. If rich HTML is required, use a vetted sanitizer and context-appropriate output encoding.',
  },
  'admin-exposed': {
    language: 'Node.js / Express',
    vulnerableCode: "app.get('/admin', renderAdminDashboard);",
    remediatedCode: "app.get('/admin', requireAuthenticatedUser, requireAdminRole, renderAdminDashboard);",
    note: 'Illustrative only. Implement server-side authentication/authorization and restrict administrative access at the network edge where practical.',
  },
  'sensitive-file': {
    language: 'Nginx',
    vulnerableCode: "# Sensitive configuration or backup files are served from the web root.",
    remediatedCode: "location ~* (^|/)(\\.env|\\.git|.*\\.(?:sql|bak|old|zip))$ {\n  deny all;\n  return 404;\n}",
    note: 'Illustrative only. Move secrets and backups outside the document root; access rules are defense in depth, not a substitute.',
  },
  'backup-exposed': {
    language: 'Nginx',
    vulnerableCode: "# A backup archive is located under the public document root.",
    remediatedCode: "location ~* \\.(?:sql|bak|old|zip|tar|gz)$ {\n  deny all;\n  return 404;\n}",
    note: 'Illustrative only. Remove exposed copies, rotate any contained credentials, and review access logs.',
  },
  'server-version': {
    language: 'Node.js / Express',
    vulnerableCode: "app.use(express.static('public')); // Framework-identifying headers may remain enabled.",
    remediatedCode: "app.disable('x-powered-by');\napp.use(express.static('public'));",
    note: 'Illustrative only. Suppressing banners reduces disclosure but does not replace patching or hardening.',
  },
  'dir-listing': {
    language: 'Nginx',
    vulnerableCode: "autoindex on;",
    remediatedCode: "autoindex off;",
    note: 'Illustrative only. Also remove private files from public directories and verify authorization on downloads.',
  },
  'http-methods': {
    language: 'Node.js / Express',
    vulnerableCode: "// The server accepts methods without an application allowlist.",
    remediatedCode: "app.use((req, res, next) => {\n  const allowed = new Set(['GET', 'HEAD', 'POST', 'OPTIONS']);\n  if (!allowed.has(req.method)) return res.sendStatus(405);\n  next();\n});",
    note: 'Illustrative only. Preserve methods required by the application and enforce authorization on every state-changing route.',
  },
  'sql-injection': {
    language: 'Node.js / PostgreSQL',
    vulnerableCode: "const query = `SELECT * FROM users WHERE email = '${email}'`;\nconst result = await db.query(query);",
    remediatedCode: "const result = await db.query(\n  'SELECT * FROM users WHERE email = $1',\n  [email],\n);",
    note: 'Illustrative only. Use parameterized queries for values; allowlist identifiers such as table names and sort directions.',
  },
  xss: {
    language: 'Browser JavaScript',
    vulnerableCode: "element.innerHTML = userSuppliedValue;",
    remediatedCode: "element.textContent = userSuppliedValue;",
    note: 'Illustrative only. If rich HTML is required, use a vetted sanitizer and context-appropriate output encoding.',
  },
  ssrf: {
    language: 'Node.js',
    vulnerableCode: "const response = await fetch(req.query.url);",
    remediatedCode: "const destination = new URL(req.query.url);\nif (!allowedHosts.has(destination.hostname)) {\n  throw new Error('Destination is not allowed');\n}\nconst response = await fetch(destination, { redirect: 'error' });",
    note: 'Illustrative only. Enforce destination allowlists after DNS resolution, block private/loopback ranges at the network layer, and revalidate redirects.',
  },
};

export function remediationGuideFor(finding) {
  const key = String(finding.k || '').toLowerCase();
  const exampleKey = /(?:sql.?injection|sqli|sqlmap)/u.test(key) ? 'sql-injection'
    : /(?:xss|cross.site.scripting|reflected)/u.test(key) ? 'xss'
      : /(?:ssrf)/u.test(key) ? 'ssrf'
        : /(?:missing.*headers|security.?headers)/u.test(key) ? 'missing-headers'
          : /(?:cookie.?flags|insecure.?cookie)/u.test(key) ? 'cookie-flags'
            : /(?:cors)/u.test(key) ? 'cors-open'
              : /(?:sensitive.?file|exposed.?file)/u.test(key) ? 'sensitive-file'
                : /(?:backup.?exposed)/u.test(key) ? 'backup-exposed'
                  : /(?:admin.?exposed)/u.test(key) ? 'admin-exposed'
                    : /(?:directory.?listing|dir.?listing)/u.test(key) ? 'dir-listing'
                      : /(?:http.?methods|trace.?open)/u.test(key) ? 'http-methods'
                        : /(?:server.?version)/u.test(key) ? 'server-version' : key;
  const code = REMEDIATION_EXAMPLES[exampleKey];
  if (finding.sourceCode || finding.fixedCode) {
    return {
      source: 'source-derived',
      language: finding.language || 'Source code',
      vulnerableCode: String(finding.sourceCode || '').slice(0, 4000),
      remediatedCode: String(finding.fixedCode || '').slice(0, 4000),
      note: 'Source snippet supplied with this finding. Review the proposed change in the application context before applying.',
    };
  }
  if (code) return { source: 'illustrative', ...code };
  return {
    source: 'guidance-only',
    language: '',
    vulnerableCode: '',
    remediatedCode: '',
    note: 'No affected source code was available from this black-box observation. Use the remediation steps and inspect the relevant application code manually.',
  };
}

/* ---------------- إثراء النتائج بالبيانات الكاملة + منع الازدواج ---------------- */
let __enrichReady = false;
let __scanImpl = null;
function scan(target, onProgress, profile = 'full') {
  const normalizedTarget = normalizeScanTarget(target);
  const targetOrigin = normalizedTarget ? new URL(normalizedTarget).origin : '';
  const parent = currentScanOptions();
  if (requiresActiveConfirmation(profile) && !parent.activeTestsConfirmed)
    throw new Error('active-test-confirmation-required');
  return SCAN_CONTEXT.run({
    ...parent,
    signal: currentScanSignal(),
    targetOrigin,
    targetUrl: normalizedTarget,
  }, () => __scanImpl(target, onProgress, profile));
}async function enrichAndRun(target, onProgress, profile = 'full') {
  const out = await __origScanImpl(target, onProgress, profile);
  out.findings = out.findings.map(f => ({
    ...f,
    cwe: REALMETA[f.k]?.cwe || 'CWE-200',
    cvss: REALMETA[f.k]?.cvss ?? 5,
    desc: REALMETA[f.k]?.desc || 'كشف حقيقي من استجابات الهدف الفعلية.',
    fix: REALMETA[f.k]?.fix || ['راجع الدليل أعلاه وعالج السبب الجذري.'],
    ai: REALMETA[f.k]?.ai || 'نتيجة مأخوذة من استجابات الهدف فعلياً.',
    remediationGuide: remediationGuideFor(f),
    real: true,
  })).sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 }[a.sev] - { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[b.sev]));
  out.counts = out.findings.reduce((c, f) => (c[f.sev] = (c[f.sev] || 0) + 1, c), {});
  out.engine = 'reasonix-live-probe v3.0 (HTTP/TLS/DNS/OSINT + Kali tool layer)';
  return out;
}
__scanImpl = enrichAndRun;
__enrichReady = true;

/* ======================================================================
   v3 — طبقة الأدوات الحقيقية (مثل Kali): اكتشاف الأدوات المثبتة وتشغيلها
   فعلياً على الهدف، ودمج مخرجاتها في التقرير. الأداة غير المثبتة تُذكر
   بحالتها مع أمر التثبيت — لا تُختلق نتائج أبدًا.
   ====================================================================== */
import { execFile } from 'node:child_process';

const TOOL_DEFS = [
  { id: 'autonomous-crawler', bin: 'reasonix-autonomous-crawler', timeout: 30000, args: () => [],
    note: 'Bounded anonymous/same-origin GET crawling; reads links, sitemap and JavaScript literals, catalogs forms without submitting them, and respects access restrictions.' },
  { id: 'nmap', bin: 'nmap', timeout: 600000, args: nmapArgs,
    note: 'فحص محدود لأكثر 100 منفذ، إصدارات الخدمات، وسكربتات NSE المصنفة safe؛ لا يعد المنفذ المفتوح ثغرة.' },
  { id: 'nikto', bin: 'nikto', timeout: 300000, args: t => ['-config', path.join(TOOLS_DIR, 'nikto', 'program', 'nikto.conf.default'), '-h', target(t), '-nointeractive', '-Tuning', 'xb'],
    note: 'فحص إعدادات الخادم والملفات الخطرة' },
  { id: 'sqlmap', bin: 'sqlmap-api', timeout: 120000, args: () => [],
    note: 'SQLmap REST API — runs in the Deep profile after explicit active-test confirmation, only on parameterized same-origin URLs; bounded Boolean/Error/Union checks and no database extraction.' },
  { id: 'zap', bin: 'zap-api', timeout: 150000, args: () => [],
    note: 'OWASP ZAP local API — opt-in same-origin spider and passive scan only; active scan is not run.' },
  { id: 'heuristic-fuzzer', bin: 'reasonix-heuristic-fuzzer', timeout: 30000, args: () => [],
    note: 'Opt-in only in Deep profile: sequential benign GET probes; stops on 401, 403, 429, or 5xx and never attempts bypass or extraction.' },
  { id: 'nuclei', bin: 'nuclei', timeout: 600000, args: t => ['-u', target(t), '-silent', '-jsonl', '-omit-raw', '-severity', 'low,medium,high,critical', '-rate-limit', '10', '-no-interactsh', '-nc'],
    note: 'فحص القوالب للثغرات' },
  { id: 'whatweb', bin: 'whatweb', timeout: 90000, args: t => ['--no-errors', '-q', target(t)],
    note: 'بصمة التقنيات' },
  { id: 'gobuster', bin: 'gobuster', timeout: 180000, args: t => ['dir', '-u', target(t), '-w', '-', '-q'],
    note: 'اكتشاف المسارات (يتطلب قائمة كلمات stdin)', stdin: 'admin\nbackup\nuploads\napi\nconfig\n.git\n.env\nlogin\n' },
  { id: 'ffuf', bin: 'ffuf', timeout: 90000, args: t => ['-u', `${target(t).replace(/\/+$/, '')}/FUZZ`, '-w', '-', '-rate', '5', '-noninteractive', '-json'],
    note: 'تعداد مسارات محدود السرعة؛ يراعي حالة 401/403 ولا يحاول تخطي التحكم بالوصول.',
    stdin: 'admin\nbackup\nuploads\napi\nconfig\n.git\n.env\nlogin\n' },
  { id: 'wfuzz', bin: 'wfuzz', timeout: 90000, args: t => ['--hc', '404', '-t', '2', '-z', 'list,admin-backup-uploads-api-config-login', `${target(t).replace(/\/+$/, '')}/FUZZ`],
    note: 'اكتشاف مسارات ويب بقائمة قصيرة ومحدودة للهدف الموثّق.' },
  { id: 'testssl', bin: 'testssl.sh', timeout: 300000, args: t => ['--quiet', '--fast', '--warnings', 'off', authority(t)],
    note: 'تدقيق TLS معمّق' },
  { id: 'sslscan', bin: 'sslscan', timeout: 90000, args: t => [authority(t)],
    note: 'اختبار التشفيرات والبروتوكولات' },
  { id: 'wafw00f', bin: 'wafw00f', timeout: 90000, args: t => [target(t)],
    note: 'كشف WAF' },
  { id: 'httpx', bin: 'httpx', timeout: 90000, args: t => ['-u', target(t), '-title', '-tech-detect', '-status-code', '-no-color'],
    note: 'تحقق الويب وتقنياته' },
  { id: 'subfinder', bin: 'subfinder', timeout: 180000, args: t => ['-d', host(t), '-silent'],
    note: 'اكتشاف النطاقات الفرعية' },
  { id: 'theharvester', bin: 'theHarvester', timeout: 180000, args: t => ['-d', host(t), '-b', 'crtsh', '-l', '100'],
    note: 'Passive subdomain and certificate lookup using public sources.' },
  { id: 'sublist3r', bin: 'sublist3r', timeout: 180000, args: t => ['-d', host(t), '-t', '5', '-n'],
    note: 'Passive subdomain enumeration.' },
  { id: 'amass', bin: 'amass', timeout: 180000, args: t => ['enum', '-d', host(t), '-passive', '-timeout', '10'],
    note: 'Passive attack-surface discovery (Amass v3, self-contained); bounded to 3 minutes.' },
  { id: 'assetfinder', bin: 'assetfinder', timeout: 120000, args: t => ['--subs-only', host(t)],
    note: 'Passive subdomain discovery.' },
  { id: 'wapiti', bin: 'wapiti', timeout: 90000, args: t => ['-u', target(t), '--scope', 'url', '-m', 'csrf,ssl,wapp,methods', '--flush-session', '--max-links-per-page', '10', '--max-files-per-dir', '10', '--depth', '1', '--tasks', '2', '--verify-ssl', '1', '--no-bugreport', '-v', '0'],
    note: 'فحص Wapiti محدود للنطاق المقدم؛ وحدات CSRF/TLS/البصمة/HTTP methods فقط' },
];

/* الأدوات التي طلبها المستخدم. ما لا ينطبق على URL لا يُشغّل ولا يُسجّل كنتيجة فحص. */
const REQUESTED_TOOL_CATALOG = [
  ['mobsf','MobSF','artifact','docker','Android/iOS; requires local MobSF service and Docker.'],
  ['drozer','Drozer','artifact','drozer','Android dynamic testing; needs emulator/device and ADB.'],
  ['jadx','JADX','artifact','jadx','Decompile APK to Java; local artifact analysis.'],
  ['apktool','Apktool','artifact','apktool','Decode APK resources and Smali; needs Java.'],
  ['qark','QARK','artifact','qark','Legacy Android scanner; compatibility with current Python is limited.'],
  ['androguard','Androguard','artifact','androguard','Static APK analysis using Python.'],
  ['frida','Frida','artifact','frida','Dynamic instrumentation; needs matching device/emulator server.'],
  ['objection','Objection','artifact','objection','Dynamic mobile testing over Frida.'],
  ['radare2','Radare2','artifact','r2','Local binary reverse engineering.'],
  ['ghidra','Ghidra','artifact','analyzeHeadless','Reverse engineering; requires Java and Ghidra distribution.'],
  ['x64dbg','x64dbg','artifact','x64dbg','Windows x64 debugger; Windows only.'],
  ['masscan','Masscan','website','masscan','ماسح منافذ نشط سريع؛ غير مفعّل تلقائياً لتجنب إرسال حركة كثيفة.'],
  ['ffuf','ffuf','website','ffuf','مكتشف مسارات/معاملات نشط محدود المعدل.'],
  ['wfuzz','Wfuzz','website','wfuzz','اختبار مسارات/معاملات نشط؛ يحتاج قائمة كلمات ونطاقاً محدداً.'],
  ['theharvester','theHarvester','website','theHarvester','استطلاع OSINT سلبي؛ يحتاج مزودي بيانات/مفاتيح وقد يرسل اسم النطاق لمزود خارجي.'],
  ['sublist3r','Sublist3r','website','sublist3r','استطلاع نطاقات فرعية؛ ليس فحص ثغرات للصفحات.'],
  ['arachni','Arachni','website','arachni','يتطلب حزمة Arachni متوافقة؛ لم يُشغّل تلقائياً.'],
  ['wapiti','Wapiti','website','wapiti','فحص ويب ديناميكي نشط.'],
  ['wireshark','Wireshark','traffic','wireshark','تحليل حركة ملتقطة؛ يحتاج ملف PCAP أو واجهة شبكة وصلاحيات نظام.'],
  ['tcpdump','Tcpdump','traffic','tcpdump','التقاط حزم الشبكة؛ يحتاج واجهة وصلاحيات ولا يفحص موقعاً عبر URL.'],
  ['sqlmap','sqlmap','database','sqlmap','أداة اختبار SQL injection ذات قدرات استغلال؛ تحتاج endpoint وموافقة ونمطاً مضبوطاً.'],
  ['zap','OWASP ZAP','website','zap','OWASP ZAP local API; passive spidering only, active scanning is not enabled.'],
  ['clamav','ClamAV','artifact','clamscan','فحص ملفات محلية؛ يحتاج ملفات أو مجلدات كمدخل.'],
  ['trivy','Trivy','repository','trivy','يفحص ملفات المشروع والصور والبنية التحتية؛ لا يفحص URL وحده.'],
  ['grype','Grype','repository','grype','يفحص صور الحاويات وSBOM؛ لا يفحص URL وحده.'],
  ['trufflehog','TruffleHog','repository','trufflehog','يفحص المستودعات/الملفات بحثاً عن أسرار؛ لا يفحص URL وحده.'],
  ['checkov','Checkov','repository','checkov','يفحص ملفات IaC؛ لا يفحص URL وحده.'],
  ['lynis','Lynis','host','lynis','تدقيق نظام Linux محلي؛ بيئة الفحص الحالية ليست مضيف Linux.'],
  ['openscap','OpenSCAP','host','oscap','تدقيق امتثال نظام/صورة؛ يحتاج نظاماً أو صورة مدعومة.'],
  ['semgrep','Semgrep','repository','semgrep','تحليل ساكن لكود مصدر؛ يحتاج نسخة المستودع.'],
  ['bandit','Bandit','repository','bandit','تحليل كود Python؛ لا ينطبق على تطبيق Node.js كفحص URL.'],
  ['sonarqube','SonarQube','repository','sonar-scanner','تحليل كود يتطلب SonarQube server ومشروعاً مهيأً.'],
  ['dependency-check','OWASP Dependency-Check','repository','dependency-check','يفحص ملفات اعتماد المشروع؛ لا يفحص URL وحده.'],
  ['retirejs','Retire.js','repository','retire','يفحص اعتماديات JavaScript محلياً؛ لا يفحص URL وحده.'],
  ['sqlsus','SQLSus','database','sqlsus','أداة SQL injection قديمة؛ تحتاج endpoint قاعدة بيانات ونطاقاً محدداً.'],
  ['dbpwaudit','DBPwAudit','database','DBPwAudit','تدقيق كلمات مرور خدمات قواعد البيانات؛ يتطلب خدمة وبيانات اعتماد مصرح بها.'],
  ['nosqlmap','NoSQLMap','database','nosqlmap','اختبارات NoSQL نشطة؛ تتطلب عنوان قاعدة بيانات محدداً وموافقة.'],
  ['kiterunner','Kiterunner','website','kr','استكشاف API نشط؛ يحتاج API scope وقائمة routes.'],
  ['apicurio','Apicurio Registry','service','apicurio-registry','سجل مخططات/واجهات وليس ماسح ثغرات.'],
  ['restler','RESTler','website','restler','اختبار API توليدي نشط؛ يتطلب OpenAPI وصياغة اختبار للنطاق.'],
  ['aircrack-ng','Aircrack-ng','wireless','aircrack-ng','يتطلب محول Wi-Fi وبيانات التقاط؛ لا ينطبق على موقع ويب.'],
  ['kismet','Kismet','wireless','kismet','مراقبة لاسلكية تتطلب محولاً مدعوماً وصلاحيات.'],
  ['binwalk','Binwalk','artifact','binwalk','تحليل Firmware؛ يحتاج ملف Firmware.'],
  ['firmadyne','Firmadyne','artifact','firmadyne','محاكاة Firmware؛ تحتاج صورة Firmware وبيئة Linux مهيأة.'],
  ['volatility','Volatility','artifact','vol','تحليل ذاكرة؛ يحتاج dump ذاكرة.'],
  ['kube-hunter','Kube-hunter','infrastructure','kube-hunter','تقييم Kubernetes؛ يحتاج عنقوداً ونطاقاً مصرحاً.'],
  ['prowler','Prowler','infrastructure','prowler','تقييم إعدادات cloud؛ يحتاج حساباً/صلاحيات سحابية.'],
  ['gitleaks','Gitleaks','repository','gitleaks','يفحص ملفات ومستودعات Git بحثاً عن أسرار.'],
  ['amass','Amass','website','amass','استطلاع أصول/نطاقات؛ ليس فحص ثغرات HTTP وحده.'],
  ['assetfinder','Assetfinder','website','assetfinder','استطلاع نطاقات فرعية؛ ليس فحص ثغرات HTTP.'],
  ['safety','Safety','repository','safety','يفحص اعتماديات Python؛ المشروع المستهدف هنا Node.js.'],
  ['npm-audit','npm audit','repository','npm','يفحص package-lock محلياً، لا موقعاً بعيداً.'],
  ['yarn-audit','Yarn audit','repository','yarn','يفحص yarn.lock محلياً، لا موقعاً بعيداً.'],
  ['zeek','Zeek','traffic','zeek','تحليل PCAP/حركة الشبكة؛ يحتاج ملف التقاط.'],
  ['suricata','Suricata','traffic','suricata','IDS/تحليل PCAP؛ يحتاج ملف التقاط أو واجهة شبكة.'],
  // --- Web app / vulnerability scanning additions ---
  ['w3af','w3af','website','w3af','إطار فحص ثغرات ويب؛ نشط، يتطلب نطاقاً مصرحاً وملفاً إعدادات.'],
  ['skipfish','Skipfish','website','skipfish','ماسح ويب نشط من Google؛ crawls نشط، يتطلب scope مصرحاً.'],
  ['vega','Vega','website','vega','ماسح ويب GUI من Subgraph؛ يحتاج تشغيلاً رسومياً.'],
  ['burpsuite','Burp Suite Community','website','burpsuite','منصة اختبار ويب تفاعلية؛ تحتاج واجهة رسومية.'],
  ['xsstrike','XSStrike','website','xsstrike','فحص/استغلال XSS نشط؛ يتطلب endpoint وscope مصرحاً.'],
  ['commix','Commix','website','commix','اختبار command injection نشط؛ يتطلب endpoint مصدقاً.'],
  ['tplmap','Tplmap','website','tplmap','اختبار SSTI نشط؛ يتطلب endpoint مصدقاً.'],
  ['ssrfmap','SSRFmap','website','ssrfmap','اختبار SSRF نشط؛ يتطلب request مصدراً وscope مصرحاً.'],
  ['jaeles','Jaeles','website','jaeles','ماسح ثغرات ويب بـ Go signatures؛ نشط، يتطلب scope.'],
  // --- Path / file discovery additions ---
  ['feroxbuster','Feroxbuster','website','feroxbuster','تعداد مسارات recursive نشط؛ يتطلب scope وقائمة كلمات.'],
  ['dirsearch','Dirsearch','website','dirsearch','تعداد مسارات ويب نشط؛ يتطلب scope وقائمة.'],
  ['dirb','DIRB','website','dirb','تعداد مسارات ويب نشط (قديم)؛ يتطلب scope وقائمة.'],
  ['arjun','Arjun','website','arjun','اكتشاف معاملات HTTP مخفية؛ نشط، يتطلب endpoint مصدقاً.'],
  // --- Network / port scanning additions ---
  ['rustscan','RustScan','website','rustscan','ماسح منافذ سريع؛ يحتاج إذن صريح، نشط.'],
  ['unicornscan','Unicornscan','website','unicornscan','ماسح منافذ/بروتوكولات؛ نشط، قديم.'],
  ['zmap','ZMap','infrastructure','zmap','ماسح منفذ واحد على نطاق واسع؛ نشط بكثافة، غير مفعل تلقائياً.'],
  ['netcat','Netcat','service','nc','أداة اتصالات شبكة عامة؛ تفاعلية، تحتاج service محدد.'],
  ['hping3','hping3','traffic','hping3','توليد حزم شبكة مخصصة؛ يتطلب صلاحيات ونطاق مصرح.'],
  // --- Subdomain / OSINT additions ---
  ['findomain','Findomain','website','findomain','استطلاع نطاقات فرعية سلبي.'],
  ['dnsx','dnsx','website','dnsx','أداة DNS سريعة من ProjectDiscovery.'],
  ['puredns','PureDNS','website','puredns','حل نطاقات فرعية بـ DNS brute/بروتوكولات متعددة.'],
  ['chaos','Chaos (ProjectDiscovery)','website','chaos','استطلاع نطاقات فرعية من قاعدة بيانات ProjectDiscovery.'],
  ['spiderfoot','SpiderFoot','website','spiderfoot','منصة OSINT أتمتة؛ تشغيل مستقل.'],
  ['recon-ng','Recon-ng','website','recon-ng','إطار استطلاع ويب وOSINT (modules).'],
  ['knockpy','Knockpy','website','knockpy','تعداد نطاقات فرعية بـ DNS wordlist.'],
  ['altdns','Altdns','website','altdns','توليد permutations للنطاقات الفرعية.'],
  ['massdns','MassDNS','website','massdns','حل DNS سريع بدفعات كبيرة.'],
  ['dnsrecon','dnsrecon','website','dnsrecon','تعداد DNS شامل.'],
  ['fierce','Fierce','website','fierce','استطلاع DNS بـ brute وreverse lookup.'],
  ['shodan','Shodan CLI','website','shodan','بحث Shodan؛ يحتاج API key وحساباً.'],
  ['censys','Censys CLI','website','censys','بحث Censys؛ يحتاج API keys.'],
  ['h8mail','h8mail','website','h8mail','استطلاع تسريبات بريد إلكتروني؛ يحتاج مزودين ومفاتيح.'],
  ['holehe','Holehe','website','holehe','فحص استخدام بريد في مواقع خارجية؛ نشط لكل موقع.'],
  ['maltego','Maltego CE','website','maltego','منصة OSINT رسومية؛ GUI وAPI.'],
  // --- SSL/TLS additions ---
  ['sslyze','SSLyze','website','sslyze','تدقيق TLS معمّق بـ Python.'],
  ['tlsx','tlsx','website','tlsx','جمع بيانات TLS سريع من ProjectDiscovery.'],
  ['cipherscan','Cipherscan','website','cipherscan','فحص cipher suites؛ أداة shell قديمة.'],
  // --- Exploitation / social engineering frameworks ---
  ['metasploit','Metasploit Framework','service','msfconsole','إطار استغلال؛ يتطلب هدفاً مفحوصاً وموافقة صريحة، لا يشتغل تلقائياً.'],
  ['searchsploit','SearchSploit','website','searchsploit','بحث Exploit-DB محلياً عن ثغرات معروفة.'],
  ['setoolkit','Social-Engineer Toolkit','service','setoolkit','هندسة اجتماعية؛ يتطلب تشغيلاً تفاعلياً وسيناريو مصرحاً.'],
  ['beef','BeEF','service','beef','اختبار متصفح عبر hooks؛ يتطلب ضحية وscope مصرحاً.'],
  // --- Password / brute-force ---
  ['hydra','Hydra','service','hydra','تخمين كلمات مرور خدمات الشبكة؛ يتطلب هدف وبيانات اعتماد مصرح بها.'],
  ['medusa','Medusa','service','medusa','تخمين كلمات مرور موازٍ؛ نفس قيود Hydra.'],
  ['john','John the Ripper','artifact','john','كسر هاشات محلياً؛ يحتاج ملف هاش.'],
  ['hashcat','Hashcat','artifact','hashcat','كسر هاشات GPU/CPU؛ يحتاج ملف هاش.'],
  ['crackmapexec','CrackMapExec','service','crackmapexec','تقييم Active Directory؛ يتطلب شبكة وscope مصرح.'],
  ['ncrack','Ncrack','service','ncrack','تخمين كلمات مرور خدمات شبكة؛ نشط.'],
  ['patator','Patator','service','patator','تخمين متعدد البروتوكولات؛ نشط.'],
  // --- Wireless ---
  ['wifite','Wifite','wireless','wifite','هجمات Wi-Fi آلية؛ يحتاج محولاً مدعوماً وصلاحيات.'],
  ['reaver','Reaver','wireless','reaver','هجوم WPS Pixie-Dust؛ يحتاج محولاً مدعوماً.'],
  ['bettercap','Bettercap','wireless','bettercap','إطار هجمات شبكة/Wi-Fi/BLE؛ تفاعلي.'],
  ['fluxion','Fluxion','wireless','fluxion','هجوم Evil Twin؛ يتطلب محولاً وسيناريو مصرحاً.'],
  // --- Cloud / containers ---
  ['scoutsuite','ScoutSuite','infrastructure','scout','تدقيق إعدادات السحابة؛ يحتاج بيانات اعتماد حساب.'],
  ['kube-bench','kube-bench','infrastructure','kube-bench','فحص CIS Kubernetes؛ يتطلب عنقوداً.'],
  ['falco','Falco','infrastructure','falco','كشف سلوك runtime للحاويات/النواة؛ daemon مستمر.'],
  ['cloudsploit','CloudSploit','infrastructure','cloudsploit','تدقيق سحابي؛ يحتاج بيانات اعتماد.'],
  ['pacu','Pacu','infrastructure','pacu','إطار استغلال AWS؛ يتطلب بيانات اعتماد مصرح بها.'],
  ['terrascan','Terrascan','infrastructure','terrascan','فحص IaC static؛ يحتاج ملفات Terraform/K8s.'],
  // --- Secrets / code analysis additions ---
  ['detect-secrets','detect-secrets','repository','detect-secrets','كشف أسرار في الكود من Yelp.'],
  ['njsscan','njsscan','repository','njsscan','تحليل ساكن Node.js للأسرار والثغرات.'],
  ['brakeman','Brakeman','repository','brakeman','تحليل ساكن Ruby on Rails.'],
  ['snyk','Snyk CLI','repository','snyk','فحص اعتماديات؛ يحتاج تسجيل/توكن Snyk.'],
  // --- CMS scanners ---
  ['wpscan','WPScan','website','wpscan','فحص WordPress؛ نشط، يتطلب scope.'],
  ['joomscan','JoomScan','website','joomscan','فحص Joomla؛ نشط، يتطلب scope.'],
  ['droopescan','Droopescan','website','droopescan','فحص Drupal؛ نشط، يتطلب scope.'],
  ['cmseek','CMSeeK','website','cmseek','كشف CMS وإصداراته؛ نشط خفيف.'],
  // --- Database additions ---
  ['mongoaudit','mongoaudit','database','mongoaudit','تدقيق MongoDB؛ يحتاج عنوان قاعدة بيانات.'],
  // --- Fuzzing additions ---
  ['radamsa','Radamsa','artifact','radamsa','fuzzer عام للملفات/الشبكة؛ يحتاج مدخلات.'],
  ['aflpp','AFL++','artifact','afl-fuzz','fuzzer تغطية؛ يحتاج binary وcorpus.'],
  ['boofuzz','boofuzz','artifact','boofuzz','fuzzer بروتوكولات شبكة بـ Python؛ يحتاج خدمة.'],
  // --- Binary analysis additions ---
  ['idafree','IDA Free','artifact','ida64','عكس ثنائيات؛ GUI، إصدار مجاني.'],
  ['cutter','Cutter','artifact','cutter','عكس ثنائيات GUI (مبني على radare2).'],
  ['angr','angr','artifact','angr','تحليل رمزي للثنائيات بـ Python.'],
  ['emba','EMBA','artifact','emba','تحليل Firmware شامل؛ يحتاج صورة Firmware.'],
  // --- Memory analysis additions ---
  ['rekall','Rekall','artifact','rekall','تحليل ذاكرة (إطار ممتد من Volatility).'],
  // --- Traffic analysis additions ---
  ['tshark','tshark','traffic','tshark','تحليل حزم CLI (من Wireshark).'],
  ['ngrep','ngrep','traffic','ngrep','بحث regex في حزم الشبكة؛ يحتاج واجهة/ملف.'],
  // --- WAF / proxy additions ---
  ['fireprox','Fireprox','website','fireprox','إنشاء endpoints rotating عبر AWS API Gateway؛ يحتاج بيانات AWS.'],
  // --- Extended coverage additions ---
  ['wapiti-cli','Wapiti CLI','website','wapiti','فحص ويب ديناميكي (CLI مباشر).'],
  ['nabu','Nabu','website','nabu','ماسح ثغرات ويب Go سريع.'],
  ['crlfuzz','Crlfuzz','website','crlfuzz','فحص CRLF injection نشط.'],
  ['dalfox','DALFOX','website','dalfox','فحص/استغلال XSS نشط من Go.'],
  ['nuclei-fuzz','Nuclei (fuzz mode)','website','nuclei','قوالب Nuclei في وضع fuzz.'],
  ['katana','Katana','website','katana','crawling/استكشاف endpoints من ProjectDiscovery.'],
  ['gau','gAU','website','gau','جمع URLs تاريخية من public sources (Wayback/OTX).'],
  ['waybackurls','waybackurls','website','waybackurls','جمع URLs من Wayback Machine.'],
  ['gf','gf','website','gf','grep سريع للأنماط في ملفات URLs.'],
  ['qsreplace','qsreplace','website','qsreplace','استبدال قيم query parameters (مفيد لاختبار SSRF/IDOR يدوياً).'],
  ['urlprobe','Urlprobe','website','urlprobe','تحقق سريع من حالة URLs.'],
  ['meg','meg','website','meg','جلب آلاف الملفات بنفس الاسم من hosts متعددة.'],
  ['gotator','Gotator','website','gotator','توليد permutations للنطاقات الفرعية.'],
  ['amass-intel','Amass Intel','website','amass','وضع intel في Amass (استطلاع سلبي).'],
  ['cloudenum','CloudEnum','website','cloud_enum','كشف أصول سحابية عامة (AWS/Azure/GCP) مرتبطة بنطاق.'],
  ['nuclei-iap','Nuclei IAP','website','nuclei','قوالب exposure للـ internal API.'],
  ['subzy','Subzy','website','subzy','كشف subdomain takeover.'],
  ['can-i-take-over-xyz','Can I Take Over XYZ','website','curl','مرجع كشف takeover (web-based).'],
  ['httpx-toolkit','httpx toolkit','website','httpx','ProjectDiscovery httpx (نفس الأداة).'],
  ['dnstwist','dnstwist','website','dnstwist','كشف typosquatting للنطاق.'],
  ['gitdorker','GitDorker','repository','gitdorker','بحث أسرار في GitHub باستخدام dorks؛ يحتاج توكن.'],
  ['trufflehog-v2','TruffleHog v3','repository','trufflehog','كشف أسرار في Git والصور (v3).'],
  ['grype-sbom','Grype SBOM','repository','grype','فحص SBOM للحاويات.'],
  ['syft','Syft','repository','syft','توليد SBOM من صور الحاويات.'],
  ['dockle','Dockle','repository','dockle','فحص إعدادات أمان صور الحاويات.'],
  ['hadolint','Hadolint','repository','hadolint','فحص Dockerfile لقواعد أفضل الممارسات.'],
  ['kubeaudit','kubeaudit','infrastructure','kubeaudit','تدقيق إعدادات Kubernetes manifests.'],
  ['kubesec','kubesec','infrastructure','kubesec','تحليل أمان Kubernetes manifests.'],
  ['popeye','Popeye','infrastructure','popeye','فحص عناقيد Kubernetes live.'],
  ['noseyparker','NoseyParker','repository','noseyparker','كشف أسرار في مستودعات Git بدقة عالية.'],
  ['ggshield','GGShield','repository','ggshield','GitGuardian CLI لكشف الأسرار؛ يحتاج توكن.'],
  ['bundler-audit','bundler-audit','repository','bundler-audit','فحص اعتماديات Ruby (Gemfile.lock).'],
  ['cargo-audit','cargo-audit','repository','cargo-audit','فحص اعتماديات Rust (Cargo.lock).'],
  ['osv-scanner','OSV-Scanner','repository','osv-scanner','فحص اعتماديات مقابل قاعدة OSV من Google.'],
  ['trivy-sbom','Trivy SBOM','repository','trivy','توليد وفحص SBOM.'],
  ['burp-cb','Burp Community (CLI)','website','burpsuite','تشغيل Burp Community من سطر الأوامر.'],
  ['zaproxy-cli','OWASP ZAP CLI','website','zap-cli','واجهة سطر أوامر لـ ZAP (بديل خفيف عن API).'],
  ['wafw00f-plus','wafw00f','website','wafw00f','كشف WAF (مضاف سابقاً، مكرر للتوضيح).'],
  ['identywaf','IdentYwaf','website','identywaf','كشف نوع WAF من الاستجابات.'],
  ['whatwalls','WhatWalls','website','whatwaf','كشف WAF وتجاوزه (اختياري).'],
  ['mitmproxy','mitmproxy','website','mitmproxy','proxy تفاعلي لفحص HTTP/HTTPS؛ يحتاج تكوين يدوي.'],
  ['websocat','websocat','website','websocat','اختبار WebSocket endpoints يدوياً.'],
  ['wscat','wscat','website','wscat','اختبار WebSocket عبر CLI.'],
  ['jwt-tool','JWT Toolkit','website','jwt_tool','تحليل وفحص توكنات JWT (alg confusion، weak secrets)؛ تم تثبيته محلياً في tools/jwt_tool.'],
  ['gf-patterns','gf patterns','website','gf','أنماط جاهزة لاكتشاف SSRF/RCE/Redirect في URLs.'],
  // --- Scanner platforms ---
  ['nessus','Nessus','website','nessusd','ماسح ثغرات Tenable؛ يتطلب تشغيلاً محلياً وactivation code وscope مصرح.'],
  ['openvas','OpenVAS/GVM','website','gvm-cli','منصة Greenbone مفتوحة المصدر؛ خدمات محلية (gvmd/gsad) وscope مصرح.'],
  ['qualys','Qualys (cloud agent)','infrastructure','qualys-cloud-agent','خدمة SaaS تجارية؛ تحتاج حساباً وplatform URL، مو محلية بالكامل.'],
];

const CATALOG_NOT_WEB = new Set(['traffic','artifact','host','repository','database','wireless','infrastructure','service']);

function normalizeScanTarget(value) {
  if (typeof value !== 'string') return null;
  let raw = value.trim().replace(/^[`"'<>]+|[`"'<>]+$/g, '').trim();
  const markdownLink = raw.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/i);
  if (markdownLink) raw = markdownLink[2];
  raw = raw.replace(/[.,;]+$/, '');
  if (!raw || /[\s<>`]/.test(raw)) return null;
  const candidate = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const url = new URL(candidate);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    if (!net.isIP(hostname) && !/^(?:localhost|127(?:\.\d{1,3}){3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})$/i.test(hostname)) return null;
    url.hash = '';
    return url.href;
  } catch { return null; }
}
function parsedTarget(t) { try { return new URL(t.startsWith('http') ? t : 'https://' + t); } catch { return null; } }
function host(t) { return parsedTarget(t)?.hostname || t; }
function target(t) { return t.startsWith('http') ? t : 'https://' + t; }
function authority(t) { const u = new URL(target(t)); return u.host; }
function nmapArgs(t) {
  const u = parsedTarget(t);
  if (!u) return ['-Pn', '-sT', '-sV', '--script', 'safe', '-T4', '--top-ports', '100', '-oX', '-', host(t)];
  const hostname = u.hostname.replace(/^\[|\]$/g, '');
  return ['-Pn', '-sT', '-sV', '--script', 'safe', '-T4', ...(u.port ? ['-p', u.port] : ['--top-ports', '100']), '-oX', '-', hostname];
}
const TLS_TOOL_IDS = new Set(['testssl', 'sslscan']);
const PASSIVE_DOMAIN_TOOL_IDS = new Set(['subfinder', 'theharvester', 'sublist3r', 'amass', 'assetfinder']);

export function passiveDomainToolSkipReason(id, targetUrl) {
  if (!PASSIVE_DOMAIN_TOOL_IDS.has(id)) return '';
  const parsed = parsedTarget(targetUrl);
  const hostname = parsed?.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname) return 'تعذر تحديد نطاق الهدف.';
  if (net.isIP(hostname) || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local'))
    return 'تعداد النطاقات الفرعية يتطلب اسم نطاق؛ الهدف عنوان IP أو اسم مضيف محلي.';
  return '';
}

/* ابحث عن الأداة أولاً في مجلد tools\ المحلي (نسخ مثبتة مع المشروع) ثم في PATH */
import fsSync from 'node:fs';
const TOOLS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'tools');
const wslExecutable = () => path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'wsl.exe');
const wslDistro = () => String(process.env.REASONIX_WSL_DISTRO || 'Ubuntu').trim() || 'Ubuntu';
const localToolPath = bin => {
  try {
    const cands = [bin, bin + '.exe', bin.endsWith('.sh') ? bin : bin + (process.platform === 'win32' ? '.exe' : ''),
      bin.endsWith('.sh') ? bin.replace(/\.sh$/, '') : bin, bin.replace(/\.sh$/, '') + '.bat', bin.replace(/\.sh$/, '') + '.cmd'];
    /* 1) الجذر مباشرة (nuclei.exe, gobuster.exe, httpx.exe, subfinder.exe, nmap.exe...) */
    for (const c of cands) {
      const p = path.join(TOOLS_DIR, c);
      if (fsSync.existsSync(p) && fsSync.statSync(p).isFile()) return p;
    }
    /* 2) داخل كل مجلد: المجلد نفسه + Scripts (pip) + bin + program (nikto) */
    for (const d of fsSync.readdirSync(TOOLS_DIR, { withFileTypes: true })) {
      if (!d.isDirectory()) continue;
      for (const sub of ['', 'Scripts', 'bin', 'program', 'utils']) {
        for (const c of cands) {
          const p = path.join(TOOLS_DIR, d.name, sub, c);
          if (fsSync.existsSync(p) && fsSync.statSync(p).isFile()) return p;
        }
      }
    }
    const mobileScripts = path.join(TOOLS_DIR, 'mobile-venv', 'Scripts');
    for (const c of cands) { const p = path.join(mobileScripts, c); if (fsSync.existsSync(p) && fsSync.statSync(p).isFile()) return p; }
  } catch { }
  return null;
};
const wslToolPath = bin => new Promise(resolve => {
  if (process.platform !== 'win32') return resolve(null);
  const safeBin = String(bin).replace(/[^A-Za-z0-9_.+-]/gu, '');
  if (!safeBin) return resolve(null);
  execFile(wslExecutable(), [
    '--distribution', wslDistro(), '--exec', 'bash', '-lc',
    `tool="$(command -v -- '${safeBin}' 2>/dev/null)" && test -x "$tool" && printf '%s' "$tool"`,
  ], { timeout: 30000, windowsHide: true }, (error, stdout) => {
    resolve(!error && stdout.trim() ? `WSL:${safeBin}` : null);
  });
});
const whichTool = bin => new Promise(async resolve => {
  /* أدوات git-bash/perl/bash الخاصة — مسارات ثابتة معروفة */
  const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
  const gitPerl = 'C:\\Program Files\\Git\\usr\\bin\\perl.exe';
  const ruby = path.join(TOOLS_DIR, 'ruby', 'bin', 'ruby.exe');
  if (bin === 'x64dbg') {
    const p = path.join(TOOLS_DIR, 'x64dbg', 'release', 'x64', 'x64dbg.exe');
    if (fsSync.existsSync(p)) return resolve(p);
  }
  if (['amass', 'ffuf', 'testssl.sh', 'wfuzz', 'nessusd', 'gvmd', 'gvm-cli'].includes(bin)) {
    const wslTool = await wslToolPath(bin);
    if (wslTool) return resolve(wslTool);
  }
  if (bin === 'nessusd') {
    const wslNessus = await new Promise(resolve => {
      execFile(wslExecutable(), ['--distribution', wslDistro(), '--exec', 'bash', '-lc',
        'test -x /opt/nessus/sbin/nessusd && printf /opt/nessus/sbin/nessusd'],
        { timeout: 30000, windowsHide: true }, (error, stdout) => resolve(!error && stdout.trim() ? 'WSL:nessusd' : null));
    });
    if (wslNessus) return resolve(wslNessus);
  }
  if (bin === 'amass') {
    /* Amass v3: self-contained (no graph DB engine) — v5 fails on Windows */
    const v3 = path.join(TOOLS_DIR, 'amass', 'amass3_windows_amd64', 'amass_Windows_amd64', 'amass.exe');
    if (fsSync.existsSync(v3)) return resolve(v3);
    const p = path.join(TOOLS_DIR, 'amass', 'amass_windows_amd64', 'amass.exe');
    if (fsSync.existsSync(p)) return resolve(p);
  }
  if (bin === 'wireshark') {
    const p = 'C:\\Program Files\\Wireshark\\tshark.exe';
    if (fsSync.existsSync(p)) return resolve(p);
  }
  if (bin === 'ghidra' || bin === 'analyzeHeadless') {
    const p = path.join(TOOLS_DIR, 'mobile-binaries', 'ghidra_12.1.4_PUBLIC', 'support', 'analyzeHeadless.bat');
    if (fsSync.existsSync(p)) return resolve(p);
  }
  const javaRoots = [path.join(TOOLS_DIR, 'mobile-binaries', 'jdk21', 'jdk-21.0.12.1+1'), 'C:\\Program Files\\Microsoft', 'C:\\Program Files\\Eclipse Adoptium'];
  const java = javaRoots.map(root => {
    try { return fsSync.readdirSync(root).filter(name => /^jdk-/i.test(name)).map(name => path.join(root, name, 'bin', 'java.exe')); } catch { return []; }
  }).flat().find(candidate => fsSync.existsSync(candidate));
  if (bin === 'jadx' || bin === 'apktool') {
    const jar = bin === 'jadx' ? path.join(TOOLS_DIR, 'mobile-binaries', 'jadx', 'lib', 'jadx-1.5.6-all.jar') : path.join(TOOLS_DIR, 'mobile-binaries', 'apktool.jar');
    if (fsSync.existsSync(jar) && fsSync.existsSync(java)) return resolve('JAVA:' + java + '|' + jar);
  }
  if (bin === 'r2') {
    const p = path.join(TOOLS_DIR, 'mobile-binaries', 'radare2', 'radare2-6.2.2-w64', 'bin', 'radare2.exe');
    if (fsSync.existsSync(p)) return resolve(p);
  }
  if (bin === 'theHarvester') {
    const p = path.join(TOOLS_DIR, 'security-tools', 'theharvester', 'bin', 'theHarvester.exe');
    if (fsSync.existsSync(p)) return resolve(p);
  }
  if (bin === 'wapiti') {
    const p = path.join(TOOLS_DIR, 'venvs', 'wapiti', 'Scripts', 'wapiti.exe');
    if (fsSync.existsSync(p)) return resolve(p);
  }
  if (bin === 'nikto') {
    const p = path.join(TOOLS_DIR, 'nikto', 'program', 'nikto.pl');
    if (fsSync.existsSync(p) && fsSync.existsSync(gitPerl)) return resolve('PERL:' + gitPerl + '|' + p);
  }
  if (bin === 'whatweb') {
    const p = path.join(TOOLS_DIR, 'whatweb', 'whatweb');
    if (fsSync.existsSync(p) && fsSync.existsSync(ruby)) return resolve('RUBY:' + ruby + '|' + p);
  }
  if (bin === 'testssl.sh') {
    const p = path.join(TOOLS_DIR, 'testssl.sh', 'testssl.sh');
    if (fsSync.existsSync(p) && fsSync.existsSync(gitBash)) return resolve('BASH:' + gitBash + '|' + p);
  }
  if (bin === 'retire') {
    const p = path.join(TOOLS_DIR, 'mobile-node', 'node_modules', 'retire', 'lib', 'cli.js');
    if (fsSync.existsSync(p)) return resolve('NODE:' + p);
  }
  if (bin === 'yarn') {
    const p = path.join(TOOLS_DIR, 'mobile-node', 'node_modules', 'yarn', 'bin', 'yarn.js');
    if (fsSync.existsSync(p)) return resolve('NODE:' + p);
  }
  const local = localToolPath(bin);
  if (local) return resolve(local);
  if (bin === 'wafw00f') {
    const py = localToolPath('python');
    if (py && fsSync.existsSync(path.join(TOOLS_DIR, 'python', 'Lib', 'site-packages', 'wafw00f'))) {
      return resolve('PY:' + py);
    }
  }
  if (bin === 'nmap') {
    const p = path.join(TOOLS_DIR, 'nmap', 'nmap.exe');
    if (fsSync.existsSync(p)) return resolve(p);
  }
  const findOnHost = () => execFile(process.platform === 'win32' ? 'where' : 'which', [bin], { timeout: 5000, windowsHide: true }, (e, so) => {
    resolve(!e && so.trim() ? so.trim().split(/\r?\n/)[0] : null);
  });
  /* Last resort on Windows: use the configured WSL distribution without elevating to root. */
  if (process.platform === 'win32') {
    const wsl = wslExecutable();
    if (!fsSync.existsSync(wsl)) return findOnHost();
    const safeBin = String(bin).replace(/[^A-Za-z0-9_.+-]/gu, '');
    if (!safeBin) return findOnHost();
    execFile(wsl, ['--distribution', wslDistro(), '--exec', 'bash', '-lc', `tool="$(command -v -- '${safeBin}' 2>/dev/null)" && test -x "$tool" && printf '%s' "$tool"`], { timeout: 30000, windowsHide: true }, (e, so) => {
      if (!e && so.trim()) return resolve('WSL:' + bin);
      try { findOnHost(); } catch { resolve(null); }
    });
    return;
  }
  try { findOnHost(); } catch { resolve(null); }
});

function execTool(toolBin, toolArgs, opts = {}) {
  /* Execute WSL tools as the configured distro user; never elevate scan processes. */
  let bin = toolBin, args = toolArgs;
  if (typeof bin === 'string' && bin.startsWith('WSL:')) {
    const inner = bin.slice(4);
    bin = wslExecutable();
    args = ['--distribution', wslDistro(), '--exec', inner, ...toolArgs];
    opts = { ...opts, timeout: opts.timeout };
  }
  const signal = opts.signal || currentScanSignal();
  return new Promise(resolve => {
    let settled = false;
    const finish = result => { if (!settled) { settled = true; resolve(result); } };
    if (signal?.aborted) return finish({ code: -1, error: 'scan-cancelled', stdout: '', stderr: '', killed: true });
    const inheritedEnv = Object.fromEntries(['PATH','PATHEXT','SystemRoot','WINDIR','TEMP','TMP','USERPROFILE','HOME','APPDATA','LOCALAPPDATA','HOMEDRIVE','HOMEPATH','COMSPEC','LANG','LC_ALL','TERM']
      .filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
    let p;
    try {
      p = execFile(bin, args, { timeout: opts.timeout === undefined ? 60000 : opts.timeout, maxBuffer: 4 * 1024 * 1024, windowsHide: true, ...(opts.cwd ? { cwd: opts.cwd } : {}), env: { ...inheritedEnv, ...(opts.env || {}) } }, (e, stdout, stderr) => {
        finish({ code: e ? (e.code ?? -1) : 0, error: e ? e.message : null, stdout: (stdout || '').slice(0, 60000), stderr: (stderr || '').slice(0, 4000), killed: e && e.killed });
      });
      const onAbort = () => {
        p.kill();
        finish({ code: -1, error: 'scan-cancelled', stdout: '', stderr: '', killed: true });
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      p.once('close', () => signal?.removeEventListener('abort', onAbort));
      if (typeof opts.onOutput === 'function') {
        let streamedBytes = 0;
        const maxLiveOutputBytes = Math.max(0, Number(opts.maxLiveOutputBytes) || 24000);
        const forward = stream => chunk => {
          if (streamedBytes >= maxLiveOutputBytes) return;
          const text = chunk.toString('utf8');
          const remaining = maxLiveOutputBytes - streamedBytes;
          const bounded = text.slice(0, remaining);
          streamedBytes += Buffer.byteLength(bounded, 'utf8');
          for (let offset = 0; offset < bounded.length; offset += 2000) {
            try { opts.onOutput({ stream, text: bounded.slice(offset, offset + 2000) }); } catch { }
          }
        };
        p.stdout?.on('data', forward('stdout'));
        p.stderr?.on('data', forward('stderr'));
      }
      p.on('error', error => finish({ code: error.code || -1, error: error.message, stdout: '', stderr: '', killed: false }));
      if (opts.stdin && p.stdin) {
        p.stdin.on('error', error => finish({ code: error.code || -1, error: error.message, stdout: '', stderr: '', killed: false }));
        p.stdin.write(opts.stdin); p.stdin.end();
      } else if (p.stdin) p.stdin.end();
    } catch (error) {
      finish({ code: error.code || -1, error: error.message, stdout: '', stderr: '', killed: false });
    }
  });
}

const TOOL_PROBE_CACHE = new Map();
function checkTool(bin) {
  if (!TOOL_PROBE_CACHE.has(bin)) TOOL_PROBE_CACHE.set(bin, (async () => {
    const executable = await whichTool(bin);
    if (!executable) return { executable: null, installed: false, version: '' };
    if (bin === 'x64dbg') return { executable, installed: true, runnable: process.platform === 'win32', version: 'Windows debugger package installed' };
    let command = executable, args = ({ nikto: ['-config', path.join(TOOLS_DIR, 'nikto', 'program', 'nikto.conf.default'), '-Version'], gobuster: ['--version'], ffuf: ['-V'], subfinder: ['-version'], amass: ['-version'], assetfinder: ['-h'], 'testssl.sh': ['--version'], theHarvester: ['-h'], wfuzz: ['--version'], ghidra: ['-version'], wireshark: ['--version'], 'kube-hunter': ['--help'], kr: ['version'] }[bin] || ['--version']);
    let env = {};
    if (executable.startsWith('NODE:')) { command = process.execPath; args = [executable.slice(5), '--version']; }
    if (executable.startsWith('JAVA:')) { const [java, jar] = executable.slice(5).split('|'); command = java; args = ['-jar', jar, bin === 'jadx' ? '--version' : '--version']; }
    if (bin === 'objection') {
      const mobileHome = path.join(TOOLS_DIR, 'mobile-home');
      fsSync.mkdirSync(path.join(mobileHome, '.objection'), { recursive: true });
      env = { USERPROFILE: mobileHome, HOME: mobileHome };
    }
    if (bin === 'ghidra') {
      const jdk = path.join(TOOLS_DIR, 'mobile-binaries', 'jdk21', 'jdk-21.0.12.1+1');
      env = { JAVA_HOME: jdk, PATH: `${path.join(jdk, 'bin')};${process.env.PATH || ''}` };
    }
    if (executable.startsWith('PY:')) { command = executable.slice(3); args = ['-m', 'wafw00f.cli', '--version']; }
    else if (executable.startsWith('PERL:')) {
      const [perl, script] = executable.slice(5).split('|'); command = perl; args = bin === 'nikto' ? [script, '-config', path.join(TOOLS_DIR, 'nikto', 'program', 'nikto.conf.default'), '-Version'] : [script, '-Version']; env = { PERL5LIB: path.join(TOOLS_DIR, 'perl-site'), PATH: `C:\\Program Files\\Git\\usr\\bin;${process.env.PATH || ''}` };
    } else if (executable.startsWith('BASH:')) {
      const [bash, script] = executable.slice(5).split('|'); command = bash; args = [script, '--version']; env = { PATH: `C:\\Program Files\\Git\\usr\\bin;${process.env.PATH || ''}` };
    } else if (executable.startsWith('RUBY:')) {
      const [rubyBin, script] = executable.slice(5).split('|'); command = rubyBin; args = [script, '--version'];
    }
    if (bin === 'wapiti') env = { ...env, PYTHONPATH: path.join(TOOLS_DIR, 'venvs', 'wapiti', 'Lib', 'site-packages'), PYTHONIOENCODING: 'utf-8' };
    if (bin === 'theHarvester') env.PYTHONPATH = path.join(TOOLS_DIR, 'security-tools', 'theharvester');
    // WSL daemon/service tools: probe by running --version inside WSL, or fall back to install check.
    if (typeof executable === 'string' && executable.startsWith('WSL:')) {
      const wslBin = executable.slice(4);
      const probe = await new Promise(resolve => {
        execFile(wslExecutable(), ['--distribution', wslDistro(), '--exec', 'bash', '-lc',
          `if [ "${wslBin}" = nessusd ] && [ -x /opt/nessus/sbin/nessusd ]; then /opt/nessus/sbin/nessusd --version 2>&1 | head -1; `
          + `elif command -v ${wslBin} >/dev/null 2>&1; then ${wslBin} --version 2>&1 | head -1 || ${wslBin} -V 2>&1 | head -1; `
          + `else echo ${wslBin}-installed; fi`],
        { timeout: 30000, windowsHide: true }, (error, stdout, stderr) => resolve({ error, stdout, stderr }));
      });
      const probeText = (probe.stdout || probe.stderr || '').trim();
      return { executable, installed: true, runnable: Boolean(probeText), version: probeText.slice(0, 160),
        error: probe.error ? String(probe.error.message).slice(0, 300) : '' };
    }
    const result = await execTool(command, args, { timeout: 30000, env, ...(bin === 'nikto' ? { cwd: path.join(TOOLS_DIR, 'nikto', 'program') } : {}) });
    const probeText = (result.stdout || result.stderr || '').trim();
    const probeSucceeded = (!result.error && result.code === 0) || (bin === 'masscan' && !result.killed && /Masscan version/i.test(probeText));
    return { executable, installed: true, runnable: probeSucceeded,
      version: probeText.slice(0, 160),
      error: result.error || (!probeSucceeded ? (result.stderr || `version probe exited ${result.code}`).slice(0, 300) : '') };
  })());
  return TOOL_PROBE_CACHE.get(bin);
}

function displayCommand(name, args = []) {
  const quote = value => /[\s"']/u.test(String(value)) ? `"${String(value).replace(/(["\\])/g, '\\$1')}"` : String(value);
  const safeArgs = args.map((value, index) => {
    if (index > 0 && ['-H', '--header'].includes(args[index - 1])) return '[REDACTED]';
    if (/^(?:Cookie|Authorization):/iu.test(String(value))) return `${String(value).split(':', 1)[0]}: [REDACTED]`;
    return value;
  });
  return [name, ...safeArgs].map(quote).join(' ');
}

function redactScanSecrets(value) {
  let output = String(value || '');
  for (const secret of Object.values(currentScanOptions().headers || {})) {
    if (secret) output = output.split(secret).join('[REDACTED]');
  }
  return output;
}

async function catalogToolStatus(item) {
  let checked, checkError;
  try { checked = await checkTool(item[3]); }
  catch (error) { checkError = String(error?.message || error).slice(0, 500); }
  if (checkError) return {
    id: item[0], name: item[1], category: item[2], installed: false, status: 'error', note: item[4],
    output: `سبب تعذر التحقق من الأداة: ${checkError}؛ يستمر فحص الهدف وبقية الأدوات.`,
  };
  if (!checked.installed) return {
    id: item[0], name: item[1], category: item[2], installed: false,
    status: 'not-installed', note: item[4], install: `الأداة المطلوبة: ${item[3]}`,
    output: `سبب عدم الفحص: الأداة ${item[3]} غير مثبتة في بيئة التشغيل الحالية.`,
  };
  if (checked.runnable === false) return {
    id: item[0], name: item[1], category: item[2], installed: true, status: 'blocked', note: item[4],
    output: `سبب عدم الفحص: الأداة مثبتة لكن فشل اختبار تشغيلها${checked.error ? `: ${String(checked.error).slice(0, 500)}` : '.'}؛ يستمر فحص الهدف وبقية الأدوات.`,
  };
  if (CATALOG_NOT_WEB.has(item[2])) return {
    id: item[0], name: item[1], category: item[2], installed: checked.installed,
    status: 'not-applicable', note: item[4],
    output: `سبب عدم الفحص: فحص الويب الحالي لا يقبل مدخلات فئة ${item[2]}. ${item[4]}`,
    ...(!checked.installed && item[2] !== 'service' ? { install: `الأداة المطلوبة: ${item[3]}` } : {}),
  };
  return {
    id: item[0], name: item[1], category: item[2], installed: checked.installed,
    status: checked.installed ? 'not-run' : 'not-installed', note: checked.installed ? 'الأداة مثبتة، لكنها غير مربوطة بمهمة الفحص الآمن الحالية.' : item[4],
    output: `سبب عدم الفحص: الأداة مثبتة لكنها غير مربوطة بمهمة الفحص الآمن الحالية.${checked.version ? ` فحص التثبيت: ${checked.version}` : ''}`,
    ...(!checked.installed ? { install: `الأداة المطلوبة: ${item[3]}` } : {}),
  };
}

function parseWapitiReport(report, targetUrl) {
  const findings = [];
  const vulnerabilities = report?.vulnerabilities;
  if (!vulnerabilities || typeof vulnerabilities !== 'object' || Array.isArray(vulnerabilities)) return findings;
  for (const [category, rows] of Object.entries(vulnerabilities)) {
    if (!Array.isArray(rows)) continue;
    for (const row of rows.slice(0, 60)) {
      const rawPath = String(row?.path || '/').slice(0, 1500);
      let endpoint = rawPath;
      try { endpoint = new URL(rawPath, targetUrl).toString(); } catch { }
      const classification = report.classifications?.[category] || {};
      const evidence = [
        `الأداة: Wapiti ${report.infos?.version || ''}`.trim(),
        `نوع النتيجة كما أبلغت الأداة: ${category}`,
        `مستوى Wapiti الداخلي: ${Number.isFinite(Number(row?.level)) ? row.level : 'غير محدد'} (ليس CVSS)`,
        `الطلب: ${String(row?.method || 'HTTP').slice(0, 20)} ${rawPath}`,
        row?.parameter ? `المعامل: ${String(row.parameter).slice(0, 300)}` : '',
        String(row?.info || '').slice(0, 1500),
      ].filter(Boolean);
      if (row?.curl_command) evidence.push(`إعادة إنتاج من التقرير: ${String(row.curl_command).slice(0, 1200)}`);
      const key = category.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 32) || 'finding';
      findings.push({
        k: `wapiti-${key}`, sev: 'info', cwe: 'CWE-Unknown', cvss: 0,
        title: `Wapiti: ${String(category).slice(0, 160)}`,
        desc: String(classification.desc || 'نتيجة من تقرير Wapiti المحلي؛ راجع الدليل وأعد التحقق يدوياً قبل المعالجة.').slice(0, 1500),
        fix: [String(classification.sol || 'تحقق من النتيجة على التطبيق وعالج السبب الجذري إذا ثبتت.').slice(0, 1000)],
        ai: 'لم تُحوّل درجة Wapiti الداخلية إلى CVSS؛ التصنيف هنا معلوماتي حتى لا نبالغ في الخطورة.',
        ep: endpoint, evidence, real: true, source: 'Wapiti',
      });
    }
  }
  return findings;
}

export function parseFfufOutput(output, targetUrl) {
  const findings = [];
  const base = new URL(targetUrl);
  const seen = new Set();
  for (const line of String(output || '').split(/\r?\n/u).slice(0, 1000)) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    const rawUrl = String(row?.url || '');
    if (!rawUrl || !Number.isInteger(Number(row?.status))) continue;
    let parsed;
    try { parsed = new URL(rawUrl, base); } catch { continue; }
    if (parsed.origin !== base.origin || parsed.username || parsed.password) continue;
    const endpoint = parsed.pathname + parsed.search;
    if (seen.has(endpoint)) continue;
    seen.add(endpoint);
    const payload = String(row?.input?.FUZZ || '').slice(0, 100);
    findings.push({
      k: 'ffuf-path-discovery', sev: 'info', cwe: 'CWE-Unknown', cvss: 0,
      title: `مسار استجاب للفحص — ${endpoint}`,
      desc: 'اكتشاف مسار من استجابة HTTP فقط؛ لا يثبت وجود ثغرة. راجع حالة الاستجابة وسياق التطبيق يدويًا.',
      fix: ['تحقق من أن المسار مقصود ومحمِيّ بالصلاحيات المناسبة.'],
      ai: 'نتيجة استطلاع للمسارات وليست تأكيدًا لثغرة.',
      ep: parsed.toString(),
      evidence: [`ffuf: HTTP ${Number(row.status)}${row.length !== undefined ? `، حجم الاستجابة ${Number(row.length) || 0} بايت` : ''}${payload ? `، كلمة الاختبار ${payload}` : ''}`],
      real: true, source: 'ffuf',
    });
    if (findings.length >= 100) break;
  }
  return findings;
}

export function parseNucleiOutput(output, targetUrl) {
  const findings = [];
  const base = new URL(targetUrl);
  const seen = new Set();
  const severities = new Set(['critical', 'high', 'medium', 'low', 'info']);
  for (const line of String(output || '').split(/\r?\n/u).slice(0, 2000)) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    const info = row?.info && typeof row.info === 'object' ? row.info : {};
    const templateId = String(row?.['template-id'] || row?.templateID || '').slice(0, 120);
    const rawUrl = String(row?.['matched-at'] || row?.url || '');
    if (!templateId || !rawUrl) continue;
    let matched;
    try { matched = new URL(rawUrl, base); } catch { continue; }
    if (matched.origin !== base.origin || matched.username || matched.password) continue;
    const key = `${templateId}|${matched.pathname}${matched.search}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const severity = String(info.severity || 'info').toLowerCase();
    const extracted = Array.isArray(row['extracted-results']) ? row['extracted-results'] : [];
    const evidence = [`Nuclei template ${templateId}`, `Matched URL: ${matched.toString()}`];
    for (const item of extracted.slice(0, 5)) evidence.push(`Extracted: ${String(item).slice(0, 300)}`);
    findings.push({
      k: `nuclei-${templateId.toLowerCase().replace(/[^a-z0-9-]+/gu, '-').slice(0, 80)}`,
      sev: severities.has(severity) ? severity : 'info',
      cwe: 'CWE-Unknown', cvss: 0,
      title: `Nuclei: ${String(info.name || templateId).slice(0, 200)}`,
      desc: String(info.description || 'Nuclei template matched; validate the response and application context manually.').slice(0, 1500),
      fix: ['تحقق يدويًا من الدليل وسياق التطبيق قبل اعتماد النتيجة أو تغيير النظام.'],
      ai: 'نتيجة مطابقة قالب آلي؛ ليست إثباتًا بشريًا ولا تحوي درجة CVSS موثوقة من هذه الاستجابة.',
      ep: matched.toString(), evidence, real: true, source: 'Nuclei',
    });
    if (findings.length >= 200) break;
  }
  return findings;
}

export function profileToolSkipReason(id, targetUrl, requestedProfile = 'full') {
  const profile = normalizeScanProfile(requestedProfile);
  if (profile === 'quick' && !new Set(['httpx', 'whatweb', 'wafw00f', 'testssl', 'sslscan']).has(id))
    return 'تم تخطي الأداة حسب نمط الفحص السريع؛ اختر الشامل أو العميق لتشغيل الأدوات المنطبقة.';
  return passiveDomainToolSkipReason(id, targetUrl);
}

export function requiresActiveConfirmation(requestedProfile = 'full') {
  return normalizeScanProfile(requestedProfile) !== 'quick';
}

function safeReportUrl(value) {
  try {
    const url = new URL(value);
    for (const key of [...url.searchParams.keys()]) {
      if (/(?:token|secret|password|api[_-]?key|session|credential)/iu.test(key))
        url.searchParams.set(key, '[REDACTED]');
    }
    return url.href.slice(0, 1000);
  } catch { return String(value).slice(0, 1000); }
}

export async function runHeuristicFuzzer({
  targets, enabled, profile, emit,
  request = req,
  wait = delay => waitForRetry(delay, currentScanSignal()),
} = {}) {
  const startedAt = Date.now();
  const id = 'heuristic-fuzzer';
  const name = 'Bounded heuristic fuzzer';
  const skipped = (status, reason) => ({
    id, name, category: 'website', installed: true, status,
    note: reason, output: reason, elapsed: Date.now() - startedAt,
  });
  if (profile !== 'deep') return { tool: skipped('not-run', 'Skipped: heuristic fuzzing requires the Deep profile.') , pipeline: { id, name, status: 'not-run', inputs: [], outputCount: 0, note: 'Deep profile required.' } };
  if (!enabled) return { tool: skipped('not-run', 'Skipped: heuristic fuzzing is opt-in and was not requested.'), pipeline: { id, name, status: 'not-run', inputs: [], outputCount: 0, note: 'Opt-in was not selected.' } };
  if (!targets.length) return { tool: skipped('not-applicable', 'Not applicable: no same-origin URL seed was available.'), pipeline: { id, name, status: 'not-applicable', inputs: [], outputCount: 0, note: 'No same-origin URL seed.' } };

  const findings = [];
  const inputs = [];
  let requests = 0;
  let delayMs = 550;
  let stopReason = '';
  const waitBeforeRequest = async () => {
    await wait(delayMs);
    requests++;
  };
  emit({ type: 'tool', id, name, status: 'running', installed: true });
  for (const rawSeed of targets.slice(0, 3)) {
    throwIfScanAborted();
    const seed = new URL(rawSeed);
    const parameters = [...new Set(seed.searchParams.keys())].slice(0, 1);
    if (!parameters.length) parameters.push('__reasonix_probe');
    for (const parameter of parameters) {
      const marker = `rsx-${crypto.randomUUID().replace(/-/gu, '').slice(0, 10)}`;
      const controlUrl = new URL(seed);
      controlUrl.searchParams.set(parameter, `${marker}-control`);
      await waitBeforeRequest();
      const control = await request(controlUrl.href, { retry429: false }, 6000);
      inputs.push({ url: safeReportUrl(seed.href), parameter, source: 'same-origin pipeline seed' });
      if (!control.status || [401, 403, 429].includes(control.status) || control.status >= 500) {
        stopReason = `Stopped safely at the control request after ${control.status || control.error}; no access-control or rate-limit bypass was attempted.`;
        break;
      }
      const probes = heuristicProbePayloads(marker).slice(0, 4);
      for (const probe of probes) {
        throwIfScanAborted();
        const candidateUrl = new URL(controlUrl);
        if (probe.parameterMode === 'value') candidateUrl.searchParams.set(parameter, probe.payload);
        else candidateUrl.searchParams.set(probe.parameter, probe.payload);
        await waitBeforeRequest();
        const candidate = await request(candidateUrl.href, { retry429: false }, 6000);
        if (!candidate.status || [401, 403, 429].includes(candidate.status)) {
          if (candidate.status === 429) delayMs = Math.min(8000, Math.max(delayMs * 2, candidate.retryAfterMs || 1000));
          stopReason = `Stopped safely after HTTP ${candidate.status || candidate.error}; no identity rotation or rate-limit evasion was used.`;
          break;
        }
        const analysis = analyzeHeuristicResponses(control, candidate, {
          probeMarker: marker,
          expectedOutput: probe.expectedOutput || '',
        });
        if (analysis.anomalous) {
          const kind = analysis.signals.includes('template-expression-evaluated')
            ? 'possible-template-evaluation'
            : analysis.signals.includes('new-stack-trace') || analysis.signals.includes('unexpected-server-error')
              ? 'unexpected-server-error'
              : 'response-anomaly';
          findings.push({
            k: `heuristic-${kind}-${encodeURIComponent(parameter).toLowerCase().slice(0, 40)}`,
            sev: 'info',
            cwe: kind === 'possible-template-evaluation' ? 'CWE-1336' : 'CWE-Unknown',
            cvss: 0,
            title: `Heuristic signal requiring review: ${kind}`,
            desc: 'This is a signal from a bounded, non-destructive GET probe; it is not a confirmed vulnerability or zero-day.',
            fix: ['Review the exact request and response in a controlled environment; do not treat a heuristic signal as proof without manual validation.'],
            ai: 'Heuristic lead only. No database contents, files, or command output were requested.',
            ep: safeReportUrl(seed.href),
            param: probe.parameterMode === 'add-param' ? probe.parameter : parameter,
            payload: probe.payload,
            responseExcerpt: analysis.responseExcerpt,
            evidence: [
              `Probe family: ${probe.kind}; payload: ${probe.payload}`,
              `Control HTTP ${analysis.controlStatus} (${analysis.controlLength} chars); probe HTTP ${analysis.probeStatus} (${analysis.probeLength} chars).`,
              `Observed signals: ${analysis.signals.join(', ')}; confidence: ${analysis.confidence}.`,
              'No data was extracted; evidence is a bounded response excerpt and status/length comparison.',
            ],
            source: name,
            evidenceDetail: createEvidenceObject({
              vulnerabilityType: kind,
              parameter: probe.parameterMode === 'add-param' ? probe.parameter : parameter,
              payload: probe.payload,
              responseExcerpt: analysis.responseExcerpt,
              observations: analysis.signals,
              source: name,
            }),
          });
        }
        if (candidate.status >= 500) {
          stopReason = `Stopped this target after HTTP ${candidate.status} to avoid repeated server errors.`;
          break;
        }
      }
      if (stopReason) break;
    }
    if (stopReason) break;
  }
  const status = stopReason ? 'blocked' : 'ok';
  const output = `${stopReason ? `${stopReason} ` : ''}Issued ${requests} bounded GET request(s) with a ${delayMs} ms minimum inter-request delay; ${findings.length} heuristic signal(s) recorded.`;
  const tool = {
    id, name, category: 'website', installed: true, status, elapsed: Date.now() - startedAt,
    note: stopReason || 'Sequential same-origin benign probes; stops on access denial, rate limit, or 5xx.',
    output,
    ...(findings.length ? { findings } : {}),
  };
  const pipeline = {
    id, name, status, inputs, outputCount: findings.length,
    note: stopReason || 'Sequential bounded same-origin probes; no exploit or data-extraction payloads.',
  };
  emit({ type: 'tool', ...tool });
  emit({ type: 'pipeline', ...pipeline });
  return { tool, pipeline };
}

export async function runAutonomousCrawler(
  targetUrl,
  profile = 'full',
  emit = () => {},
  {
    request = req,
    wait = delay => waitForRetry(delay, currentScanSignal()),
  } = {},
) {
  const limits = profile === 'deep'
    ? { pages: 24, scripts: 6, depth: 3 }
    : profile === 'quick' ? { pages: 6, scripts: 1, depth: 1 } : { pages: 12, scripts: 3, depth: 2 };
  const origin = new URL(targetUrl).origin;
  const discovered = new Map();
  const fields = new Map();
  const cookieObservations = new Map();
  const queue = [];
  const visited = new Set();
  const disallowed = [];
  const errors = [];
  let externalRejected = 0;
  let authRestricted = 0;
  let rateLimited = false;
  let scriptsRead = 0;
  let requests = 0;
  let completedResponses = 0;
  const rootUrl = new URL(targetUrl);
  rootUrl.hash = '';
  const addDiscovery = (url, source) => {
    const parsed = new URL(url);
    if (!discovered.has(parsed.href)) discovered.set(parsed.href, new Set());
    discovered.get(parsed.href).add(source);
  };
  const normalizeInScope = (raw, base = targetUrl) => {
    try {
      const url = new URL(raw, base);
      if (!['http:', 'https:'].includes(url.protocol) || url.origin !== origin || url.username || url.password) {
        externalRejected++;
        return null;
      }
      url.hash = '';
      if ([...url.searchParams.keys()].some(isSensitiveParameterName)) return null;
      return url;
    } catch { return null; }
  };
  const isDisallowed = pathname => disallowed.some(prefix => prefix !== '/' && pathname.startsWith(prefix));
  const enqueue = (url, depth, source, kind = 'page', allowRoot = false) => {
    if (depth > limits.depth) return;
    const parsed = allowRoot ? rootUrl : normalizeInScope(url);
    if (!parsed) return;
    addDiscovery(parsed.href, source);
    if (isDisallowed(parsed.pathname) && !allowRoot) return;
    if (kind === 'script' && scriptsRead + queue.filter(item => item.kind === 'script').length >= limits.scripts) return;
    if (!visited.has(parsed.href) && !queue.some(item => item.url === parsed.href))
      queue.push({ url: parsed.href, depth, kind });
  };
  enqueue(rootUrl.href, 0, 'user-supplied target', 'page', true);
  enqueue(new URL('/robots.txt', origin).href, 0, 'robots.txt', 'robots');
  enqueue(new URL('/sitemap.xml', origin).href, 0, 'sitemap.xml', 'sitemap');
  const startedAt = Date.now();
  const toolId = 'autonomous-crawler';
  const toolName = 'Autonomous same-origin crawler';
  emit({ type: 'tool', id: toolId, name: toolName, status: 'running', installed: true });

  while (queue.length && requests < limits.pages && visited.size < limits.pages) {
    throwIfScanAborted();
    const item = queue.shift();
    if (visited.has(item.url) || (isDisallowed(new URL(item.url).pathname) && item.url !== rootUrl.href)) continue;
    visited.add(item.url);
    if (requests) await wait(300);
    requests++;
    let response;
    try {
      response = await request(item.url, {
        retry429: false,
        headers: { Accept: 'text/html,application/xhtml+xml,application/javascript,text/javascript,application/xml,text/xml;q=0.9,*/*;q=0.5' },
      }, 7000);
    } catch (error) {
      if (currentScanSignal()?.aborted) throw error;
      errors.push(`${safeReportUrl(item.url)}: ${redactScanSecrets(error?.message || error).slice(0, 200)}`);
      continue;
    }
    if (!response.ok || !response.status) {
      errors.push(`${safeReportUrl(item.url)}: ${response.error || 'request failed'}`);
      continue;
    }
    completedResponses++;
    if (response.status === 429) {
      rateLimited = true;
      errors.push(`${safeReportUrl(item.url)}: HTTP 429; crawl stopped to respect rate limiting.`);
      break;
    }
    if ([401, 403].includes(response.status)) {
      authRestricted++;
      continue;
    }
    if (response.status >= 300 && response.status < 400 && response.headers?.location) {
      const redirected = normalizeInScope(response.headers.location, item.url);
      if (redirected) enqueue(redirected.href, item.depth, 'same-origin redirect', item.kind);
      continue;
    }
    if (response.status < 200 || response.status >= 300) continue;

    const rawCookies = response.headers?.['set-cookie'] || [];
    for (const rawCookie of (Array.isArray(rawCookies) ? rawCookies : [rawCookies]).slice(0, 20)) {
      const parts = String(rawCookie).split(';');
      const name = String(parts.shift()?.split('=', 1)[0] || '').trim().slice(0, 100);
      if (!name) continue;
      const attributes = new Set(parts.map(part => part.trim().split('=', 1)[0].toLowerCase()));
      const missing = [];
      if (!attributes.has('httponly')) missing.push('HttpOnly');
      if (!attributes.has('samesite')) missing.push('SameSite');
      if (new URL(item.url).protocol === 'https:' && !attributes.has('secure')) missing.push('Secure');
      if (missing.length) {
        const key = `${name.toLowerCase()}|${new URL(item.url).pathname}|${missing.join(',')}`;
        cookieObservations.set(key, {
          name,
          endpoint: safeReportUrl(item.url),
          missing,
          sessionLike: /(?:session|auth|token|sid)/iu.test(name),
        });
      }
    }

    const contentType = String(response.headers?.['content-type'] || '').toLowerCase();
    if (item.kind === 'robots' || /\/robots\.txt(?:$|\?)/iu.test(new URL(item.url).pathname)) {
      const robots = parseRobotsDiscovery(response.body, item.url);
      disallowed.push(...robots.disallow);
      for (const sitemap of robots.sitemaps) enqueue(sitemap, item.depth + 1, 'robots.txt sitemap', 'sitemap');
      continue;
    }
    if (item.kind === 'sitemap' || /sitemap[^/]*\.xml$/iu.test(new URL(item.url).pathname)) {
      const locations = [...String(response.body || '').matchAll(/<loc\b[^>]*>\s*([^<\s]+)\s*<\/loc>/giu)]
        .slice(0, 200).map(match => match[1].trim());
      for (const location of locations) enqueue(location, item.depth + 1, 'sitemap.xml', 'page');
      continue;
    }
    const isScript = item.kind === 'script' || /\.(?:m?js)(?:$|\?)/iu.test(new URL(item.url).pathname) ||
      /(?:javascript|ecmascript)/iu.test(contentType);
    if (isScript) scriptsRead++;
    if (!isScript && !/(?:html|xhtml)/iu.test(contentType)) continue;
    const extraction = extractWebDiscovery(item.url, response.body, contentType);
    for (const field of extraction.fields) fields.set(`${item.url}|${field.name}|${field.type}`, { ...field, page: safeReportUrl(item.url) });
    for (const candidate of extraction.urls) {
      const candidateUrl = normalizeInScope(candidate.url, item.url);
      if (!candidateUrl) continue;
      if (candidate.sources.includes('form-action')) {
        addDiscovery(candidateUrl.href, 'form-action-not-submitted');
        continue;
      }
      const candidateIsScript = candidate.sources.includes('script-src') ||
        /\.(?:m?js)(?:$|\?)/iu.test(candidateUrl.pathname);
      enqueue(candidateUrl.href, item.depth + (candidateIsScript ? 0 : 1),
        candidate.sources.join(', ') || 'page link', candidateIsScript ? 'script' : 'page');
    }
  }

  const findings = [...cookieObservations.values()].slice(0, 30).map(cookie => ({
    k: `autonomous-cookie-flags-${crypto.createHash('sha256').update(`${cookie.name}|${cookie.endpoint}`).digest('hex').slice(0, 12)}`,
    sev: cookie.sessionLike ? 'low' : 'info',
    cwe: cookie.missing.includes('HttpOnly') ? 'CWE-1004' : cookie.missing.includes('Secure') ? 'CWE-614' : 'CWE-352',
    cvss: 0,
    title: `Cookie attributes need review: ${cookie.name}`,
    desc: 'A cookie was observed in an anonymous same-origin response without one or more recommended attributes. This alone does not prove the cookie is a sensitive session credential or exploitable.',
    fix: ['Confirm whether the cookie carries authentication or sensitive state, then apply Secure on HTTPS, HttpOnly when JavaScript access is unnecessary, and an appropriate SameSite policy.'],
    ep: cookie.endpoint,
    param: cookie.name,
    evidence: [`Anonymous GET ${cookie.endpoint}`, `Cookie name: ${cookie.name}; value intentionally not retained.`, `Missing attributes: ${cookie.missing.join(', ')}`],
    source: toolName,
    evidenceDetail: createEvidenceObject({
      vulnerabilityType: 'cookie-security-attribute-observation',
      parameter: cookie.name,
      observations: [`Missing attributes: ${cookie.missing.join(', ')}`, 'Cookie value was neither stored nor replayed.'],
      source: toolName,
    }),
  }));
  const status = rateLimited ? 'blocked' : errors.length ? completedResponses ? 'partial' : 'error' : 'ok';
  const output = `${requests} GET request(s); ${visited.size} page(s) visited; ${discovered.size} same-origin endpoint(s) discovered; ${scriptsRead} JavaScript asset(s) inspected; ${fields.size} form field(s) catalogued; ${authRestricted} access-restricted response(s); ${externalRejected} out-of-origin URL(s) rejected.${rateLimited ? ' Crawl stopped after HTTP 429.' : ''}`;
  const note = 'GET-only crawl; same-origin and robots.txt boundaries enforced. Forms are catalogued but never submitted; no credentials are guessed, harvested, or replayed.';
  const tool = {
    id: toolId, name: toolName, category: 'website', installed: true, status,
    elapsed: Date.now() - startedAt, note, output, ...(findings.length ? { findings } : {}),
  };
  const urls = [...discovered].map(([url, sources]) => ({
    url, sources: [...sources].slice(0, 5),
    source: [...sources][0] || 'autonomous crawler',
  })).slice(0, 100);
  const pipeline = {
    id: 'autonomous-crawl', name: toolName, status,
    inputs: [{ url: safeReportUrl(targetUrl), source: 'user-supplied target' }],
    steps: urls.slice(0, 40).map(item => ({ url: safeReportUrl(item.url), sources: item.sources })),
    inputCount: 1, outputCount: urls.length,
    rejectedOutOfScope: externalRejected,
    pageCount: visited.size, scriptCount: scriptsRead,
    formFieldCount: fields.size, restrictedCount: authRestricted,
    formFields: [...fields.values()].slice(0, 100),
    note: `${note}${errors.length ? ` ${errors.slice(0, 4).join('; ')}` : ''}`,
  };
  emit({ type: 'tool', ...tool });
  emit({ type: 'pipeline', ...pipeline });
  return { tool, pipeline, urls, formFields: [...fields.values()].slice(0, 100) };
}

async function runCrawlerSafely(targetUrl, profile, emit) {
  try {
    return await runAutonomousCrawler(targetUrl, profile, emit);
  } catch (error) {
    if (currentScanSignal()?.aborted) throw error;
    const message = redactScanSecrets(error?.message || error).slice(0, 1000);
    const tool = {
      id: 'autonomous-crawler', name: 'Autonomous same-origin crawler', category: 'website',
      installed: true, status: 'error',
      note: 'Crawler failed unexpectedly; the remaining scan stages will continue.',
      output: `Crawler failed: ${message}; remaining stages will continue.`,
    };
    const pipeline = {
      id: 'autonomous-crawl', name: tool.name, status: 'error',
      inputCount: 1, outputCount: 0, steps: [],
      note: tool.output,
    };
    emit({ type: 'tool', ...tool });
    emit({ type: 'pipeline', ...pipeline });
    return { tool, pipeline, urls: [], formFields: [] };
  }
}

async function runToolSuite(targetUrl, onProgress, requestedProfile = 'full', seedFindings = []) {
  const profile = normalizeScanProfile(requestedProfile);
  const scanOptions = currentScanOptions();
  const authEnabled = Object.keys(scanOptions.headers || {}).length > 0;
  const proxyEnabled = Boolean(scanOptions.proxy);
  const authCapableTools = new Set(['nuclei', 'ffuf', 'httpx', 'sqlmap']);
  const results = [];
  const emit = event => { if (onProgress) onProgress({ ...event, at: Date.now() }); };
  if (IS_PRODUCTION) {
    const crawl = await runCrawlerSafely(targetUrl, profile, emit);
    results.push(crawl.tool);
    for (const def of TOOL_DEFS) {
      if (def.id === 'autonomous-crawler') continue;
      const reason = 'معطّلة في وضع الإنتاج لأن الأدوات الخارجية تتجاوز فحص اتصال الشبكة الآمن.';
      const result = { id: def.id, name: def.bin, note: reason, output: `سبب عدم الفحص: ${reason}`, installed: false, status: 'disabled' };
      results.push(result);
      emit({ type: 'tool', ...result });
    }
    for (const item of REQUESTED_TOOL_CATALOG.filter(([id]) => !TOOL_DEFS.some(def => def.id === id))) {
      const notApplicable = CATALOG_NOT_WEB.has(item[2]);
      const reason = notApplicable ? `فئة ${item[2]} لا تنطبق على فحص الويب.` : 'الأداة موجودة في الكتالوج لكنها غير مرتبطة بمهمة الفحص الآمن الحالية.';
      const result = { id: item[0], name: item[1], category: item[2], installed: false,
        status: notApplicable ? 'not-applicable' : 'disabled', note: item[4], output: `سبب عدم الفحص: ${reason} ${item[4]}` };
      results.push(result); emit({ type: 'tool', ...result });
    }
    return { tools: results, findings: results.flatMap(result => result.findings || []), pipeline: [crawl.pipeline] };
  }
  const crawl = await runCrawlerSafely(targetUrl, profile, emit);
  results.push(crawl.tool);
  const queue = [...TOOL_DEFS];
  const worker = async () => { while (queue.length) {
    throwIfScanAborted();
    const def = queue.shift();
    try {
    if (def.id === 'autonomous-crawler' || def.id === 'sqlmap' || def.id === 'zap' || def.id === 'heuristic-fuzzer') continue;
    if (TLS_TOOL_IDS.has(def.id) && parsedTarget(targetUrl)?.protocol !== 'https:') {
      const reason = 'فحص TLS يتطلب عنوان HTTPS؛ الهدف يستخدم HTTP.';
      const skipped = { id: def.id, name: def.bin, installed: true, status: 'not-applicable', note: reason, output: `سبب عدم الفحص: ${reason}` };
      results.push(skipped); emit({ type: 'tool', ...skipped });
      continue;
    }
    const profileSkipReason = profileToolSkipReason(def.id, targetUrl, profile);
    if (profileSkipReason) {
      const skipped = { id: def.id, name: def.bin, installed: true,
        status: profile === 'quick' && !PASSIVE_DOMAIN_TOOL_IDS.has(def.id) ? 'not-run' : 'not-applicable',
        note: profileSkipReason, output: `سبب عدم الفحص: ${profileSkipReason}` };
      results.push(skipped); emit({ type: 'tool', ...skipped });
      continue;
    }
    if ((proxyEnabled || (authEnabled && ['nuclei', 'ffuf', 'httpx', 'nikto', 'wapiti', 'gobuster', 'wfuzz', 'whatweb'].includes(def.id))) &&
        !authCapableTools.has(def.id) && (proxyEnabled || authEnabled)) {
      const capability = authEnabled && proxyEnabled ? 'بيانات المصادقة والبروكسي' : authEnabled ? 'بيانات المصادقة' : 'البروكسي';
      const reason = `تم تخطي الأداة لضمان عدم تشغيلها دون ${capability}؛ الأدوات الموثقة دعمها لهذه الخيارات هي Nuclei وffuf وhttpx وSQLmap API.`;
      const skipped = { id: def.id, name: def.bin, installed: true, status: 'not-run', note: reason, output: `سبب عدم الفحص: ${reason}` };
      results.push(skipped); emit({ type: 'tool', ...skipped });
      continue;
    }
    const toolPath = await whichTool(def.bin);
    if (!toolPath) { const missing = { id: def.id, name: def.bin, note: def.note, installed: false, status: 'not-installed',
      output: `سبب عدم الفحص: الأداة ${def.bin} غير مثبتة في بيئة التشغيل الحالية.`,
      install: process.platform === 'win32'
        ? ({ nmap: 'winget install Insecure.Nmap', nuclei: 'go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest', whatweb: 'يتطلب Ruby — استخدم WSL/Kali', nikto: 'يتطلب Perl — استخدم WSL/Kali', gobuster: 'go install github.com/OJ/gobuster/v3@latest', wafw00f: 'pip install wafw00f', subfinder: 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest', httpx: 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest', 'testssl.sh': 'استخدم WSL/Kali', sslscan: 'استخدم WSL/Kali' }[def.id] || 'ثبّت الأداة يدوياً')
        : ({ nmap: 'apt install nmap', nikto: 'apt install nikto', nuclei: 'go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest', whatweb: 'apt install whatweb', gobuster: 'apt install gobuster', 'testssl.sh': 'apt install testssl.sh', sslscan: 'apt install sslscan', wafw00f: 'pip install wafw00f', subfinder: 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest', httpx: 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest' }[def.id] || 'apt install ' + def.bin) };
      results.push(missing); emit({ type: 'tool', ...missing });
      continue;
    }
    const t0 = Date.now();
    let binCmd = toolPath, args = def.args(targetUrl), extraEnv = {}, tempDir = null, extraFindings = [], toolCwd = undefined, stdin = def.stdin;
    if (toolPath.startsWith('PY:')) {
      binCmd = toolPath.slice(3);
      args = ['-m', 'wafw00f.cli', '-a', targetUrl];
    } else if (toolPath.startsWith('PERL:')) {
      const [perl, script] = toolPath.slice(5).split('|');
      if (def.id === 'nikto') { args = [script, '-config', path.join(TOOLS_DIR, 'nikto', 'program', 'nikto.conf.default'), '-h', targetUrl, '-nointeractive', '-Tuning', 'xb']; extraEnv = { PERL5LIB: path.join(TOOLS_DIR, 'perl-site'), PATH: `C:\\Program Files\\Git\\usr\\bin;${process.env.PATH || ''}` }; toolCwd = path.join(TOOLS_DIR, 'nikto', 'program'); }
      else { args = [script, '-q', '--no-errors', targetUrl]; extraEnv = { PERL5LIB: path.join(TOOLS_DIR, 'perl-site') }; }
      binCmd = perl;
    } else if (toolPath.startsWith('BASH:')) {
      const [bash, script] = toolPath.slice(5).split('|');
      binCmd = bash; args = [script, '--quiet', '--fast', '--warnings', 'off', targetUrl]; extraEnv = { PATH: `C:\\Program Files\\Git\\usr\\bin;${process.env.PATH || ''}` };
    } else if (toolPath.startsWith('RUBY:')) {
      const [ruby, script] = toolPath.slice(5).split('|');
      binCmd = ruby; args = [script, '--no-errors', '-q', targetUrl];
    } else if (def.id === 'nmap') {
      extraEnv = { NMAPDIR: path.join(TOOLS_DIR, 'nmap') };
      args = nmapArgs(targetUrl);
    } else if (def.id === 'nuclei') {
      extraEnv = { NUCLEI_TEMPLATES_DIR: path.join(TOOLS_DIR, 'nuclei', 'nuclei-templates-main') };
      for (const [name, value] of Object.entries(scanOptions.headers || {})) args.push('-H', `${name}: ${value}`);
      if (scanOptions.proxy) args.push('-p', scanOptions.proxy);
    } else if (def.id === 'ffuf') {
      for (const [name, value] of Object.entries(scanOptions.headers || {})) args.push('-H', `${name}: ${value}`);
      if (scanOptions.proxy) args.push('-x', scanOptions.proxy);
    } else if (def.id === 'httpx') {
      for (const [name, value] of Object.entries(scanOptions.headers || {})) args.push('-H', `${name}: ${value}`);
      if (scanOptions.proxy) args.push('-proxy', scanOptions.proxy);
    } else if (def.id === 'theharvester') {
      extraEnv = { PYTHONPATH: path.join(TOOLS_DIR, 'security-tools', 'theharvester') };
    } else if (def.id === 'wapiti') {
      extraEnv = { PYTHONPATH: path.join(TOOLS_DIR, 'venvs', 'wapiti', 'Lib', 'site-packages'), PYTHONIOENCODING: 'utf-8' };
      if (profile === 'deep') {
        for (const [flag, value] of [['--max-links-per-page','20'],['--depth','2'],['--tasks','3']]) {
          const index = args.indexOf(flag);
          if (index >= 0) args[index + 1] = value;
        }
      }
      tempDir = await fs.mkdtemp(path.join(TOOLS_DIR, '.wapiti-run-'));
      const reportPath = path.join(tempDir, 'report.json');
      const relativeTempDir = path.relative(process.cwd(), tempDir);
      args.push('--store-session', relativeTempDir, '--store-config', relativeTempDir, '--format', 'json', '--output', path.join(relativeTempDir, 'report.json'));
    }
    if (profile === 'deep' && def.id === 'gobuster') stdin = `${stdin || ''}admin.php\nbackup.zip\nserver-status\napi-docs\nswagger.json\nrobots.txt\nsitemap.xml\n`;
    const command = redactScanSecrets(displayCommand(def.bin, args));
    emit({ type: 'tool', id: def.id, name: def.bin, status: 'running', installed: true, command });
    // No runtime cap for scan tools; the authenticated owner can still cancel the job.
    const r = await execTool(binCmd, args, {
      timeout: 0, stdin, env: extraEnv, cwd: toolCwd,
      onOutput: ({ stream, text }) => emit({ type: 'tool-output', id: def.id, name: def.bin, status: 'output', stream, text: redactScanSecrets(text) }),
      maxLiveOutputBytes: 24000,
    });
    let toolOutput = redactScanSecrets(r.stdout || r.stderr).split('\n').filter(line => line.trim()).slice(0, 120).join('\n') || '(لا مخرجات — الهدف غير متاح أو لا نتائج)';
    if (def.id === 'ffuf') {
      extraFindings = parseFfufOutput(r.stdout, targetUrl);
      toolOutput = `ffuf JSONL: ${extraFindings.length} paths returned a matched response; these are path discoveries, not confirmed vulnerabilities.`;
    }
    if (def.id === 'nuclei') {
      extraFindings = parseNucleiOutput(redactScanSecrets(r.stdout), targetUrl);
      toolOutput = `Nuclei JSONL: ${extraFindings.length} template matches; validate findings manually.`;
    }
    if (def.id === 'nmap') {
      extraFindings = parseNmapXml(r.stdout, targetUrl);
      toolOutput = `Nmap XML: ${extraFindings.length} open-port service observation(s); these are inventory signals, not confirmed vulnerabilities.`;
    }
    if (def.id === 'wapiti' && tempDir) {
      try {
        const reportPath = path.join(tempDir, 'report.json');
        const report = JSON.parse(await fs.readFile(reportPath, 'utf8'));
        extraFindings = parseWapitiReport(report, targetUrl);
        toolOutput = `Wapiti JSON report: ${extraFindings.length} finding(s), ${Object.values(report.anomalies || {}).reduce((n, list) => n + (Array.isArray(list) ? list.length : 0), 0)} anomalies. Detailed report parsed and retained as evidence.`;
      } catch (error) { toolOutput += `\nتعذر قراءة تقرير JSON: ${error.message}`; }
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
    }
    throwIfScanAborted();
    const status = r.killed ? 'timeout' : r.error || r.code !== 0 ? 'error' : 'ok';
    if (status === 'timeout') toolOutput = `سبب توقف الأداة: انتهت المهلة المحددة للتشغيل؛ استمر باقي الفحص.\n${toolOutput}`;
    else if (status === 'error') toolOutput = `سبب تعذر الأداة: ${redactScanSecrets(r.error || r.stderr || `exit code ${r.code}`).slice(0, 1000)}؛ استمر باقي الفحص.\n${toolOutput}`;
    const result = { id: def.id, name: def.bin, note: def.note, installed: true, status, command, category: 'website',
      elapsed: Date.now() - t0, code: r.code,
      ...((r.error || r.stderr) ? { error: redactScanSecrets(r.error || r.stderr).slice(0, 1000) } : {}),
      output: toolOutput };
    results.push(result);
    if (extraFindings.length) result.findings = extraFindings;
    emit({ type: 'tool', ...result, summary: result.output.split('\n').slice(0, 3).join(' | ') });
    } catch (error) {
      if (currentScanSignal()?.aborted) throw error;
      const failed = { id: def.id, name: def.bin, category: 'website', note: def.note,
        installed: true, status: 'error', error: redactScanSecrets(error?.message || error).slice(0, 1000),
        output: `سبب تعذر الأداة: ${redactScanSecrets(error?.message || error).slice(0, 1000)}؛ يستمر فحص الهدف وبقية الأدوات.` };
      results.push(failed); emit({ type: 'tool', ...failed });
    }
  } };
  await Promise.all(Array.from({ length: Math.min(3, queue.length) }, worker));
  throwIfScanAborted();
  const discoveredFindings = [...seedFindings, ...results.flatMap(result => result.findings || [])];
  const pipelinePlan = buildPipelineTargets(scanOptions.targetUrl || targetUrl, discoveredFindings, {
    additionalUrls: crawl.urls,
  });
  const pipeline = [crawl.pipeline, {
    id: 'same-origin-handoff',
    name: 'Same-origin discovery handoff',
    status: 'completed',
    inputCount: discoveredFindings.length,
    outputCount: pipelinePlan.handoffs.length,
    rejectedOutOfScope: pipelinePlan.rejected,
    steps: pipelinePlan.handoffs.map(item => ({ url: safeReportUrl(item.url), sources: item.sources })),
    note: 'Only same-origin URLs are handed to optional engines; cross-origin and non-target-port URLs are rejected.',
  }];
  emit({ type: 'pipeline', ...pipeline[0] });
  let heuristicResult;
  try {
    heuristicResult = await runHeuristicFuzzer({
      targets: pipelinePlan.zapSeeds,
      enabled: scanOptions.enableHeuristicFuzzing,
      profile,
      emit,
    });
  } catch (error) {
    if (currentScanSignal()?.aborted) throw error;
    const message = redactScanSecrets(error?.message || error).slice(0, 1000);
    const tool = {
      id: 'heuristic-fuzzer', name: 'Bounded heuristic fuzzer', category: 'website',
      installed: true, status: 'error',
      note: 'Heuristic probe stage failed; optional integrations and reporting will continue.',
      output: `Heuristic probe stage failed: ${message}; remaining stages will continue.`,
    };
    const pipeline = {
      id: tool.id, name: tool.name, status: 'error', inputs: [], outputCount: 0,
      note: tool.output,
    };
    emit({ type: 'tool', ...tool });
    emit({ type: 'pipeline', ...pipeline });
    heuristicResult = { tool, pipeline };
  }
  results.push(heuristicResult.tool);
  pipeline.push(heuristicResult.pipeline);
  for (const id of ['sqlmap', 'zap']) {
    const enabled = id === 'sqlmap' ? scanOptions.enableSqlmap : scanOptions.enableZap;
    const configuredUrl = id === 'sqlmap' ? process.env.REASONIX_SQLMAP_API_URL : process.env.REASONIX_ZAP_API_URL;
    const credentialsConfigured = Boolean(process.env.REASONIX_SQLMAP_API_USERNAME && process.env.REASONIX_SQLMAP_API_PASSWORD);
    const selectedTarget = id === 'sqlmap' ? pipelinePlan.sqlmapTargets[0] || scanOptions.targetUrl || targetUrl : scanOptions.targetUrl || targetUrl;
    const skip = optionalIntegrationSkip(id, {
      profile,
      enabled,
      configuredUrl,
      apiCredentialsConfigured: id === 'sqlmap' ? credentialsConfigured : true,
      authEnabled,
      proxyEnabled,
      target: selectedTarget,
    });
    const name = id === 'sqlmap' ? 'SQLmap API' : 'OWASP ZAP API';
    const startedAt = Date.now();
    if (skip) {
      const skipped = {
        id, name, category: 'website', installed: Boolean(configuredUrl), status: skip.status,
        note: skip.reason, output: skip.reason,
      };
      results.push(skipped);
      pipeline.push({ id, name, status: skip.status, inputs: [], outputCount: 0, note: skip.reason });
      emit({ type: 'tool', ...skipped });
      emit({ type: 'pipeline', ...pipeline[pipeline.length - 1] });
      continue;
    }
    emit({ type: 'tool', id, name, status: 'running', installed: true });
    const findings = [];
    const stageOutputs = [];
    const stageFailures = [];
    let hadSuccessfulInput = false;
    let status = 'ok';
    let failureReason = '';
    let integrationOutput = '';
    if (id === 'sqlmap') {
      for (const url of pipelinePlan.sqlmapTargets) {
        throwIfScanAborted();
        const source = pipelinePlan.handoffs.find(item => item.url === url)?.sources || [];
        try {
          const outcome = await runSqlmapApiScan({
            apiUrl: configuredUrl,
            apiUsername: process.env.REASONIX_SQLMAP_API_USERNAME,
            apiPassword: process.env.REASONIX_SQLMAP_API_PASSWORD,
            apiKey: process.env.REASONIX_SQLMAP_API_KEY || '',
            target: url,
            headers: scanOptions.headers,
            proxy: scanOptions.proxy,
            signal: currentScanSignal(),
          });
          findings.push(...(outcome.findings || []));
          stageOutputs.push({ url, sources: source, status: outcome.status });
          if (outcome.output) integrationOutput = outcome.output;
          if (outcome.status === 'ok') hadSuccessfulInput = true;
          else if (status === 'ok') status = outcome.status;
        } catch (error) {
          const failure = optionalIntegrationFailure(id, error);
          stageFailures.push(`${safeReportUrl(url)}: ${failure.reason}`);
          if (!hadSuccessfulInput && status === 'ok') status = failure.status;
          stageOutputs.push({ url, sources: source, status: failure.status, reason: failure.reason });
          if (error?.code === 'LOCAL_API_OFFLINE') break;
        }
      }
      if (stageFailures.length) {
        if (hadSuccessfulInput) status = 'partial';
        failureReason = `${stageFailures.join(' ')}${hadSuccessfulInput ? ` Other inputs completed; ${findings.length} finding(s) emitted.` : ''}`;
      }
    } else {
      try {
        const outcome = await runZapPassiveScan({
          apiUrl: configuredUrl,
          apiKey: process.env.REASONIX_ZAP_API_KEY || '',
          target: selectedTarget,
          seedUrls: pipelinePlan.zapSeeds,
          signal: currentScanSignal(),
        });
        findings.push(...(outcome.findings || []));
        status = outcome.status || 'ok';
        integrationOutput = outcome.output || '';
        stageOutputs.push(...(outcome.inputs || pipelinePlan.zapSeeds.map(url => ({ url, status: outcome.status })))
          .map(input => ({
            ...input,
            sources: pipelinePlan.handoffs.find(item => {
              const parsed = new URL(item.url);
              return `${parsed.origin}${parsed.pathname}` === input.url;
            })?.sources || [],
          })));
      } catch (error) {
        const failure = optionalIntegrationFailure(id, error);
        status = failure.status;
        failureReason = failure.reason;
      }
    }
    const output = failureReason || integrationOutput ||
      `${name} completed for ${stageOutputs.length} same-origin input(s); ${findings.length} finding(s) emitted.`;
    const integrationResult = {
      id, name, category: 'website', installed: true, status, note: failureReason || (id === 'sqlmap' ? 'Bounded non-extractive SQL injection checks.' : 'Passive spidering only; no active scan.'),
      elapsed: Date.now() - startedAt, output,
      ...(failureReason ? { error: failureReason } : {}),
      ...(findings.length ? { findings } : {}),
    };
    results.push(integrationResult);
    const pipelineItem = {
      id, name, status, inputs: stageOutputs, outputCount: findings.length,
      note: failureReason || output,
    };
    pipeline.push(pipelineItem);
    emit({ type: 'tool', ...integrationResult });
    emit({ type: 'pipeline', ...pipelineItem });
  }
  const catalog = await Promise.all(REQUESTED_TOOL_CATALOG.filter(([id]) => !TOOL_DEFS.some(def => def.id === id)).map(catalogToolStatus));
  throwIfScanAborted();
  for (const result of catalog) { results.push(result); emit({ type: 'tool', ...result }); }
  const order = { ok: 0, partial: 1, timeout: 2, error: 3, 'not-installed': 4, 'not-applicable': 5, 'not-run': 6 };
  return {
    tools: results.sort((a, b) => order[a.status] - order[b.status]),
    findings: results.flatMap(result => result.findings || []),
    pipeline,
  };
}

const __origScanImpl = baseScan;
__scanImpl = async function (target, onProgress, profile = 'full') {
  throwIfScanAborted();
  const out = await enrichAndRun(target, onProgress, profile);
  throwIfScanAborted();
  const toolResult = await runToolSuite(out.target, onProgress, profile, out.findings);
  throwIfScanAborted();
  out.profile = normalizeScanProfile(profile);
  out.tools = toolResult.tools;
  out.coverage = { ...(out.coverage || {}), tools: toolResult.tools.map(tool => ({
    id: tool.id, name: tool.name, status: tool.status,
    reason: tool.status === 'ok' ? '' : tool.output || tool.error || tool.note || '',
  })) };
  out.coverage.pipeline = toolResult.pipeline;
  out.findings.push(...toolResult.findings);
  out.findings = out.findings.map(finding => ({
    ...finding,
    remediationGuide: finding.remediationGuide || remediationGuideFor(finding),
    evidenceDetail: finding.evidenceDetail || createEvidenceObject({
      vulnerabilityType: finding.k || finding.cwe || finding.title || 'unclassified signal',
      parameter: finding.param || null,
      payload: finding.payload || null,
      responseExcerpt: finding.responseExcerpt || null,
      dataExtracted: Array.isArray(finding.dataExtracted) ? finding.dataExtracted : [],
      observations: Array.isArray(finding.evidence) ? finding.evidence : [],
      source: finding.source || 'Reasonix probe',
    }),
  }));
  out.counts = out.findings.reduce((counts, finding) => (counts[finding.sev] = (counts[finding.sev] || 0) + 1, counts), {});
  out.engine = 'reasonix-live-probe v3.3 — HTTP/TLS, local tool integrations, and bounded heuristic probes';
  return out;
};

export async function toolInventory() {
  const mapWithConcurrency = async (items, limit, mapper) => {
    const results = new Array(items.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (true) {
        const index = next++;
        if (index >= items.length) return;
        results[index] = await mapper(items[index]);
      }
    }));
    return results;
  };
  const active = await mapWithConcurrency(TOOL_DEFS, 4, async def => {
    if (def.id === 'autonomous-crawler' || def.id === 'heuristic-fuzzer') {
      return {
        id: def.id,
        name: def.id === 'autonomous-crawler' ? 'Autonomous same-origin crawler' : 'Bounded heuristic fuzzer',
        category: 'website',
        note: `${def.note} Implemented in-process; no separate executable is required.`,
        installed: true,
        status: 'available',
      };
    }
    if (def.id === 'sqlmap' || def.id === 'zap') {
      const apiUrl = process.env[def.id === 'sqlmap' ? 'REASONIX_SQLMAP_API_URL' : 'REASONIX_ZAP_API_URL'];
      const apiConfigured = Boolean(apiUrl && (def.id === 'sqlmap'
        ? process.env.REASONIX_SQLMAP_API_USERNAME && process.env.REASONIX_SQLMAP_API_PASSWORD
        : process.env.REASONIX_ZAP_API_KEY));
      let apiStatus = apiConfigured ? 'blocked' : 'not-installed';
      let apiNote = apiConfigured
        ? `${def.note} API is configured but has not passed its health check.`
        : `${def.note} Configure ${def.id === 'sqlmap' ? 'REASONIX_SQLMAP_API_URL and Basic Auth credentials' : 'REASONIX_ZAP_API_URL and REASONIX_ZAP_API_KEY'} to enable this opt-in integration.`;
      if (apiConfigured) {
        try {
          const base = localApiBase(apiUrl, def.id === 'sqlmap' ? 'SQLmap' : 'OWASP ZAP');
          const healthUrl = new URL(def.id === 'sqlmap' ? '/version' : '/JSON/core/view/version/', base);
          const headers = def.id === 'sqlmap'
            ? { Authorization: `Basic ${Buffer.from(`${process.env.REASONIX_SQLMAP_API_USERNAME}:${process.env.REASONIX_SQLMAP_API_PASSWORD}`).toString('base64')}` }
            : {};
          if (def.id === 'zap') healthUrl.searchParams.set('apikey', process.env.REASONIX_ZAP_API_KEY);
          const response = await fetch(healthUrl, { headers, signal: AbortSignal.timeout(5000) });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const result = await response.json();
          if (typeof result?.version !== 'string' || !result.version) throw new Error('invalid health response');
          apiStatus = 'available';
          apiNote = `${def.note} Local API healthy (version ${result.version}); scans remain opt-in.`;
        } catch (error) {
          apiNote = `${def.note} Local API health check failed: ${String(error.message || error).replace(/https?:\/\/[^\s?]+(?:\?[^\s]*)?/giu, '[local API URL]').slice(0, 240)}`;
        }
      }
      return {
        id: def.id,
        name: def.id === 'sqlmap' ? 'SQLmap API' : 'OWASP ZAP API',
        category: 'website',
        note: apiNote,
        installed: apiConfigured,
        status: apiStatus,
      };
    }
    let checked;
    try { checked = await checkTool(def.bin); }
    catch (error) { checked = { installed: false, runnable: false, error: error.message }; }
    const status = !checked.installed ? 'not-installed' : checked.runnable ? 'available' : 'blocked';
    return { id: def.id, name: def.bin, category: 'website', note: checked.error ? `${def.note} — ${checked.error}` : def.note, installed: checked.installed, status };
  });
  const extraItems = REQUESTED_TOOL_CATALOG.filter(([id]) => !TOOL_DEFS.some(def => def.id === id));
  const extra = await mapWithConcurrency(extraItems, 4, async item => {
    if (CATALOG_NOT_WEB.has(item[2])) {
      return { id: item[0], name: item[1], category: item[2], installed: false, status: 'not-applicable', note: item[4] };
    }
    let checked = { installed: false, runnable: false };
    try { checked = await checkTool(item[3]); }
    catch (error) { checked.error = error.message; }
    return { id: item[0], name: item[1], category: item[2], note: item[4], installed: checked.installed,
      status: !checked.installed ? 'not-installed' : checked.runnable ? 'not-run' : 'blocked' };
  });
  return [...active, ...extra];
}
  /* ======================================================================
    v4 — طبقة الامتثال الأخلاقي (Vulnerability Assessment فقط)
   1) تحقق ملكية إلزامي عبر DNS TXT قبل أي فحص
   2) سجل مساءلة لكل طلب (IP، وقت، هدف)
   3) لا استغلال — الكاشفات كشف فقط، والاستجابة تتضمن عبارة النطاق الثابتة
   ====================================================================== */
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const LOG_FILE = path.resolve(process.env.REASONIX_AUDIT_LOG_PATH ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), 'scan-audit.log'));
const AUDIT_KEY = /^[a-f0-9]{64}$/i.test(process.env.REASONIX_DATA_KEY || '')
  ? Buffer.from(process.env.REASONIX_DATA_KEY, 'hex') : null;
const AUDIT_AAD = Buffer.from('reasonix-audit-log-v1');
const TENANT_ID_VALUE = String(process.env.REASONIX_TENANT_ID || (IS_PRODUCTION ? '' : 'local-development')).trim().toLowerCase();
const TENANT_ID = /^[a-z0-9][a-z0-9-]{0,59}$/u.test(TENANT_ID_VALUE) ? TENANT_ID_VALUE : '';
export function normalizeAllowedTargets(values) {
  if (!Array.isArray(values)) throw new Error('config.json must contain an allowedTargets array.');
  const targets = [];
  for (const item of values) {
    const isExactTarget = item && typeof item === 'object' && !Array.isArray(item);
    if (typeof item !== 'string' && !isExactTarget)
      throw new Error('Every allowed target must be a hostname/IP string or an exact-target object.');
    if (isExactTarget && (typeof item.hostname !== 'string' || typeof item.includeSubdomains !== 'boolean' ||
        Object.keys(item).some(key => !['hostname', 'includeSubdomains'].includes(key))))
      throw new Error('Exact targets must contain only a hostname string and includeSubdomains boolean.');
    const rawTarget = isExactTarget ? item.hostname : item;
    const target = rawTarget.trim().toLowerCase().replace(/\.$/u, '');
    /* wildcard مطلق: * يسمح بكل النطاقات (وضع الفحص التجريبي بدون رفض) */
    if (target === '*') { targets.push({ hostname: '*', includeSubdomains: true }); continue; }
    const validHostname = target.length <= 253 &&
      target.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label));
    if (!target || (!net.isIP(target) && !validHostname))
      throw new Error(`Invalid allowed target in config.json: ${rawTarget}`);
    targets.push(isExactTarget ? { hostname: target, includeSubdomains: item.includeSubdomains } : target);
  }
  const unique = new Map(targets.map(target => [
    typeof target === 'string' ? `root:${target}` : `exact:${target.hostname}:${target.includeSubdomains}`,
    target,
  ]));
  return [...unique.values()];
}

function loadAllowedTargets() {
  const configPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'config.json');
  try {
    const config = JSON.parse(fsSync.readFileSync(configPath, 'utf8'));
    if (!config || typeof config !== 'object' || Array.isArray(config))
      throw new Error('config.json must be a JSON object.');
    return normalizeAllowedTargets(config.allowedTargets);
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error(`Unable to load scan scope from config.json: ${error.message}`);
    const legacyTargets = String(process.env.REASONIX_ALLOWED_DOMAINS || '')
      .split(',').map(value => value.trim().toLowerCase().replace(/^\*\./u, '').replace(/\.$/u, '')).filter(Boolean);
    return normalizeAllowedTargets(legacyTargets);
  }
}

const ALLOWED_SCAN_DOMAINS = loadAllowedTargets();
const CONSENT_VERSION = 'reasonix-scan-consent-v1';
const CONSENT_TTL_MS = 30 * 60_000;
const ACTIVE_CONSENTS = new Map();
let auditQueue = Promise.resolve();
let auditInitialized = false;
let auditSequence = 0;
let auditPreviousHash = 'GENESIS';

function sealAuditEntry(entry) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AUDIT_KEY, iv);
  cipher.setAAD(AUDIT_AAD);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(entry), 'utf8'), cipher.final()]);
  return JSON.stringify({ version: 1, algorithm: 'aes-256-gcm', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') });
}

function openAuditEntry(record) {
  if (!record || record.version !== 1 || record.algorithm !== 'aes-256-gcm') return record;
  const decipher = crypto.createDecipheriv('aes-256-gcm', AUDIT_KEY, Buffer.from(record.iv, 'base64'));
  decipher.setAAD(AUDIT_AAD);
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(record.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
}

async function initializeAuditLog() {
  if (auditInitialized) return;
  if (!AUDIT_KEY) throw new Error('audit encryption key is unavailable');
  let raw;
  try { raw = await fs.readFile(LOG_FILE, 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') { auditSequence = 0; auditPreviousHash = 'GENESIS'; auditInitialized = true; return; }
    throw error;
  }
  const lines = raw.split(/\r?\n/).filter(Boolean);
  if (lines.length) {
    const entries = lines.map(line => openAuditEntry(JSON.parse(line)));
    const chained = entries.every(entry => Number.isInteger(entry?.sequence) && typeof entry?.integrityHash === 'string');
    const legacy = entries.every(entry => !Number.isInteger(entry?.sequence) && !entry?.integrityHash);
    if (!chained && !legacy) throw new Error('audit log contains mixed or malformed integrity records');
    let previousHash = 'GENESIS';
    const verifiedEntries = [];
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index];
      let verifiedEntry;
      if (legacy) verifiedEntry = createChainedAuditEntry(entry, index + 1, previousHash);
      else {
        const { integrityHash, ...content } = entry;
        const expected = auditEntryHash(content);
        if (entry.sequence !== index + 1 || entry.previousHash !== previousHash ||
            !/^[a-f0-9]{64}$/iu.test(integrityHash) ||
            !crypto.timingSafeEqual(Buffer.from(integrityHash, 'hex'), Buffer.from(expected, 'hex'))) {
          throw new Error(`audit log integrity verification failed at record ${index + 1}`);
        }
        verifiedEntry = entry;
      }
      verifiedEntries.push(verifiedEntry);
      previousHash = verifiedEntry.integrityHash;
    }
    const encrypted = verifiedEntries.map(sealAuditEntry).join('\n') + '\n';
    const temporary = `${LOG_FILE}.${crypto.randomBytes(8).toString('hex')}.tmp`;
    try {
      await fs.writeFile(temporary, encrypted, { flag: 'wx', mode: 0o600 });
      await fs.rename(temporary, LOG_FILE);
    } catch (error) { await fs.unlink(temporary).catch(() => {}); throw error; }
    auditSequence = verifiedEntries.length;
    auditPreviousHash = previousHash;
  }
  auditInitialized = true;
}

function auditEntryHash(content) {
  if (!AUDIT_KEY) throw new Error('audit encryption key is unavailable');
  return crypto.createHmac('sha256', AUDIT_KEY).update(JSON.stringify(content)).digest('hex');
}

function createChainedAuditEntry(entry, sequence, previousHash) {
  const content = { ...entry, sequence, previousHash };
  return { ...content, integrityHash: auditEntryHash(content) };
}

export function auditLog(entry) {
  if (!AUDIT_KEY) return Promise.reject(new Error('audit encryption key is unavailable'));
  const queued = auditQueue.then(async () => {
    await initializeAuditLog();
    const next = createChainedAuditEntry({ ts: new Date().toISOString(), ...entry }, auditSequence + 1, auditPreviousHash);
    await fs.appendFile(LOG_FILE, sealAuditEntry(next) + '\n', { encoding: 'utf8', mode: 0o600 });
    auditSequence = next.sequence;
    auditPreviousHash = next.integrityHash;
  });
  auditQueue = queued.catch(error => { console.error('audit log failed:', error.message); });
  return queued;
}

export function trustedScanIdentity(rq) {
  if (!AUDIT_KEY) return null;
  const issuedAt = String(rq.headers['x-reasonix-issued-at'] || '');
  const tenantId = String(rq.headers['x-reasonix-tenant'] || '');
  const user = String(rq.headers['x-reasonix-user'] || '').trim().toLowerCase();
  const ip = String(rq.headers['x-reasonix-ip'] || '');
  const signature = String(rq.headers['x-reasonix-signature'] || '');
  const timestamp = Number(issuedAt);
  if (!/^\d{13}$/u.test(issuedAt) || Math.abs(Date.now() - timestamp) > 60_000 ||
      !tenantId || tenantId.length > 100 || !user || user.length > 254 ||
      !ip || ip.length > 64 || !/^[a-f0-9]{64}$/iu.test(signature)) return null;
  const payload = [issuedAt, tenantId, user, ip].join('\n');
  const expected = crypto.createHmac('sha256', AUDIT_KEY).update(payload).digest();
  const provided = Buffer.from(signature, 'hex');
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) return null;
  if (TENANT_ID && tenantId !== TENANT_ID) return null;
  return { user, tenantId, ip };
}

export function tenantScopeFor(target, tenantId = TENANT_ID) {
  const domain = domainOf(target);
  if (!domain) return { ok: false, reason: 'invalid-target' };
  if (isLocalTarget(domain)) return { ok: true, domain, localDevelopment: true };
  if (!tenantId || tenantId !== TENANT_ID) return { ok: false, reason: 'tenant-not-configured', domain };
  if (!ALLOWED_SCAN_DOMAINS.length) return { ok: false, reason: 'allowed-domain-list-not-configured', domain };
  const allowed = isAllowedScanTarget(domain, ALLOWED_SCAN_DOMAINS);
  return allowed ? { ok: true, domain } : { ok: false, reason: 'outside-tenant-allowlist', domain };
}

export function isAllowedScanTarget(domain, allowedTargets) {
  const normalizedDomain = String(domain || '').toLowerCase().replace(/\.$/u, '');
  return allowedTargets.some(target => {
    /* wildcard مطلق: * يسمح بكل النطاقات */
    if (typeof target === 'string' && target === '*') return true;
    if (typeof target === 'object' && target.hostname === '*') return true;
    if (typeof target === 'string') return net.isIP(target)
      ? normalizedDomain === target
      : normalizedDomain === target || normalizedDomain.endsWith(`.${target}`);
    return normalizedDomain === target.hostname ||
      (target.includeSubdomains && normalizedDomain.endsWith(`.${target.hostname}`));
  });
}

function findConsent(token, identity) {
  if (typeof token !== 'string' || token.length < 32 || token.length > 200 || !identity) return null;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const consent = ACTIVE_CONSENTS.get(tokenHash);
  if (!consent || consent.expiresAt <= Date.now()) {
    if (consent) ACTIVE_CONSENTS.delete(tokenHash);
    return null;
  }
  return consent.user === identity.user && consent.tenantId === identity.tenantId ? consent : null;
}

function consumeConsent(token) {
  if (typeof token === 'string') ACTIVE_CONSENTS.delete(crypto.createHash('sha256').update(token).digest('hex'));
}

/* استثناء آمن: الأهداف المحلية/الخاصة للتجربة والتطوير — لا تحتاج TXT */
export function isLocalTarget(hostname) {
  if (IS_PRODUCTION) return false;
  if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.)/.test(hostname)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return true;
  return false;
}

function domainOf(t) { try { return new URL(t.startsWith('http') ? t : 'https://' + t).hostname; } catch { return null; } }

const DISCLAIMER = 'هذا تقرير فحص آلي (Vulnerability Scan) وليس اختبار اختراق كامل (Penetration Test) — لا يتضمن استغلالًا فعليًا للثغرات. الفحص تم على نطاق مدرج في قائمة السماح الخادمية، بواسطة مستخدم مسجل دخوله وبعد تسجيل الموافقة، وسُجّل الطلب في سجل التدقيق. يُنصح بمراجعة أمنية يدوية من خبير قبل اعتماد الإصلاحات على بيئة إنتاج (production).';
 
