// خادم عرض بسيط: node serve.mjs → يفتح الموقع على http://127.0.0.1:5500
import http from 'node:http';
import net from 'node:net';
import { readFile, writeFile, mkdir, rename, unlink } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exec, execFileSync } from 'node:child_process';
import { createCipheriv, createDecipheriv, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const ROOT = path.dirname(fileURLToPath(import.meta.url));
function loadLocalEnvironment() {
  if (process.env.NODE_ENV === 'production') return;
  try {
    for (const line of readFileSync(path.join(ROOT, '.env'), 'utf8').split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
    }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
loadLocalEnvironment();
function configureWslApiHosts() {
  if (process.platform !== 'win32' || process.env.NODE_ENV === 'production') return;
  const configuredApis = ['REASONIX_SQLMAP_API_URL', 'REASONIX_ZAP_API_URL'].filter(key => process.env[key]);
  if (!configuredApis.length) return;
  try {
    const distro = String(process.env.REASONIX_WSL_DISTRO || 'Ubuntu').trim() || 'Ubuntu';
    const output = execFileSync('wsl.exe', [
      '--distribution', distro, '--user', 'root', '--exec', 'hostname', '-I',
    ], { encoding: 'utf8', timeout: 15000, windowsHide: true });
    const host = output.trim().split(/\s+/u).find(value =>
      /^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/u.test(value));
    if (!host) return;
    process.env.REASONIX_WSL_API_HOST = host;
    for (const key of configuredApis) {
      const url = new URL(process.env[key]);
      if (['localhost', '127.0.0.1', '::1'].includes(url.hostname.replace(/^\[|\]$/gu, '').toLowerCase())) {
        url.hostname = host;
        process.env[key] = url.href;
      }
    }
  } catch (error) {
    console.warn('Optional WSL API host discovery failed:', error.message);
  }
}
configureWslApiHosts();
const rawDataKey = process.env.REASONIX_DATA_KEY || '';
if (!/^[a-f0-9]{64}$/i.test(rawDataKey)) throw new Error('Set REASONIX_DATA_KEY to a private 32-byte hex key before starting the server.');
const DATA_ENCRYPTION_KEY = Buffer.from(rawDataKey, 'hex');
const TENANT_ID_VALUE = String(process.env.REASONIX_TENANT_ID || (process.env.NODE_ENV === 'production' ? '' : 'local-development')).trim().toLowerCase();
const TENANT_ID = /^[a-z0-9][a-z0-9-]{0,59}$/.test(TENANT_ID_VALUE) ? TENANT_ID_VALUE : '';
const TRUSTED_PROXY_IPS = new Set(String(process.env.REASONIX_TRUSTED_PROXY_IPS || '').split(',').map(value => value.trim()).filter(value => net.isIP(value)));
const PORT = Number(process.env.PORT) || 5500;
let scanPort = Number(process.env.REASONIX_SCAN_PORT) || 17777;
const IS_PRODUCTION = process.env.NODE_ENV === 'production' ||
  (Boolean(process.env.PORT) && process.env.NODE_ENV !== 'development');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const sessions = new Map();
const authAttempts = new Map();
const scannerAttempts = new Map();
const scanStartQueues = new Map();
let activeFileUploads = 0;
const MAX_CONCURRENT_FILE_UPLOADS = 2;
const scrypt = promisify(scryptCallback);
let userMutationQueue = Promise.resolve();
const MAX_ACCOUNT_SCAN_SITES = 4;
const USER_STORE_AAD = Buffer.from('reasonix-user-store-v1');
const PAYMENT_REQUIRED = process.env.REASONIX_PAYMENT_REQUIRED === 'true';
const SUBSCRIPTION_PRICE = process.env.REASONIX_SUBSCRIPTION_PRICE || '';
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'X-Permitted-Cross-Domain-Policies': 'none',
  'X-DNS-Prefetch-Control': 'off',
  'Origin-Agent-Cluster': '?1',
  ...(IS_PRODUCTION ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
};
function contentSecurityPolicy(nonce) {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' https://cdn.tailwindcss.com`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    ...(IS_PRODUCTION ? ['upgrade-insecure-requests'] : []),
  ].join('; ');
}

async function readUsers() {
  try {
    const raw = await readFile(USERS_FILE, 'utf8');
    const store = JSON.parse(raw);
    if (Array.isArray(store)) return store;
    if (!store || store.version !== 1 || store.algorithm !== 'aes-256-gcm' || typeof store.iv !== 'string' || typeof store.tag !== 'string' || typeof store.ciphertext !== 'string')
      throw new Error('Unsupported encrypted account store format.');
    const decipher = createDecipheriv('aes-256-gcm', DATA_ENCRYPTION_KEY, Buffer.from(store.iv, 'base64'));
    decipher.setAAD(USER_STORE_AAD);
    decipher.setAuthTag(Buffer.from(store.tag, 'base64'));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(store.ciphertext, 'base64')), decipher.final()]).toString('utf8');
    const users = JSON.parse(plaintext);
    if (!Array.isArray(users)) throw new Error('Encrypted account store does not contain an account list.');
    return users;
  }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
}
function mutateUsers(operation) {
  const queued = userMutationQueue.then(operation);
  userMutationQueue = queued.catch(() => {});
  return queued;
}
async function writeUsers(users) {
  await mkdir(DATA_DIR, { recursive: true });
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', DATA_ENCRYPTION_KEY, iv);
  cipher.setAAD(USER_STORE_AAD);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(users), 'utf8'), cipher.final()]);
  const store = JSON.stringify({ version: 1, algorithm: 'aes-256-gcm', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') });
  const temporary = `${USERS_FILE}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    await writeFile(temporary, store, { flag: 'wx', mode: 0o600 });
    await rename(temporary, USERS_FILE);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}
async function initializeEncryptedUserStore() {
  try {
    const raw = await readFile(USERS_FILE, 'utf8');
    const existing = JSON.parse(raw);
    if (Array.isArray(existing)) await writeUsers(existing);
    else await readUsers();
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
function saveNewUser(user) {
  return mutateUsers(async () => {
    const users = await readUsers();
    if (users.some(item => item.email === user.email)) return false;
    users.push(user);
    await writeUsers(users);
    return true;
  });
}
function accountSiteKeys(user) {
  return [...new Set((Array.isArray(user?.scanSites) ? user.scanSites : [])
    .filter(site => typeof site === 'string' && site.length <= 253)
    .map(site => site.toLowerCase().replace(/\.$/, '').replace(/^www\./, '')))]
    .filter(Boolean).slice(0, MAX_ACCOUNT_SCAN_SITES);
}
function accountUsage(user) { return { scanSitesUsed: accountSiteKeys(user).length, scanSiteLimit: MAX_ACCOUNT_SCAN_SITES }; }
function siteKeyFromTarget(target) {
  if (typeof target !== 'string' || target.length > 2048) return null;
  try {
    const url = new URL(/^https?:\/\//i.test(target.trim()) ? target.trim() : `https://${target.trim()}`);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return url.hostname.toLowerCase().replace(/\.$/, '').replace(/^www\./, '') || null;
  } catch { return null; }
}
async function reserveAccountSite(email, siteKey) {
  return mutateUsers(async () => {
    const users = await readUsers();
    const user = users.find(item => item.email === email);
    if (!user) return { allowed: false, code: 'account-not-found', used: 0 };
    const sites = accountSiteKeys(user);
    if (sites.includes(siteKey)) return { allowed: true, added: false, used: sites.length };
    if (sites.length >= MAX_ACCOUNT_SCAN_SITES) return { allowed: false, code: 'site-limit-reached', used: sites.length };
    sites.push(siteKey);
    user.scanSites = sites;
    await writeUsers(users);
    return { allowed: true, added: true, used: sites.length };
  });
}
async function releaseAccountSite(email, siteKey) {
  return mutateUsers(async () => {
    const users = await readUsers();
    const user = users.find(item => item.email === email);
    if (!user || !Array.isArray(user.scanSites)) return;
    user.scanSites = accountSiteKeys(user).filter(site => site !== siteKey);
    await writeUsers(users);
  });
}
function serializeScanStart(email, operation) {
  const previous = scanStartQueues.get(email) || Promise.resolve();
  const current = previous.then(operation, operation);
  const settled = current.then(() => undefined, () => undefined);
  scanStartQueues.set(email, settled);
  return current.finally(() => { if (scanStartQueues.get(email) === settled) scanStartQueues.delete(email); });
}
function registrationFailure(error) {
  if (error?.code === 'ENOSPC') return 'مساحة تخزين الخادم ممتلئة؛ لم يتم إنشاء الحساب.';
  if (['EACCES', 'EPERM', 'EROFS'].includes(error?.code)) return 'الخادم لا يملك صلاحية حفظ الحسابات؛ لم يتم إنشاء الحساب.';
  if (error instanceof SyntaxError) return 'تعذر قراءة بيانات الحسابات على الخادم؛ لم يتم إنشاء الحساب. أبلغ الدعم بهذه الرسالة.';
  return 'حدث خطأ أثناء حفظ الحساب على الخادم؛ لم يتم إنشاء الحساب. حاول مرة أخرى بعد قليل.';
}
function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...headers });
  res.end(JSON.stringify(body));
}
function hasSameOrigin(req) {
  if (req.headers['sec-fetch-site'] === 'cross-site') return false;
  const suppliedOrigin = req.headers.origin || req.headers.referer;
  const host = String(req.headers.host || '').toLowerCase();
  if (!suppliedOrigin || !host) return false;
  try {
    const origin = new URL(suppliedOrigin);
    return ['http:', 'https:'].includes(origin.protocol) && origin.host.toLowerCase() === host;
  } catch { return false; }
}
async function readBody(req) {
  let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 16_384) throw new Error('Request too large'); }
  return JSON.parse(raw || '{}');
}
function sessionUser(req) {
  const cookie = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('reasonix_session='));
  const token = cookie?.slice('reasonix_session='.length);
  const stored = token && sessions.get(token);
  if (!stored) return null;
  if (stored.expiresAt <= Date.now()) { sessions.delete(token); return null; }
  return { token, email: stored.email };
}
async function authRoute(req, res, pathname) {
  if (req.method === 'GET' && pathname === '/api/auth/config') {
    return sendJson(res, 200, { paymentRequired: PAYMENT_REQUIRED, price: SUBSCRIPTION_PRICE, paymentReady: false });
  }
  if (req.method === 'GET' && pathname === '/api/auth/me') {
    const session = sessionUser(req);
    if (!session) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول.' });
    const user = (await readUsers()).find(item => item.email === session.email);
    if (PAYMENT_REQUIRED && !user?.paidAt) return sendJson(res, 402, { error: 'الاشتراك غير مدفوع أو لم يتم تأكيد الدفع.' });
    return user ? sendJson(res, 200, { user: { name: user.name, email: user.email, ...accountUsage(user) } }) : sendJson(res, 401, { error: 'الجلسة غير صالحة.' });
  }
  if (req.method === 'POST' && ['/api/auth/signup', '/api/auth/login', '/api/auth/logout'].includes(pathname) &&
      !String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json'))
    return sendJson(res, 415, { error: 'نوع بيانات الطلب غير مدعوم.' });
  if (req.method === 'POST' && pathname === '/api/auth/signup') {
    if (!allowAuthAttempt(req)) return sendJson(res, 429, { error: 'محاولات كثيرة. انتظر قليلًا ثم أعد المحاولة.' });
    const input = await readBody(req);
    const name = String(input.name || '').trim().slice(0, 100);
    const email = String(input.email || '').trim().toLowerCase();
    const password = String(input.password || '');
    if (name.length < 2 || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 256)
      return sendJson(res, 400, { error: 'تحقق من الاسم والبريد وكلمة المرور (8 أحرف على الأقل).' });
    if (PAYMENT_REQUIRED) return sendJson(res, 503, { error: SUBSCRIPTION_PRICE ? 'الدفع مطلوب، لكن بوابة الدفع غير مفعّلة بعد. لم يتم إنشاء الحساب.' : 'التسجيل المدفوع غير متاح حتى يتم تحديد سعر الاشتراك وربط بوابة الدفع. لم يتم إنشاء الحساب.' });
    let saved;
    try {
      const salt = randomBytes(16).toString('hex');
      const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
      saved = await saveNewUser({ name, email, salt, passwordHash, scanSites: [], createdAt: new Date().toISOString() });
    } catch (error) {
      console.error('signup failed:', error);
      return sendJson(res, 503, { code: 'signup-save-failed', error: registrationFailure(error) });
    }
    if (!saved) return sendJson(res, 409, { error: 'هذا البريد مسجل مسبقًا. سجّل الدخول بدلًا من ذلك.' });
    const token = randomBytes(32).toString('hex'); sessions.set(token, { email, expiresAt: Date.now() + 7 * 24 * 60 * 60_000 });
    return sendJson(res, 201, { user: { name, email, scanSitesUsed: 0, scanSiteLimit: MAX_ACCOUNT_SCAN_SITES } }, { 'Set-Cookie': sessionCookie(token) });
  }
  if (req.method === 'POST' && pathname === '/api/auth/login') {
    if (!allowAuthAttempt(req)) return sendJson(res, 429, { error: 'محاولات كثيرة. انتظر قليلًا ثم أعد المحاولة.' });
    const input = await readBody(req);
    const email = String(input.email || '').trim().toLowerCase();
    const password = String(input.password || '');
    const user = (await readUsers()).find(item => item.email === email);
    if (!user || !password || password.length > 256) return sendJson(res, 401, { error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' });
    const candidate = Buffer.from(await scrypt(password, user.salt, 64));
    const expected = Buffer.from(user.passwordHash, 'hex');
    if (expected.length !== candidate.length || !timingSafeEqual(candidate, expected)) return sendJson(res, 401, { error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' });
    if (PAYMENT_REQUIRED && !user.paidAt) return sendJson(res, 402, { error: 'الاشتراك غير مدفوع أو لم يتم تأكيد الدفع.' });
    const token = randomBytes(32).toString('hex'); sessions.set(token, { email, expiresAt: Date.now() + 7 * 24 * 60 * 60_000 });
    return sendJson(res, 200, { user: { name: user.name, email, ...accountUsage(user) } }, { 'Set-Cookie': sessionCookie(token) });
  }
  if (req.method === 'POST' && pathname === '/api/auth/logout') {
    const session = sessionUser(req); if (session) sessions.delete(session.token);
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': 'reasonix_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }
  /* ====== مفتاح AI API لكل حساب + استدعاء المساعد عبر مزود حقيقي ====== */
  const VALID_AI_PROVIDERS = ['openai', 'gemini', 'anthropic'];
  function maskKey(key) {
    if (!key) return '';
    return key.length <= 8 ? '••••' : key.slice(0, 3) + '••••' + key.slice(-4);
  }
  async function aiProviderCall(provider, apiKey, messages) {
    const urls = {
      openai: 'https://api.openai.com/v1/chat/completions',
      gemini: 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent',
      anthropic: 'https://api.anthropic.com/v1/messages',
    };
    const url = urls[provider];
    const headers = { 'Content-Type': 'application/json' };
    let payload;
    if (provider === 'openai') {
      headers.Authorization = `Bearer ${apiKey}`;
      payload = { model: 'gpt-4o-mini', messages, temperature: 0.3 };
    } else if (provider === 'gemini') {
      headers['x-goog-api-key'] = apiKey;
      payload = { contents: messages.map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })) };
    } else {
      headers['x-api-key'] = apiKey;
      headers['anthropic-version'] = '2023-06-01';
      payload = { model: 'claude-3-5-sonnet-20241022', max_tokens: 1024, messages };
    }
    const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = data?.error?.message || data?.message || `HTTP ${response.status}`;
      return { ok: false, error: detail.slice(0, 300) };
    }
    let text = '';
    if (provider === 'openai') text = data?.choices?.[0]?.message?.content || '';
    else if (provider === 'gemini') text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    else text = data?.content?.[0]?.text || '';
    return { ok: true, text };
  }
  if (req.method === 'GET' && pathname === '/api/ai/key') {
    if (!session) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول.' });
    const user = (await readUsers()).find(item => item.email === session.email);
    return sendJson(res, 200, { provider: VALID_AI_PROVIDERS.includes(user?.aiProvider) ? user.aiProvider : 'openai', hasKey: Boolean(user?.aiApiKey), maskedKey: maskKey(user?.aiApiKey || '') });
  }
  if (req.method === 'POST' && pathname === '/api/ai/key') {
    if (!session) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول.' });
    const input = await readBody(req);
    const provider = VALID_AI_PROVIDERS.includes(String(input.provider || '').toLowerCase()) ? String(input.provider).toLowerCase() : 'openai';
    const key = String(input.key || '').trim();
    if (key.length > 512) return sendJson(res, 400, { error: 'المفتاح طويل جداً (الحد 512 حرفاً).' });
    const updated = await mutateUsers(async () => {
      const users = await readUsers();
      const user = users.find(item => item.email === session.email);
      if (!user) return null;
      user.aiProvider = provider;
      if (key) user.aiApiKey = key;
      else if (input.clear === true) delete user.aiApiKey;
      await writeUsers(users);
      return { provider: user.aiProvider, hasKey: Boolean(user.aiApiKey), maskedKey: maskKey(user.aiApiKey || '') };
    });
    if (!updated) return sendJson(res, 404, { error: 'الحساب غير موجود؛ سجّل الدخول من جديد.' });
    return sendJson(res, 200, updated);
  }
  if (req.method === 'POST' && pathname === '/api/ai/ask') {
    if (!session) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول.' });
    const input = await readBody(req);
    const question = String(input.question || '').trim().slice(0, 4000);
    if (!question) return sendJson(res, 400, { error: 'السؤال مطلوب.' });
    const user = (await readUsers()).find(item => item.email === session.email);
    const provider = VALID_AI_PROVIDERS.includes(user?.aiProvider) ? user.aiProvider : 'openai';
    const apiKey = user?.aiApiKey || process.env.AI_API_KEY || '';
    if (!apiKey) return sendJson(res, 409, { error: 'no-api-key', message: 'أضف مفتاح AI API من الإعدادات لتشغيل الوكيل الأمني.' });
    const systemPrompt = [
      'أنت "Reasonix Cyber Agent" — وكيل الذكاء الاصطناعي المتقدم المسؤول عن الفحص الهجومي، محاكاة الاختراق، وتحليل الثغرات داخل منصة Reasonix Ethical Hacker.',
      'مهمتك: قيادة عملية الفحص الهجومي واختبار الاختراق التلقائي بدقة عالية، وتوجيه الأدوات المدمجة (محرك الفحص والزاحح، وكيل الأدوات Nmap→Nikto→Dirb/Gobuster→Nuclei/SQLmap) لاستكشاف الثغرات ومحاكاة الاستغلال للحصول على أدلة الإثبات (PoC) ضمن النطاق المصرح به فقط.',
      'خطتك المنهجية عند استلام هدف مصرح به:',
      '1) الاستطلاع: Nmap للمنافذ/الخدمات/النسخ، WhatWeb للتقنيات، Dirb/Gobuster للمسارات المخفية.',
      '2) اكتشاف الثغرات: Nikto وNuclei للتكوينات الخاطئة، التحقق من JWT/IDOR/Broken Auth/CORS، وفحص OWASP Top 10 (SQLi, XSS, CSRF, RCE, SSRF).',
      '3) محاكاة الاستغلال: تحليل المدخلات مع SQLmap للتحقق من استخراج البيانات بدقة دون إضرار بالنظام، واقتراح وحدات Metasploit الأنسب مع الأوامر الجاهزة، واستخراج أدلة الإثبات (اسم قاعدة البيانات، النطاق المتاح، ترويسات الاستجابة).',
      'صيغة تقريرك:',
      'أ) الملخص التنفيذي: مستوى الأمان العام، عدد النتائج المفتوحة، درجة CVSS العامة.',
      'ب) جدول الثغرات: الاسم، المسار المتأثر (Endpoint/Parameter)، درجة CVSS والمستوى، دليل الإثبات (PoC) وشفرة الاستغلال، البيانات المستخرجة (Data Exfiltration Proof).',
      'ج) خطة الإصلاح والأولوية: الخطوات البرمجية لإغلاق الثغرة (Patching Code)، وإرشادات أمان السحابة والشبكة والاعتماديات.',
      'قواعد التشغيل: اعتمد فقط على البيانات الحقيقية من الأدوات لتقليل النتائج الإيجابية الخاطئة؛ عند فشل أداة أو مواجهة حظر (Rate-Limiting/WAF) اقترح تعديل المعلمات أو أداة بديلة فورًا.',
      'قيد أخلاقي صارم: كل هذا يقتصر على أهداف مصرَّح بها كتابياً (Authorized/Lab). لا تقدم إرشادات لأنشطة غير قانونية — اقترح دائماً إصلاحات دفاعية مع تقنيات الاستغلال.',
      'أجب بالعربية أو الإنجليزية حسب لغة السؤال.',
    ].join('\n');
    const history = Array.isArray(input.history) ? input.history.slice(-6)
      .filter(m => m && typeof m.q === 'string' && typeof m.a === 'string')
      .flatMap(m => [{ role: 'user', content: String(m.q).slice(0, 2000) }, { role: 'assistant', content: String(m.a).slice(0, 2000) }]) : [];
    const messages = [
      { role: 'system', content: systemPrompt },
      ...history,
      { role: 'user', content: question },
    ];
    const started = Date.now();
    try {
      const result = await aiProviderCall(provider, apiKey, messages);
      if (!result.ok) return sendJson(res, 502, { error: 'ai-provider-error', message: result.error });
      return sendJson(res, 200, { text: result.text, provider, elapsed: Date.now() - started });
    } catch (error) {
      return sendJson(res, 502, { error: 'ai-provider-unreachable', message: String(error?.message || error).slice(0, 300) });
    }
  }
  return false;
}
function allowAuthAttempt(req) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  if (authAttempts.size > 10_000) for (const [address, entry] of authAttempts) if (entry.resetAt <= now) authAttempts.delete(address);
  const record = authAttempts.get(ip) || { count: 0, resetAt: now + 15 * 60_000 };
  if (now > record.resetAt) { record.count = 0; record.resetAt = now + 15 * 60_000; }
  record.count++;
  authAttempts.set(ip, record);
  return record.count <= 20;
}
function sessionCookie(token) {
  const secure = IS_PRODUCTION ? '; Secure' : '';
  return `reasonix_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${secure}`;
}

function clientIpForAudit(req) {
  const peer = String(req.socket.remoteAddress || 'unknown');
  if (!TRUSTED_PROXY_IPS.has(peer)) return peer;
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',').map(value => value.trim());
  for (let index = forwarded.length - 1; index >= 0; index--) {
    if (net.isIP(forwarded[index])) return forwarded[index];
  }
  return peer;
}

async function proxyScanner(req, res, pathname, search) {
  const session = sessionUser(req);
  const anonymousQuickScan = req.method === 'POST' && pathname === '/quick-scan';
  if (!session && !anonymousQuickScan) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول.' });
  const allowed = (req.method === 'GET' && ['/health', '/tools', '/knowledge', '/scan/status'].includes(pathname)) ||
    (req.method === 'POST' && ['/scan/start', '/scan/cancel', '/consent/accept', '/file-scan', '/quick-scan'].includes(pathname));
  if (!allowed) return sendJson(res, 404, { error: 'Not found' });
  if (anonymousQuickScan && !TENANT_ID)
    return sendJson(res, 503, { error: 'الفحص السريع غير متاح قبل إعداد نطاق المؤسسة.' });
  if (req.method === 'POST' && pathname !== '/file-scan' &&
      !String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json'))
    return sendJson(res, 415, { error: 'يجب إرسال بيانات الطلب بصيغة JSON.' });
  const identityIp = clientIpForAudit(req);
  const identityUser = session?.email || `anonymous-${identityIp}`.toLowerCase();
  if (req.method === 'POST' && !allowScannerAttempt(identityUser, pathname))
    return sendJson(res, 429, { error: 'طلبات كثيرة. انتظر دقيقة ثم أعد المحاولة.' });
  if (PAYMENT_REQUIRED && session) {
    const user = (await readUsers()).find(item => item.email === session.email);
    if (!user?.paidAt) return sendJson(res, 402, { error: 'الاشتراك غير مدفوع أو لم يتم تأكيد الدفع.' });
  }
  const forward = async () => {
    const target = `http://127.0.0.1:${scanPort}${pathname}${search}`;
    const headers = {};
    if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
    headers['x-reasonix-user'] = identityUser;
    const identityTime = String(Date.now());
    const identityPayload = [identityTime, TENANT_ID, identityUser, identityIp].join('\n');
    headers['x-reasonix-tenant'] = TENANT_ID;
    headers['x-reasonix-ip'] = identityIp;
    headers['x-reasonix-issued-at'] = identityTime;
    headers['x-reasonix-signature'] = createHmac('sha256', DATA_ENCRYPTION_KEY).update(identityPayload).digest('hex');
    const isUpload = pathname === '/file-scan' && req.method === 'POST';
    let input = null;
    let body;
    if (!['GET', 'HEAD'].includes(req.method)) {
      if (isUpload) {
        const declaredLength = Number(req.headers['content-length'] || 0);
        if (declaredLength > 52 * 1024 * 1024) throw new Error('Request too large');
        const chunks = []; let size = 0;
        for await (const chunk of req) { size += chunk.length; if (size > 52 * 1024 * 1024) throw new Error('Request too large'); chunks.push(chunk); }
        body = Buffer.concat(chunks);
      } else { input = await readBody(req); body = JSON.stringify(input); }
    }
    let siteKey = null;
    let reservation = null;
    if (req.method === 'POST' && pathname === '/scan/start') {
      siteKey = siteKeyFromTarget(input?.target);
      if (!siteKey) return sendJson(res, 400, { code: 'invalid-site', error: 'تعذر تحديد الموقع من العنوان. أدخل نطاقًا أو عنوان IP صالحًا.' });
      try { reservation = await reserveAccountSite(session.email, siteKey); }
      catch (error) {
        console.error('scan site quota save failed:', error);
        return sendJson(res, 503, { code: 'site-quota-save-failed', error: 'تعذر حفظ حصة المواقع لهذا الحساب؛ لم يبدأ الفحص. حاول مرة أخرى.' });
      }
      if (!reservation.allowed) {
        if (reservation.code === 'account-not-found') return sendJson(res, 401, { error: 'الحساب غير موجود؛ سجّل الدخول من جديد.' });
        return sendJson(res, 403, { code: 'site-limit-reached', scanSitesUsed: reservation.used, scanSiteLimit: MAX_ACCOUNT_SCAN_SITES,
          error: 'وصلت إلى الحد الأقصى: أربعة مواقع مختلفة لهذا الحساب. تستطيع إعادة فحص موقع سبق فحصه، لكن لا يمكن إضافة موقع خامس.' });
      }
    }
    try {
      if (isUpload) headers['content-length'] = String(body.length);
      const upstream = await fetch(target, { method: req.method, headers, body });
      const responseBody = Buffer.from(await upstream.arrayBuffer());
      if (pathname === '/quick-scan') {
        let payload;
        try { payload = JSON.parse(responseBody.toString('utf8')); }
        catch { return sendJson(res, 502, { error: 'تعذر قراءة نتيجة الفحص السريع.' }); }
        if (upstream.ok && payload?.ok === true) {
          const tools = Array.isArray(payload.tools) ? payload.tools
            .filter(tool => ['nmap', 'sqlmap'].includes(tool?.id))
            .map(tool => ({
              id: tool.id,
              name: tool.id,
              installed: Boolean(tool.installed),
              status: String(tool.status || 'unknown').slice(0, 32),
              command: String(tool.command || '').slice(0, 2000),
              note: String(tool.note || '').slice(0, 500),
              elapsed: Math.max(0, Math.min(300_000, Number(tool.elapsed) || 0)),
              output: String(tool.output || '').slice(0, 2000),
            })) : [];
          const findings = Array.isArray(payload.findings) ? payload.findings.slice(0, 100).map(finding => ({
            k: String(finding?.k || '').slice(0, 120),
            sev: ['critical', 'high', 'medium', 'low', 'info'].includes(finding?.sev) ? finding.sev : 'info',
            title: String(finding?.title || 'نتيجة فحص').slice(0, 240),
            desc: String(finding?.desc || '').slice(0, 2000),
            ep: String(finding?.ep || '').slice(0, 500),
            cvss: Number.isFinite(Number(finding?.cvss)) ? Math.max(0, Math.min(10, Number(finding.cvss))) : 0,
            real: finding?.real === true,
            evidence: Array.isArray(finding?.evidence)
              ? finding.evidence.slice(0, 20).map(item => String(item).slice(0, 500)) : [],
            fix: Array.isArray(finding?.fix)
              ? finding.fix.slice(0, 20).map(item => String(item).slice(0, 500)) : [],
            cwe: String(finding?.cwe || '').slice(0, 40),
            source: String(finding?.source || '').slice(0, 100),
          })) : [];
          const counts = Object.fromEntries(['critical', 'high', 'medium', 'low', 'info']
            .map(severity => [severity, Math.max(0, Math.min(100, Number(payload.counts?.[severity]) || 0))]));
          return sendJson(res, upstream.status, { ok: true, target: String(payload.target || '').slice(0, 2000), tools, findings, counts,
            disclaimer: 'فحص سريع محدود (Nmap + SQLmap). عدم ظهور نتائج لا يثبت خلو الهدف من الثغرات.' });
        }
        const status = upstream.status === 200 ? 400 : upstream.status;
        const errors = {
          400: 'تعذر تحليل الطلب أو الهدف.',
          403: 'الهدف خارج النطاق المصرح به.',
          409: 'يوجد فحص سريع جارٍ لهذا الهدف.',
          429: 'تم تجاوز حد الفحص السريع؛ حاول لاحقاً.',
        };
        return sendJson(res, status, { error: errors[status] || 'تعذر إكمال الفحص السريع.' });
      }
      if (siteKey && reservation) {
        let payload;
        try { payload = JSON.parse(responseBody.toString('utf8')); } catch { payload = null; }
        const started = upstream.ok && typeof payload?.scanId === 'string';
        if (!started && reservation.added) await releaseAccountSite(session.email, siteKey);
        if (started) return sendJson(res, upstream.status, { ...payload, scanSitesUsed: reservation.used, scanSiteLimit: MAX_ACCOUNT_SCAN_SITES });
      }
      res.writeHead(upstream.status, { 'Content-Type': upstream.headers.get('content-type') || 'application/json', 'Cache-Control': 'no-store', ...SECURITY_HEADERS });
      res.end(responseBody);
    } catch (error) {
      if (siteKey && reservation?.added) {
        try { await releaseAccountSite(session.email, siteKey); }
        catch (releaseError) { console.error('scan site quota rollback failed:', releaseError); }
      }
      throw error;
    }
  };
  if (pathname === '/file-scan' && req.method === 'POST') {
    if (activeFileUploads >= MAX_CONCURRENT_FILE_UPLOADS) {
      req.resume();
      return sendJson(res, 429, { code: 'upload-busy', error: 'هناك عمليتا تحليل ملفات قيد التنفيذ؛ انتظر قليلاً ثم أعد المحاولة.' });
    }
    activeFileUploads++;
    try { return await forward(); }
    finally { activeFileUploads--; }
  }
  if (req.method === 'POST' && pathname === '/scan/start') return serializeScanStart(session.email, forward);
  return forward();
}
function allowScannerAttempt(email, pathname) {
  const key = email + ':' + pathname;
  const now = Date.now();
  if (scannerAttempts.size > 10_000) for (const [entryKey, entry] of scannerAttempts) if (entry.resetAt <= now) scannerAttempts.delete(entryKey);
  let record = scannerAttempts.get(key);
  if (!record || now >= record.resetAt) record = { count: 0, resetAt: now + 60_000 };
  record.count++;
  scannerAttempts.set(key, record);
  const limit = pathname === '/scan/start' ? 3 : pathname === '/quick-scan' ? 5 : 10;
  return record.count <= limit;
}

const server = http.createServer(async (req, res) => {
  try {
    const pathname = new URL(req.url, 'http://localhost').pathname;
    const parsedUrl = new URL(req.url, 'http://localhost');
    if (req.method !== 'GET' && req.method !== 'HEAD' && pathname.startsWith('/api/') && !hasSameOrigin(req))
      return sendJson(res, 403, { code: 'cross-origin-request', error: 'تم رفض الطلب لأنه لم يصدر من نفس موقع التطبيق.' });
    if (pathname.startsWith('/api/scanner/')) {
      await proxyScanner(req, res, pathname.slice('/api/scanner'.length), parsedUrl.search);
      return;
    }
    if (pathname.startsWith('/api/auth/') || pathname.startsWith('/api/ai/')) {
      const handled = await authRoute(req, res, pathname);
      if (handled === false) sendJson(res, 404, { error: 'Not found' });
      return;
    }
    if (pathname !== '/' && pathname !== '/index.html' && pathname !== '/reasonix-logo.svg' && pathname !== '/reasonix-mark.svg') return sendJson(res, 404, { error: 'Not found' });
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return sendJson(res, 405, { error: 'الطريقة غير مسموحة لهذا المسار.' }, { Allow: 'GET, HEAD' });
    }
    const f = path.join(ROOT, pathname === '/reasonix-logo.svg' || pathname === '/reasonix-mark.svg' ? pathname.slice(1) : 'index.html');
    const isHtml = path.extname(f) === '.html';
    const nonce = isHtml ? randomBytes(18).toString('base64') : '';
    const body = await readFile(f);
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)], 'Cache-Control': 'no-store', ...SECURITY_HEADERS,
      ...(isHtml ? { 'Content-Security-Policy': contentSecurityPolicy(nonce) } : {}) });
    if (req.method === 'HEAD') res.end();
    else res.end(isHtml ? body.toString('utf8').replaceAll('__REASONIX_NONCE__', nonce) : body);
  } catch (error) {
    console.error('request failed:', req.method, req.url, error);
    if (res.headersSent) return res.destroy();
    if (error instanceof SyntaxError) return sendJson(res, 400, { code: 'invalid-json', error: 'بيانات الطلب غير صالحة. حدّث الصفحة وأعد المحاولة.' });
    if (error.message === 'Request too large') return sendJson(res, 413, { code: 'request-too-large', error: 'حجم الطلب أكبر من المسموح.' });
    if (req.url?.split('?')[0] === '/api/auth/signup') return sendJson(res, 503, { code: 'signup-failed', error: registrationFailure(error) });
    return sendJson(res, 500, { code: 'request-failed', error: 'حدث خطأ داخلي أثناء معالجة الطلب. أعد المحاولة بعد قليل.' });
  }
});
await initializeEncryptedUserStore();
server.listen(PORT, process.env.HOST || (IS_PRODUCTION ? '0.0.0.0' : '127.0.0.1'), () => {
  console.log(`http://127.0.0.1:${PORT}`);
  // تشغيل خادم الفحص الحقيقي تلقائياً — الواجهة تستخدمه إن كان متاحاً
  let shuttingDown = false;
  let scanHttpServer;
  let scanServerStarting = false;
  const startScan = async () => {
    if (shuttingDown || scanServerStarting || scanHttpServer?.listening) return;
    scanServerStarting = true;
    try {
      const scannerModule = await import('./scan-server.mjs');
      scanHttpServer = scannerModule.default;
      await new Promise((resolve, reject) => {
        const onError = error => { scanHttpServer.off('listening', onListening); reject(error); };
        const onListening = () => { scanHttpServer.off('error', onError); resolve(); };
        scanHttpServer.once('error', onError);
        scanHttpServer.once('listening', onListening);
        scanHttpServer.listen(scanPort, '127.0.0.1');
      });
      const address = scanHttpServer.address();
      if (address && typeof address === 'object') scanPort = address.port;
      console.log(`scan-server ready → http://127.0.0.1:${scanPort}`);
    } catch (error) {
      if (error.code === 'EADDRINUSE' && scanPort !== 0) {
        console.warn(`Scanner port ${scanPort} is already in use; retrying on an available local port.`);
        scanPort = 0;
        setTimeout(startScan, 0);
        return;
      }
      console.error('scan-server start failed:', error.message);
      if (!shuttingDown) setTimeout(startScan, 2000);
    } finally { scanServerStarting = false; }
  };
  startScan();
  const stop = () => { shuttingDown = true; server.close(); scanHttpServer?.close(); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  if (process.argv.includes('--open')) exec(`start "" http://127.0.0.1:${PORT}`, { shell: 'powershell.exe' });
});
