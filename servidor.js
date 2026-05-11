const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 10000;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://liveplay-backend.onrender.com';

let overlayClients = [];
let videoClients = [];
let lastOverlayPayload = null;

const uploadRoot = path.join(__dirname, 'video_alerts');
fs.mkdirSync(uploadRoot, { recursive: true });

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
      if (body.length > 80 * 1024 * 1024) {
        reject(new Error('Payload muito grande.'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function sanitizeBaseName(value) {
  return String(value || 'video')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 80) || 'video';
}

function extensionFromMime(mime) {
  const normalized = String(mime || '').toLowerCase();
  if (normalized.includes('video/mp4')) return '.mp4';
  if (normalized.includes('video/webm')) return '.webm';
  if (normalized.includes('video/quicktime')) return '.mov';
  if (normalized.includes('video/x-matroska')) return '.mkv';
  if (normalized.includes('video/x-msvideo')) return '.avi';
  return '.mp4';
}

function contentTypeFromPath(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.mp4') return 'video/mp4';
  if (ext === '.webm') return 'video/webm';
  if (ext === '.mov') return 'video/quicktime';
  if (ext === '.mkv') return 'video/x-matroska';
  if (ext === '.avi') return 'video/x-msvideo';
  if (ext === '.mp3') return 'audio/mpeg';
  if (ext === '.wav') return 'audio/wav';
  if (ext === '.ogg') return 'audio/ogg';
  if (ext === '.m4a') return 'audio/mp4';
  return 'application/octet-stream';
}

function safePublicBase(req) {
  const host = req.headers.host;
  if (host) return `https://${host}`;
  return PUBLIC_BASE_URL.replace(/\/$/, '');
}


// =============================
// LivePlay Auth + Plan Backend
// =============================
// Primeira versão sem dependências extras: usa Supabase via REST + senha com PBKDF2 + token HMAC.
// No Render configure estas variáveis:
// SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, LIVEPLAY_AUTH_SECRET
const SUPABASE_URL = String(process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_SERVICE_ROLE_KEY = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '');
const LIVEPLAY_AUTH_SECRET = String(process.env.LIVEPLAY_AUTH_SECRET || 'dev-change-this-secret');
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 dias

function jsonResponse(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(input) {
  const value = String(input || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = value.padEnd(value.length + ((4 - (value.length % 4)) % 4), '=');
  return Buffer.from(padded, 'base64').toString('utf8');
}

function signToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = {
    ...payload,
    iat: Date.now(),
    exp: Date.now() + TOKEN_TTL_MS,
  };
  const unsigned = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(body))}`;
  const signature = crypto
    .createHmac('sha256', LIVEPLAY_AUTH_SECRET)
    .update(unsigned)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${unsigned}.${signature}`;
}

function verifyToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const [header, body, signature] = parts;
  const unsigned = `${header}.${body}`;
  const expected = crypto
    .createHmac('sha256', LIVEPLAY_AUTH_SECRET)
    .update(unsigned)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const expectedBuffer = Buffer.from(expected);
  const signatureBuffer = Buffer.from(signature);
  if (expectedBuffer.length !== signatureBuffer.length) return null;
  if (!crypto.timingSafeEqual(expectedBuffer, signatureBuffer)) return null;
  try {
    const payload = JSON.parse(base64UrlDecode(body));
    if (!payload.exp || Date.now() > Number(payload.exp)) return null;
    return payload;
  } catch {
    return null;
  }
}

function getBearerToken(req) {
  const header = String(req.headers.authorization || '');
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(String(password || ''), salt, 120000, 32, 'sha256').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const candidate = crypto.pbkdf2Sync(String(password || ''), salt, 120000, 32, 'sha256').toString('hex');
  const a = Buffer.from(hash);
  const b = Buffer.from(candidate);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function supabaseReady() {
  return Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
}

async function supabaseRequest(table, options = {}) {
  if (!supabaseReady()) {
    throw new Error('Supabase não configurado no Render.');
  }
  const query = options.query ? `?${options.query}` : '';
  const response = await fetch(`${SUPABASE_URL}/rest/v1/${table}${query}`, {
    method: options.method || 'GET',
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'Content-Type': 'application/json',
      Prefer: options.prefer || 'return=representation',
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    throw new Error(typeof data === 'object' && data?.message ? data.message : `Supabase HTTP ${response.status}`);
  }
  return data;
}

async function getUserByEmail(email) {
  const data = await supabaseRequest('liveplay_users', {
    query: `email=eq.${encodeURIComponent(email)}&limit=1`,
  });
  return Array.isArray(data) ? data[0] || null : null;
}

async function getUserById(id) {
  const data = await supabaseRequest('liveplay_users', {
    query: `id=eq.${encodeURIComponent(id)}&limit=1`,
  });
  return Array.isArray(data) ? data[0] || null : null;
}

async function getSubscriptionForUser(userId) {
  const data = await supabaseRequest('liveplay_subscriptions', {
    query: `user_id=eq.${encodeURIComponent(userId)}&order=created_at.desc&limit=1`,
  });
  return Array.isArray(data) ? data[0] || null : null;
}

function resolvePlanFromSubscription(subscription) {
  if (!subscription) return { plan: 'FREE', status: 'inactive', expiresAt: null };
  const plan = String(subscription.plan || 'FREE').toUpperCase() === 'PRO' ? 'PRO' : 'FREE';
  const status = String(subscription.status || 'inactive').toLowerCase();
  const expiresAt = subscription.expires_at || null;
  const expired = expiresAt ? new Date(expiresAt).getTime() < Date.now() : false;
  if (plan !== 'PRO' || status !== 'active' || expired) {
    return { plan: 'FREE', status: expired ? 'expired' : status, expiresAt };
  }
  return { plan: 'PRO', status: 'active', expiresAt };
}

async function createFreeSubscription(userId) {
  const data = await supabaseRequest('liveplay_subscriptions', {
    method: 'POST',
    body: [{ user_id: userId, plan: 'FREE', status: 'active', expires_at: null }],
  });
  return Array.isArray(data) ? data[0] || null : null;
}

async function handleRegister(req, res) {
  try {
    const body = await readJsonBody(req);
    const email = normalizeEmail(body.email);
    const password = String(body.password || '');
    if (!validateEmail(email)) return jsonResponse(res, 400, { ok: false, error: 'Email inválido.' });
    if (password.length < 6) return jsonResponse(res, 400, { ok: false, error: 'A senha precisa ter pelo menos 6 caracteres.' });
    const existing = await getUserByEmail(email);
    if (existing) return jsonResponse(res, 409, { ok: false, error: 'Já existe uma conta com esse email.' });
    const passwordHash = hashPassword(password);
    const inserted = await supabaseRequest('liveplay_users', {
      method: 'POST',
      body: [{ email, password_hash: passwordHash }],
    });
    const user = Array.isArray(inserted) ? inserted[0] : null;
    if (!user?.id) throw new Error('Falha ao criar usuário.');
    await createFreeSubscription(user.id);
    const token = signToken({ userId: user.id, email: user.email });
    jsonResponse(res, 200, {
      ok: true,
      token,
      user: { id: user.id, email: user.email },
      plan: { plan: 'FREE', status: 'active', expiresAt: null },
    });
  } catch (error) {
    jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha no cadastro.' });
  }
}

async function handleLogin(req, res) {
  try {
    const body = await readJsonBody(req);
    const email = normalizeEmail(body.email);
    const password = String(body.password || '');
    const user = validateEmail(email) ? await getUserByEmail(email) : null;
    if (!user || !verifyPassword(password, user.password_hash)) {
      return jsonResponse(res, 401, { ok: false, error: 'Email ou senha inválidos.' });
    }
    const subscription = await getSubscriptionForUser(user.id);
    const plan = resolvePlanFromSubscription(subscription);
    const token = signToken({ userId: user.id, email: user.email });
    jsonResponse(res, 200, {
      ok: true,
      token,
      user: { id: user.id, email: user.email },
      plan,
    });
  } catch (error) {
    jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha no login.' });
  }
}

async function handleMePlan(req, res) {
  try {
    const payload = verifyToken(getBearerToken(req));
    if (!payload?.userId) return jsonResponse(res, 401, { ok: false, error: 'Token inválido ou expirado.' });
    const user = await getUserById(payload.userId);
    if (!user) return jsonResponse(res, 401, { ok: false, error: 'Usuário não encontrado.' });
    const subscription = await getSubscriptionForUser(user.id);
    const plan = resolvePlanFromSubscription(subscription);
    jsonResponse(res, 200, {
      ok: true,
      user: { id: user.id, email: user.email },
      plan,
    });
  } catch (error) {
    jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao consultar plano.' });
  }
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('LivePlay Backend Online 🚀\nAuth: /auth/register, /auth/login, /me/plan');
    return;
  }

  if (req.url === '/auth/register' && req.method === 'POST') {
    await handleRegister(req, res);
    return;
  }

  if (req.url === '/auth/login' && req.method === 'POST') {
    await handleLogin(req, res);
    return;
  }

  if (req.url === '/me/plan' && req.method === 'GET') {
    await handleMePlan(req, res);
    return;
  }

  if (req.url.startsWith('/overlay-bridge/events')) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write('\n');
    overlayClients.push(res);
    req.on('close', () => {
      overlayClients = overlayClients.filter((c) => c !== res);
    });
    return;
  }

  if (req.url === '/overlay-bridge/emit' && req.method === 'POST') {
    try {
      const data = await readJsonBody(req);
      lastOverlayPayload = data;
      overlayClients.forEach((client) => {
        client.write(`data: ${JSON.stringify(data)}\n\n`);
      });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: true }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false }));
    }
    return;
  }

  if (req.url.startsWith('/overlay-bridge/snapshot')) {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      ok: true,
      payload: lastOverlayPayload,
    }));
    return;
  }

  if (req.url.startsWith('/video-alert-bridge/events')) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write('\n');
    videoClients.push(res);
    req.on('close', () => {
      videoClients = videoClients.filter((c) => c !== res);
    });
    return;
  }

  if (req.url === '/video-alert-bridge/emit' && req.method === 'POST') {
    try {
      const data = await readJsonBody(req);
      videoClients.forEach((client) => {
        client.write(`data: ${JSON.stringify(data)}\n\n`);
      });
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: true }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false }));
    }
    return;
  }

  if (req.url === '/video-alert-bridge/upload' && req.method === 'POST') {
    try {
      const { fileName, dataUrl } = await readJsonBody(req);
      const match = String(dataUrl || '').match(/^data:([^;,]+)?(;base64)?,(.*)$/);
      if (!match) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ ok: false, error: 'dataUrl inválido.' }));
        return;
      }

      const mime = match[1] || 'video/mp4';
      const base64 = match[3] || '';
      const extFromName = path.extname(String(fileName || '')).toLowerCase();
      const ext = extFromName || extensionFromMime(mime);
      const baseName = sanitizeBaseName(path.basename(String(fileName || 'video'), ext));
      const finalName = `${Date.now()}_${crypto.randomUUID()}_${baseName}${ext}`;
      const filePath = path.join(uploadRoot, finalName);

      fs.writeFileSync(filePath, Buffer.from(base64, 'base64'));

      const publicUrl = `${safePublicBase(req)}/video-alert-bridge/assets/${encodeURIComponent(finalName)}`;

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({
        ok: true,
        fileName: finalName,
        url: publicUrl,
      }));
    } catch (error) {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({
        ok: false,
        error: error instanceof Error ? error.message : 'Falha no upload.',
      }));
    }
    return;
  }

  if (req.url.startsWith('/video-alert-bridge/assets/')) {
    const relativePath = decodeURIComponent(req.url.slice('/video-alert-bridge/assets/'.length)).replace(/^[/\\]+/, '');
    const filePath = path.resolve(uploadRoot, relativePath);

    if (!filePath.startsWith(path.resolve(uploadRoot)) || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'Arquivo não encontrado.' }));
      return;
    }

    res.writeHead(200, {
      'Content-Type': contentTypeFromPath(filePath),
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Accept-Ranges': 'bytes',
    });
    fs.createReadStream(filePath).pipe(res);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log('Servidor rodando na porta', PORT);
});
