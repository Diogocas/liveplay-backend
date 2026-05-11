const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 10000;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://liveplay-backend.onrender.com';
const MERCADOPAGO_ACCESS_TOKEN = String(process.env.MERCADOPAGO_ACCESS_TOKEN || '').trim();
const LIVEPLAY_PRO_PRICE = Number(String(process.env.LIVEPLAY_PRO_PRICE || '50.00').replace(',', '.')) || 50;

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
const LIVEPLAY_AUTH_SECRET = String(process.env.LIVEPLAY_AUTH_SECRET || process.env.JWT_SECRET || 'dev-change-this-secret');
const LIVEPLAY_ADMIN_SECRET = String(process.env.LIVEPLAY_ADMIN_SECRET || process.env.ADMIN_SECRET || '');
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


function isAdminRequest(req) {
  const headerSecret = String(req.headers['x-liveplay-admin-secret'] || '').trim();
  const bearer = getBearerToken(req).trim();
  const provided = headerSecret || bearer;
  if (!LIVEPLAY_ADMIN_SECRET || !provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(LIVEPLAY_ADMIN_SECRET);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireAdmin(req, res) {
  if (isAdminRequest(req)) return true;
  jsonResponse(res, 401, { ok: false, error: 'Admin secret inválido ou ausente.' });
  return false;
}

function safeLimit(value, fallback = 50) {
  const num = Math.floor(Number(value || fallback) || fallback);
  return Math.max(1, Math.min(200, num));
}

async function getSubscriptionById(id) {
  const data = await supabaseRequest('liveplay_subscriptions', {
    query: `id=eq.${encodeURIComponent(id)}&limit=1`,
  });
  return Array.isArray(data) ? data[0] || null : null;
}

async function listAdminUsers(req, res) {
  try {
    if (!requireAdmin(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const search = normalizeEmail(url.searchParams.get('search') || '');
    const limit = safeLimit(url.searchParams.get('limit'), 50);
    const queryParts = [`order=created_at.desc`, `limit=${limit}`];
    if (search) queryParts.unshift(`email=ilike.*${encodeURIComponent(search)}*`);
    const users = await supabaseRequest('liveplay_users', {
      query: queryParts.join('&'),
    });
    const result = [];
    for (const user of Array.isArray(users) ? users : []) {
      const subscription = await getSubscriptionForUser(user.id);
      result.push({
        id: user.id,
        email: user.email,
        createdAt: user.created_at,
        subscription,
        effectivePlan: resolvePlanFromSubscription(subscription),
      });
    }
    jsonResponse(res, 200, { ok: true, users: result });
  } catch (error) {
    jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao listar usuários.' });
  }
}

async function handleAdminSetPlan(req, res) {
  try {
    if (!requireAdmin(req, res)) return;
    const body = await readJsonBody(req);
    const email = normalizeEmail(body.email);
    const userId = String(body.userId || '').trim();
    const plan = String(body.plan || 'FREE').toUpperCase() === 'PRO' ? 'PRO' : 'FREE';
    const statusValue = String(body.status || 'active').toLowerCase();
    const status = ['active', 'inactive', 'expired', 'canceled'].includes(statusValue) ? statusValue : 'active';
    const expiresAtRaw = body.expiresAt ?? body.expires_at ?? null;
    const expiresAt = expiresAtRaw ? new Date(expiresAtRaw).toISOString() : null;

    let user = null;
    if (userId) user = await getUserById(userId);
    if (!user && email) user = await getUserByEmail(email);
    if (!user) return jsonResponse(res, 404, { ok: false, error: 'Usuário não encontrado.' });

    const current = await getSubscriptionForUser(user.id);
    let saved = null;
    const payload = {
      user_id: user.id,
      plan,
      status,
      expires_at: expiresAt,
    };

    if (current?.id) {
      const updated = await supabaseRequest('liveplay_subscriptions', {
        method: 'PATCH',
        query: `id=eq.${encodeURIComponent(current.id)}`,
        body: payload,
      });
      saved = Array.isArray(updated) ? updated[0] || null : null;
    } else {
      const inserted = await supabaseRequest('liveplay_subscriptions', {
        method: 'POST',
        body: [payload],
      });
      saved = Array.isArray(inserted) ? inserted[0] || null : null;
    }

    jsonResponse(res, 200, {
      ok: true,
      user: { id: user.id, email: user.email },
      subscription: saved,
      effectivePlan: resolvePlanFromSubscription(saved),
    });
  } catch (error) {
    jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao atualizar plano.' });
  }
}

function adminHtml() {
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>LivePlay Admin</title>
<link rel="manifest" href="/admin/manifest.json" />
<meta name="theme-color" content="#080d1a" />
<link rel="icon" href="/admin/icon.svg" type="image/svg+xml" />
<style>
  body{font-family:Inter,system-ui,Segoe UI,Arial,sans-serif;background:#080d1a;color:#e5e7eb;margin:0;padding:28px}
  .wrap{max-width:980px;margin:0 auto;display:grid;gap:18px}
  .card{background:rgba(15,23,42,.92);border:1px solid rgba(148,163,184,.18);border-radius:18px;padding:20px;box-shadow:0 20px 60px rgba(0,0,0,.28)}
  h1{margin:0 0 6px;font-size:28px}.muted{color:#94a3b8;font-size:14px}label{display:grid;gap:6px;font-size:13px;color:#cbd5e1;font-weight:700}
  input,select,button{border-radius:12px;border:1px solid rgba(148,163,184,.25);background:#0b1223;color:#fff;padding:12px;font-size:14px}
  button{cursor:pointer;background:linear-gradient(135deg,#6d5dfc,#22d3ee);border:0;font-weight:900}.secondary{background:#111827;border:1px solid rgba(148,163,184,.22)}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}.users{display:grid;gap:10px}.user{padding:14px;border-radius:14px;background:rgba(255,255,255,.04);display:grid;gap:8px;border:1px solid rgba(255,255,255,.06)}
  .pill{display:inline-flex;align-items:center;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:900;background:#1f2937}.pro{background:#312e81;color:#ddd6fe}.free{background:#064e3b;color:#bbf7d0}.danger{color:#fca5a5}.ok{color:#86efac}
  pre{white-space:pre-wrap;word-break:break-word;background:#020617;border-radius:12px;padding:12px;color:#cbd5e1}
</style>
</head>
<body><div class="wrap">
  <div class="card"><h1>LivePlay Admin</h1><div class="muted">Gerencie planos sem abrir o Supabase. Guarde o ADMIN_SECRET com segurança.</div></div>
  <div class="card grid">
    <label>Admin secret<input id="secret" type="password" placeholder="LIVEPLAY_ADMIN_SECRET" /></label>
    <label>Buscar email<input id="search" placeholder="email do cliente" /></label>
    <button id="btnLoadUsers" type="button">Buscar usuários</button><button id="btnClearLog" class="secondary" type="button">Limpar log</button>
  </div>
  <div class="card grid">
    <label>Email do usuário<input id="email" placeholder="cliente@email.com" /></label>
    <label>Plano<select id="plan"><option value="FREE">FREE</option><option value="PRO">PRO</option></select></label>
    <label>Status<select id="status"><option value="active">active</option><option value="inactive">inactive</option><option value="expired">expired</option><option value="canceled">canceled</option></select></label>
    <label>Expira em (opcional)<input id="expiresAt" type="datetime-local" /></label>
    <button id="btnSetPlan" type="button">Salvar plano</button><button id="btnSetFree" class="secondary" type="button">Voltar para FREE</button>
  </div>
  <div class="card"><div class="users" id="users"></div></div>
  <div class="card"><pre id="log">Pronto.</pre></div>
</div>
<script>
(function(){
  if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/admin/sw.js').catch(function(){}); }
  const logEl = document.getElementById('log');
  function secret(){ return document.getElementById('secret').value.trim(); }
  function log(v){ logEl.textContent = typeof v === 'string' ? v : JSON.stringify(v, null, 2); }
  function clearLog(){ log('Pronto.'); }
  async function api(path, options){
    options = options || {};
    const headers = Object.assign({
      'Content-Type': 'application/json',
      'x-liveplay-admin-secret': secret()
    }, options.headers || {});
    const res = await fetch(path, Object.assign({}, options, { headers }));
    const data = await res.json().catch(function(){ return null; });
    if(!res.ok || !data || data.ok !== true){
      throw new Error((data && data.error) ? data.error : ('Falha HTTP ' + res.status));
    }
    return data;
  }
  function fillEmail(email){
    document.getElementById('email').value = email || '';
  }
  async function loadUsers(){
    try{
      const q = encodeURIComponent(document.getElementById('search').value.trim());
      const data = await api('/admin/users?limit=50&search=' + q);
      const box = document.getElementById('users');
      box.innerHTML = '';
      if(!data.users || data.users.length === 0){
        box.innerHTML = '<div class="muted">Nenhum usuário encontrado.</div>';
      }
      (data.users || []).forEach(function(u){
        const plan = (u.effectivePlan && u.effectivePlan.plan) || 'FREE';
        const sub = u.subscription || {};
        const div = document.createElement('div');
        div.className = 'user';
        const header = document.createElement('div');
        header.innerHTML = '<b></b> <span class="pill"></span>';
        header.querySelector('b').textContent = u.email || '';
        const pill = header.querySelector('.pill');
        pill.textContent = plan;
        pill.classList.add(plan === 'PRO' ? 'pro' : 'free');
        const meta = document.createElement('div');
        meta.className = 'muted';
        meta.textContent = 'status: ' + (sub.status || '-') + ' · expira: ' + (sub.expires_at || 'sem expiração');
        const row = document.createElement('div');
        row.className = 'row';
        const btn = document.createElement('button');
        btn.className = 'secondary';
        btn.type = 'button';
        btn.textContent = 'Selecionar';
        btn.addEventListener('click', function(){
          fillEmail(u.email || '');
          document.getElementById('plan').value = plan === 'PRO' ? 'PRO' : 'FREE';
          document.getElementById('status').value = sub.status || 'active';
          document.getElementById('expiresAt').value = sub.expires_at ? String(sub.expires_at).slice(0,16) : '';
        });
        row.appendChild(btn);
        div.appendChild(header);
        div.appendChild(meta);
        div.appendChild(row);
        box.appendChild(div);
      });
      log(data);
    }catch(e){ log('Erro: ' + e.message); }
  }
  async function setPlan(){
    try{
      const body = {
        email: document.getElementById('email').value.trim(),
        plan: document.getElementById('plan').value,
        status: document.getElementById('status').value,
        expiresAt: document.getElementById('expiresAt').value || null
      };
      const data = await api('/admin/set-plan', { method: 'POST', body: JSON.stringify(body) });
      log(data);
      await loadUsers();
    }catch(e){ log('Erro: ' + e.message); }
  }
  async function setFree(){
    document.getElementById('plan').value = 'FREE';
    document.getElementById('status').value = 'active';
    document.getElementById('expiresAt').value = '';
    await setPlan();
  }
  document.getElementById('btnLoadUsers').addEventListener('click', loadUsers);
  document.getElementById('btnClearLog').addEventListener('click', clearLog);
  document.getElementById('btnSetPlan').addEventListener('click', setPlan);
  document.getElementById('btnSetFree').addEventListener('click', setFree);
})();
</script></body></html>`;
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


async function handleCreateCheckout(req, res) {
  try {
    if (!MERCADOPAGO_ACCESS_TOKEN) {
      return jsonResponse(res, 500, {
        ok: false,
        error: 'Mercado Pago não configurado no Render.',
      });
    }

    const body = await readJsonBody(req);
    const email = normalizeEmail(body.email);

    if (!validateEmail(email)) {
      return jsonResponse(res, 400, {
        ok: false,
        error: 'Email inválido ou ausente.',
      });
    }

    const user = await getUserByEmail(email);
    if (!user) {
      return jsonResponse(res, 404, {
        ok: false,
        error: 'Conta LivePlay não encontrada para este email.',
      });
    }

    const baseUrl = PUBLIC_BASE_URL.replace(/\/$/, '');
    const preferencePayload = {
      items: [
        {
          id: 'liveplay-pro-monthly',
          title: 'LivePlay PRO',
          description: 'Licença LivePlay PRO - 30 dias',
          quantity: 1,
          currency_id: 'BRL',
          unit_price: LIVEPLAY_PRO_PRICE,
        },
      ],
      payer: { email },
      external_reference: user.id,
      metadata: {
        liveplay_user_id: user.id,
        liveplay_email: email,
        product: 'liveplay-pro',
      },
      notification_url: `${baseUrl}/payments/webhook`,
      back_urls: {
        success: `${baseUrl}/payment-success`,
        failure: `${baseUrl}/payment-failure`,
        pending: `${baseUrl}/payment-pending`,
      },
      auto_return: 'approved',
    };

    const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${MERCADOPAGO_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(preferencePayload),
    });

    const mpData = await response.json().catch(() => null);
    if (!response.ok || !mpData?.init_point) {
      return jsonResponse(res, 500, {
        ok: false,
        error: 'Falha ao criar checkout no Mercado Pago.',
        details: mpData,
      });
    }

    return jsonResponse(res, 200, {
      ok: true,
      checkoutUrl: mpData.init_point,
      sandboxCheckoutUrl: mpData.sandbox_init_point || null,
      preferenceId: mpData.id || null,
      price: LIVEPLAY_PRO_PRICE,
    });
  } catch (error) {
    console.error('Erro ao criar checkout Mercado Pago:', error);
    return jsonResponse(res, 500, {
      ok: false,
      error: error instanceof Error ? error.message : 'Falha ao criar checkout.',
    });
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
    res.end('LivePlay Backend Online 🚀\nAuth: /auth/register, /auth/login, /me/plan | Admin: /admin');
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

  if (req.url === '/payments/create-checkout' && req.method === 'POST') {
    await handleCreateCheckout(req, res);
    return;
  }

  if (req.url === '/payment-success' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>Pagamento aprovado</h1><p>Volte ao LivePlay e clique em Atualizar plano.</p>');
    return;
  }

  if (req.url === '/payment-pending' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>Pagamento pendente</h1><p>Assim que o Mercado Pago aprovar, o PRO será liberado.</p>');
    return;
  }

  if (req.url === '/payment-failure' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>Pagamento não concluído</h1><p>Tente novamente pelo LivePlay.</p>');
    return;
  }



  if (req.url === '/admin/manifest.json' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/manifest+json; charset=utf-8' });
    res.end(JSON.stringify({
      name: 'LivePlay Admin',
      short_name: 'LivePlay Admin',
      description: 'Painel administrativo do LivePlay para gerenciar planos FREE/PRO.',
      start_url: '/admin',
      scope: '/',
      display: 'standalone',
      background_color: '#080d1a',
      theme_color: '#080d1a',
      icons: [
        { src: '/admin/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable' }
      ]
    }));
    return;
  }

  if (req.url === '/admin/icon.svg' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'public, max-age=86400' });
    res.end(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
      <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#6d5dfc"/><stop offset="1" stop-color="#22d3ee"/></linearGradient></defs>
      <rect width="256" height="256" rx="56" fill="#080d1a"/>
      <circle cx="128" cy="128" r="92" fill="url(#g)" opacity=".22"/>
      <path d="M75 72h48c40 0 68 24 68 61s-28 61-68 61H75V72zm38 32v58h10c18 0 30-10 30-29s-12-29-30-29h-10z" fill="white"/>
      <path d="M78 204h100" stroke="#22d3ee" stroke-width="12" stroke-linecap="round"/>
    </svg>`);
    return;
  }

  if (req.url === '/admin/sw.js' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(`self.addEventListener('install', event => self.skipWaiting());\nself.addEventListener('activate', event => event.waitUntil(self.clients.claim()));`);
    return;
  }

  if (req.url === '/admin' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(adminHtml());
    return;
  }

  if (req.url.startsWith('/admin/users') && req.method === 'GET') {
    await listAdminUsers(req, res);
    return;
  }

  if (req.url === '/admin/set-plan' && req.method === 'POST') {
    await handleAdminSetPlan(req, res);
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
