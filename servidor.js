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

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  });

  res.end(JSON.stringify(data));
}

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
const GOOGLE_CLIENT_ID = String(process.env.GOOGLE_CLIENT_ID || '').trim();
const GOOGLE_CLIENT_SECRET = String(process.env.GOOGLE_CLIENT_SECRET || '').trim();
const GITHUB_CLIENT_ID = String(process.env.GITHUB_CLIENT_ID || '').trim();
const GITHUB_CLIENT_SECRET = String(process.env.GITHUB_CLIENT_SECRET || '').trim();
const OAUTH_REDIRECT_BASE = String(process.env.OAUTH_REDIRECT_BASE || PUBLIC_BASE_URL).replace(/\/$/, '');
const oauthPendingSessions = new Map();
const ACCESS_TOKEN_TTL_MS = 1000 * 60 * 60 * 24; // 1 dia
const REFRESH_TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 dias

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

function signToken(payload, ttlMs = ACCESS_TOKEN_TTL_MS) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = {
    ...payload,
    iat: Date.now(),
    exp: Date.now() + ttlMs,
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

function createRefreshToken() {
  return crypto.randomBytes(48).toString('base64url');
}

function hashRefreshToken(refreshToken) {
  return crypto
    .createHash('sha256')
    .update(String(refreshToken || ''))
    .digest('hex');
}

function refreshExpiresAtFromNow() {
  return new Date(Date.now() + REFRESH_TOKEN_TTL_MS).toISOString();
}


async function setActiveSessionForUser(userId, sessionId) {
  const updated = await supabaseRequest('liveplay_users', {
    method: 'PATCH',
    query: `id=eq.${encodeURIComponent(userId)}`,
    body: {
      active_session_id: sessionId,
      active_session_updated_at: new Date().toISOString(),
    },
  });
  return Array.isArray(updated) ? updated[0] || null : null;
}

async function createActiveSessionTokenForUser(user, req) {
  const sessionId = crypto.randomUUID();
  const refreshToken = createRefreshToken();
  const refreshTokenHash = hashRefreshToken(refreshToken);
  const refreshExpiresAt = refreshExpiresAtFromNow();

  await markUserDeviceSessionsInactive(user.id);
  const updatedUser = await setActiveSessionForUser(user.id, sessionId);
  const finalUser = updatedUser || user;
  await saveDeviceSession(finalUser, sessionId, req, 'active', {
    refresh_token_hash: refreshTokenHash,
    refresh_expires_at: refreshExpiresAt,
  });

  return {
    token: signToken({ userId: finalUser.id, email: finalUser.email, sessionId }),
    refreshToken,
    refreshExpiresAt,
    sessionId,
    user: finalUser,
  };
}

function isSessionValidForUser(payload, user) {
  const tokenSessionId = String(payload?.sessionId || '').trim();
  const activeSessionId = String(user?.active_session_id || '').trim();

  // Tokens antigos sem sessionId deixam de ser válidos depois desta atualização.
  if (!tokenSessionId || !activeSessionId) return false;

  return tokenSessionId === activeSessionId;
}


function getClientIp(req) {
  return String(
    req.headers['x-forwarded-for'] ||
    req.headers['cf-connecting-ip'] ||
    req.socket?.remoteAddress ||
    ''
  ).split(',')[0].trim().slice(0, 120);
}

function getDeviceName(req) {
  const explicit = String(req.headers['x-liveplay-device-name'] || '').trim();
  if (explicit) return explicit.slice(0, 160);

  const ua = String(req.headers['user-agent'] || '').trim();
  if (ua.includes('Windows')) return 'Windows PC';
  if (ua.includes('Mac')) return 'Mac';
  if (ua.includes('Linux')) return 'Linux PC';
  return ua ? ua.slice(0, 160) : 'Dispositivo LivePlay';
}

async function getDeviceSessionBySessionId(sessionId) {
  const data = await supabaseRequest('liveplay_device_sessions', {
    query: `session_id=eq.${encodeURIComponent(sessionId)}&limit=1`,
  });
  return Array.isArray(data) ? data[0] || null : null;
}

async function markUserDeviceSessionsInactive(userId, exceptSessionId = '') {
  try {
    const query = exceptSessionId
      ? `user_id=eq.${encodeURIComponent(userId)}&session_id=neq.${encodeURIComponent(exceptSessionId)}`
      : `user_id=eq.${encodeURIComponent(userId)}`;
    await supabaseRequest('liveplay_device_sessions', {
      method: 'PATCH',
      query,
      body: {
        is_active: false,
        revoked_at: new Date().toISOString(),
      },
      prefer: 'return=minimal',
    });
  } catch (error) {
    console.warn('Não foi possível marcar sessões antigas como inativas:', error instanceof Error ? error.message : String(error));
  }
}

async function saveDeviceSession(user, sessionId, req, status = 'active', extra = {}) {
  if (!user?.id || !sessionId) return null;

  const now = new Date().toISOString();
  const record = {
    user_id: user.id,
    email: user.email,
    session_id: sessionId,
    device_name: getDeviceName(req),
    user_agent: String(req.headers['user-agent'] || '').slice(0, 500),
    ip_address: getClientIp(req),
    status,
    is_active: status === 'active',
    last_seen_at: now,
    updated_at: now,
    revoked_at: status === 'revoked' ? now : null,
    ...extra,
  };

  const existing = await getDeviceSessionBySessionId(sessionId);
  if (existing?.id) {
    const updated = await supabaseRequest('liveplay_device_sessions', {
      method: 'PATCH',
      query: `id=eq.${encodeURIComponent(existing.id)}`,
      body: record,
    });
    return Array.isArray(updated) ? updated[0] || null : null;
  }

  const inserted = await supabaseRequest('liveplay_device_sessions', {
    method: 'POST',
    body: [{ ...record, created_at: now }],
  });
  return Array.isArray(inserted) ? inserted[0] || null : null;
}

async function touchCurrentDeviceSession(user, payload, req) {
  const sessionId = String(payload?.sessionId || '').trim();
  if (!user?.id || !sessionId) return;
  try {
    await saveDeviceSession(user, sessionId, req, 'active');
  } catch (error) {
    console.warn('Não foi possível atualizar sessão do dispositivo:', error instanceof Error ? error.message : String(error));
  }
}

async function getAuthenticatedLivePlayContext(req) {
  const payload = verifyToken(getBearerToken(req));
  if (!payload?.userId) return null;
  const user = await getUserById(payload.userId);
  if (!user || !isSessionValidForUser(payload, user)) return null;
  return { user, payload };
}

async function getAuthenticatedLivePlayUser(req) {
  const context = await getAuthenticatedLivePlayContext(req);
  if (!context?.user) return null;
  await touchCurrentDeviceSession(context.user, context.payload, req);
  return context.user;
}

function sanitizeCloudPayload(payload) {
  const cloned = JSON.parse(JSON.stringify(payload || {}));
  // Segurança: nunca salvar sessão/token dentro do snapshot caso algum dia entre no state.
  delete cloned.auth;
  delete cloned.authSession;
  delete cloned.token;
  delete cloned.liveplayAuth;
  return cloned;
}

async function getCloudSaveForUser(userId) {
  const data = await supabaseRequest('liveplay_cloud_saves', {
    query: `user_id=eq.${encodeURIComponent(userId)}&order=updated_at.desc&limit=1`,
  });
  return Array.isArray(data) ? data[0] || null : null;
}

async function handleCloudSave(req, res) {
  try {
    const user = await getAuthenticatedLivePlayUser(req);
    if (!user?.id) {
      return jsonResponse(res, 401, { ok: false, error: 'Sessão inválida ou expirada.' });
    }

    const body = await readJsonBody(req);
    const payload = sanitizeCloudPayload(body.payload ?? body.state ?? {});
    const appVersion = String(body.appVersion || '').trim() || null;
    const existing = await getCloudSaveForUser(user.id);

    const record = {
      user_id: user.id,
      email: user.email,
      app_version: appVersion,
      payload,
      updated_at: new Date().toISOString(),
    };

    let saved = null;
    if (existing?.id) {
      const updated = await supabaseRequest('liveplay_cloud_saves', {
        method: 'PATCH',
        query: `id=eq.${encodeURIComponent(existing.id)}`,
        body: record,
      });
      saved = Array.isArray(updated) ? updated[0] || null : null;
    } else {
      const inserted = await supabaseRequest('liveplay_cloud_saves', {
        method: 'POST',
        body: [record],
      });
      saved = Array.isArray(inserted) ? inserted[0] || null : null;
    }

    return jsonResponse(res, 200, {
      ok: true,
      backup: {
        id: saved?.id || existing?.id || null,
        email: user.email,
        appVersion: saved?.app_version || appVersion,
        createdAt: saved?.created_at || existing?.created_at || null,
        updatedAt: saved?.updated_at || record.updated_at,
      },
    });
  } catch (error) {
    return jsonResponse(res, 500, {
      ok: false,
      error: error instanceof Error ? error.message : 'Falha ao salvar backup na nuvem.',
    });
  }
}

async function handleCloudLoad(req, res) {
  try {
    const user = await getAuthenticatedLivePlayUser(req);
    if (!user?.id) {
      return jsonResponse(res, 401, { ok: false, error: 'Sessão inválida ou expirada.' });
    }

    const backup = await getCloudSaveForUser(user.id);
    if (!backup) {
      return jsonResponse(res, 200, { ok: true, backup: null });
    }

    return jsonResponse(res, 200, {
      ok: true,
      backup: {
        id: backup.id,
        email: backup.email || user.email,
        appVersion: backup.app_version || null,
        createdAt: backup.created_at || null,
        updatedAt: backup.updated_at || null,
        payload: backup.payload || null,
      },
    });
  } catch (error) {
    return jsonResponse(res, 500, {
      ok: false,
      error: error instanceof Error ? error.message : 'Falha ao carregar backup da nuvem.',
    });
  }
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


async function activateLivePlayProForUser(userId, email, source = 'mercadopago') {
  let user = null;
  const cleanUserId = String(userId || '').trim();
  const cleanEmail = normalizeEmail(email || '');

  if (cleanUserId) user = await getUserById(cleanUserId);
  if (!user && cleanEmail) user = await getUserByEmail(cleanEmail);
  if (!user?.id) return null;

  const expiresAt = new Date();
  expiresAt.setMonth(expiresAt.getMonth() + 1);

  const current = await getSubscriptionForUser(user.id);
  const payload = {
    user_id: user.id,
    plan: 'PRO',
    status: 'active',
    expires_at: expiresAt.toISOString(),
  };

  let saved = null;
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

  console.log('PRO ativado automaticamente:', {
    email: user.email,
    userId: user.id,
    source,
    expiresAt: payload.expires_at,
  });

  return { user, subscription: saved, effectivePlan: resolvePlanFromSubscription(saved) };
}

function getMercadoPagoPaymentIdFromWebhook(body) {
  const directId = body?.data?.id || body?.id;
  if (directId && String(directId) !== '123456') return String(directId).trim();

  const resource = String(body?.resource || '').trim();
  const topic = String(body?.topic || body?.type || '').toLowerCase();
  if (topic === 'payment' && resource && !resource.startsWith('http')) {
    return resource;
  }

  const match = resource.match(/\/payments?\/(\d+)/i);
  if (match?.[1]) return match[1];

  return '';
}

async function fetchMercadoPagoPayment(paymentId) {
  if (!MERCADOPAGO_ACCESS_TOKEN) {
    throw new Error('Mercado Pago não configurado no Render.');
  }

  const response = await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${MERCADOPAGO_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
    },
  });

  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(`Mercado Pago payment ${paymentId} HTTP ${response.status}: ${JSON.stringify(data)}`);
  }

  return data;
}

async function handleMercadoPagoWebhook(req, res) {
  try {
    const body = await readJsonBody(req);

    console.log('Mercado Pago webhook:', JSON.stringify(body));

    const topic = String(body?.topic || body?.type || '').toLowerCase();
    const action = String(body?.action || '').toLowerCase();
    const paymentId = getMercadoPagoPaymentIdFromWebhook(body);

    // O simulador do Mercado Pago envia data.id = 123456.
    // Esse ID não é um pagamento real, então respondemos 200 só para validar a URL.
    if (!paymentId) {
      return sendJson(res, 200, { ok: true, ignored: true, reason: 'no-payment-id', topic, action });
    }

    let payment = null;
    try {
      payment = await fetchMercadoPagoPayment(paymentId);
    } catch (error) {
      // Não devolve erro para o Mercado Pago ficar reenviando sem necessidade.
      console.error('Falha ao consultar pagamento Mercado Pago:', error);
      return sendJson(res, 200, { ok: true, ignored: true, reason: 'payment-fetch-failed', paymentId });
    }

    console.log('Pagamento Mercado Pago consultado:', JSON.stringify({
      id: payment?.id,
      status: payment?.status,
      external_reference: payment?.external_reference,
      payerEmail: payment?.payer?.email,
      metadata: payment?.metadata,
    }));

    if (String(payment?.status || '').toLowerCase() !== 'approved') {
      return sendJson(res, 200, { ok: true, ignored: true, reason: 'payment-not-approved', status: payment?.status || null });
    }

    const metadata = payment?.metadata && typeof payment.metadata === 'object' ? payment.metadata : {};
    const userId = String(
      payment?.external_reference ||
      metadata.liveplay_user_id ||
      metadata.user_id ||
      ''
    ).trim();
    const email = normalizeEmail(
      metadata.liveplay_email ||
      metadata.email ||
      payment?.payer?.email ||
      ''
    );

    const activated = await activateLivePlayProForUser(userId, email, `mercadopago:${paymentId}`);
    if (!activated) {
      console.warn('Pagamento aprovado, mas usuário LivePlay não encontrado.', { paymentId, userId, email });
      return sendJson(res, 200, { ok: true, ignored: true, reason: 'liveplay-user-not-found', paymentId });
    }

    return sendJson(res, 200, {
      ok: true,
      activated: true,
      user: { id: activated.user.id, email: activated.user.email },
      plan: activated.effectivePlan,
    });
  } catch (error) {
    console.error('Erro webhook Mercado Pago:', error);
    // Responde 200 para evitar loop infinito de retries do MP em erro transitório.
    return sendJson(res, 200, {
      ok: true,
      ignored: true,
      reason: 'webhook-exception',
    });
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
<meta name="theme-color" content="#070b18" />
<link rel="icon" href="/admin/icon.svg" type="image/svg+xml" />
<style>
  :root{color-scheme:dark;--bg:#070b18;--panel:rgba(15,23,42,.78);--panel2:rgba(9,14,28,.94);--line:rgba(148,163,184,.16);--muted:#93a4bd;--text:#eef4ff;--blue:#22d3ee;--purple:#7c5cff;--green:#22c55e;--red:#fb7185;--amber:#facc15}
  *{box-sizing:border-box}body{font-family:Inter,system-ui,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 12% 0%,rgba(124,92,255,.24),transparent 32%),radial-gradient(circle at 90% 8%,rgba(34,211,238,.18),transparent 28%),linear-gradient(180deg,#070b18,#050816 55%,#03050d);color:var(--text);margin:0;min-height:100vh;padding:28px}button,input,select{font:inherit}.wrap{max-width:1180px;margin:0 auto;display:grid;gap:18px}.hero{display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center}.brand{display:flex;gap:14px;align-items:center}.logo{width:54px;height:54px;border-radius:18px;background:linear-gradient(135deg,var(--purple),var(--blue));display:grid;place-items:center;font-size:25px;font-weight:1000;box-shadow:0 0 34px rgba(124,92,255,.35)}.card{background:linear-gradient(180deg,rgba(15,23,42,.86),rgba(11,18,35,.78));border:1px solid var(--line);border-radius:22px;padding:20px;box-shadow:0 22px 70px rgba(0,0,0,.30);backdrop-filter:blur(16px)}h1{margin:0;font-size:31px;letter-spacing:-.04em}.muted{color:var(--muted);font-size:14px;line-height:1.55}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.field{display:grid;gap:7px;font-size:12px;color:#cbd5e1;font-weight:800;text-transform:uppercase;letter-spacing:.06em}input,select{width:100%;border-radius:14px;border:1px solid rgba(148,163,184,.24);background:#081020;color:#fff;padding:12px 13px;font-size:14px;outline:none}input:focus,select:focus{border-color:rgba(34,211,238,.55);box-shadow:0 0 0 3px rgba(34,211,238,.10)}button{cursor:pointer;border-radius:14px;border:0;background:linear-gradient(135deg,var(--purple),var(--blue));color:#fff;padding:12px 15px;font-weight:950;box-shadow:0 12px 26px rgba(34,211,238,.12)}button:disabled{opacity:.55;cursor:not-allowed}.secondary{background:#101827;border:1px solid rgba(148,163,184,.22);box-shadow:none}.dangerBtn{background:linear-gradient(135deg,#7f1d1d,var(--red))}.okBtn{background:linear-gradient(135deg,#065f46,var(--green))}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.stat{padding:16px;border-radius:18px;background:rgba(255,255,255,.045);border:1px solid rgba(255,255,255,.07)}.stat span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:900}.stat b{display:block;margin-top:8px;font-size:28px}.users{display:grid;gap:10px;max-height:540px;overflow:auto;padding-right:4px}.user{padding:15px;border-radius:17px;background:rgba(255,255,255,.045);display:grid;gap:10px;border:1px solid rgba(255,255,255,.07)}.userTop{display:flex;justify-content:space-between;gap:12px;align-items:center}.email{font-weight:950;word-break:break-all}.pill{display:inline-flex;align-items:center;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:950;background:#1f2937}.pro{background:rgba(124,58,237,.25);color:#ddd6fe;border:1px solid rgba(167,139,250,.3)}.free{background:rgba(6,78,59,.35);color:#bbf7d0;border:1px solid rgba(52,211,153,.25)}.expired{background:rgba(127,29,29,.35);color:#fecaca;border:1px solid rgba(248,113,113,.25)}.status{display:flex;gap:8px;flex-wrap:wrap}.toolbar{display:grid;grid-template-columns:1.1fr .8fr auto auto;gap:12px;align-items:end}.remember{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:14px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.06);color:#dbeafe;font-size:13px;font-weight:800}.remember input{width:auto}pre{white-space:pre-wrap;word-break:break-word;background:#020617;border:1px solid rgba(148,163,184,.13);border-radius:16px;padding:14px;color:#cbd5e1;max-height:260px;overflow:auto}.toast{position:fixed;right:22px;bottom:22px;background:#07111f;border:1px solid rgba(34,211,238,.22);border-radius:16px;padding:13px 15px;box-shadow:0 20px 60px rgba(0,0,0,.45);display:none;z-index:20}.toast.show{display:block}.small{font-size:12px}.spacer{flex:1}@media(max-width:860px){body{padding:16px}.hero,.toolbar,.grid,.grid2,.stats{grid-template-columns:1fr}.card{padding:16px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div class="brand"><div class="logo">LP</div><div><h1>LivePlay Admin</h1><div class="muted">Painel para gerenciar usuários, planos e assinaturas. O segredo pode ficar salvo somente neste navegador.</div></div></div>
    <div class="row"><span class="pill pro">Backend online</span><span class="pill">PRO R$ ${LIVEPLAY_PRO_PRICE.toFixed(2).replace('.', ',')}</span></div>
  </div>

  <div class="stats">
    <div class="stat"><span>Usuários</span><b id="statTotal">0</b></div>
    <div class="stat"><span>PRO ativos</span><b id="statPro">0</b></div>
    <div class="stat"><span>FREE</span><b id="statFree">0</b></div>
    <div class="stat"><span>Vencidos</span><b id="statExpired">0</b></div>
  </div>

  <div class="card toolbar">
    <label class="field">Admin secret<input id="secret" type="password" placeholder="LIVEPLAY_ADMIN_SECRET" autocomplete="current-password" /></label>
    <label class="field">Buscar email<input id="search" placeholder="cliente@email.com" /></label>
    <button id="btnLoadUsers" type="button">Buscar usuários</button>
    <button id="btnClearLog" class="secondary" type="button">Limpar log</button>
    <label class="remember"><input id="rememberSecret" type="checkbox" /> Lembrar neste navegador</label>
    <button id="btnForgetSecret" class="secondary" type="button">Esquecer senha salva</button>
    <div class="muted small" style="grid-column:span 2">Use apenas no seu PC. Se estiver em computador de outra pessoa, não marque para lembrar.</div>
  </div>

  <div class="card">
    <div class="grid">
      <label class="field">Email do usuário<input id="email" placeholder="cliente@email.com" /></label>
      <label class="field">Plano<select id="plan"><option value="FREE">FREE</option><option value="PRO">PRO</option></select></label>
      <label class="field">Status<select id="status"><option value="active">active</option><option value="inactive">inactive</option><option value="expired">expired</option><option value="canceled">canceled</option></select></label>
      <label class="field">Expira em<input id="expiresAt" type="datetime-local" /></label>
    </div>
    <div class="row" style="margin-top:14px">
      <button id="btnSetPlan" type="button">Salvar plano</button>
      <button id="btnPro30" class="okBtn" type="button">PRO +30 dias</button>
      <button id="btnPro7" class="secondary" type="button">PRO +7 dias</button>
      <button id="btnSetFree" class="dangerBtn" type="button">Voltar para FREE</button>
      <button id="btnClearForm" class="secondary" type="button">Limpar formulário</button>
    </div>
  </div>

  <div class="grid2">
    <div class="card"><div class="row" style="justify-content:space-between;margin-bottom:12px"><div><b>Usuários</b><div class="muted">Clique em selecionar para editar rápido.</div></div><button id="btnReload" class="secondary" type="button">Atualizar</button></div><div class="users" id="users"><div class="muted">Busque usuários para começar.</div></div></div>
    <div class="card"><b>Log</b><pre id="log">Pronto.</pre></div>
  </div>
</div>
<div id="toast" class="toast"></div>
<script>
(function(){
  if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/admin/sw.js').catch(function(){}); }
  var STORAGE_KEY = 'liveplay_admin_secret_v1';
  var REMEMBER_KEY = 'liveplay_admin_secret_remember_v1';
  var lastUsers = [];
  var logEl = document.getElementById('log');
  var toastEl = document.getElementById('toast');
  function byId(id){ return document.getElementById(id); }
  function secret(){ return byId('secret').value.trim(); }
  function log(v){ logEl.textContent = typeof v === 'string' ? v : JSON.stringify(v, null, 2); }
  function toast(message){ toastEl.textContent = message; toastEl.classList.add('show'); window.setTimeout(function(){ toastEl.classList.remove('show'); }, 1800); }
  function saveSecretIfNeeded(){ try{ if(byId('rememberSecret').checked && secret()){ localStorage.setItem(STORAGE_KEY, secret()); localStorage.setItem(REMEMBER_KEY, '1'); } }catch(e){} }
  function loadSavedSecret(){ try{ var remember = localStorage.getItem(REMEMBER_KEY) === '1'; byId('rememberSecret').checked = remember; if(remember){ byId('secret').value = localStorage.getItem(STORAGE_KEY) || ''; } }catch(e){} }
  function forgetSecret(){ try{ localStorage.removeItem(STORAGE_KEY); localStorage.removeItem(REMEMBER_KEY); }catch(e){} byId('rememberSecret').checked = false; byId('secret').value = ''; toast('Senha esquecida neste navegador.'); }
  async function api(path, options){
    options = options || {}; saveSecretIfNeeded();
    var headers = Object.assign({'Content-Type':'application/json','x-liveplay-admin-secret':secret()}, options.headers || {});
    var res = await fetch(path, Object.assign({}, options, { headers: headers }));
    var data = await res.json().catch(function(){ return null; });
    if(!res.ok || !data || data.ok !== true){ throw new Error((data && data.error) ? data.error : ('Falha HTTP ' + res.status)); }
    return data;
  }
  function formatDate(value){ if(!value) return 'sem expiração'; try{ return new Date(value).toLocaleString('pt-BR'); }catch(e){ return String(value); } }
  function setStats(users){
    var total = users.length, pro = 0, free = 0, expired = 0;
    users.forEach(function(u){ var plan = (u.effectivePlan && u.effectivePlan.plan) || 'FREE'; var status = (u.effectivePlan && u.effectivePlan.status) || ''; if(plan === 'PRO') pro++; else free++; if(status === 'expired') expired++; });
    byId('statTotal').textContent = total; byId('statPro').textContent = pro; byId('statFree').textContent = free; byId('statExpired').textContent = expired;
  }
  function fillUser(u){
    var sub = u.subscription || {}; var effective = u.effectivePlan || {}; var plan = effective.plan || sub.plan || 'FREE';
    byId('email').value = u.email || ''; byId('plan').value = plan === 'PRO' ? 'PRO' : 'FREE'; byId('status').value = sub.status || effective.status || 'active'; byId('expiresAt').value = sub.expires_at ? String(sub.expires_at).slice(0,16) : ''; toast('Usuário selecionado.');
  }
  function setExpirationDays(days){ var d = new Date(); d.setDate(d.getDate() + days); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); byId('expiresAt').value = d.toISOString().slice(0,16); byId('plan').value = 'PRO'; byId('status').value = 'active'; }
  function renderUsers(users){
    var box = byId('users'); box.innerHTML = ''; setStats(users);
    if(!users.length){ box.innerHTML = '<div class="muted">Nenhum usuário encontrado.</div>'; return; }
    users.forEach(function(u){
      var plan = (u.effectivePlan && u.effectivePlan.plan) || 'FREE'; var status = (u.effectivePlan && u.effectivePlan.status) || '-'; var sub = u.subscription || {}; var div = document.createElement('div'); div.className = 'user';
      var top = document.createElement('div'); top.className = 'userTop';
      var email = document.createElement('div'); email.className = 'email'; email.textContent = u.email || '';
      var pill = document.createElement('span'); pill.className = 'pill ' + (plan === 'PRO' ? 'pro' : 'free'); if(status === 'expired') pill.className = 'pill expired'; pill.textContent = plan;
      top.appendChild(email); top.appendChild(pill);
      var meta = document.createElement('div'); meta.className = 'muted'; meta.textContent = 'status: ' + (sub.status || status) + ' · expira: ' + formatDate(sub.expires_at || (u.effectivePlan && u.effectivePlan.expiresAt));
      var row = document.createElement('div'); row.className = 'row';
      var select = document.createElement('button'); select.className = 'secondary'; select.type = 'button'; select.textContent = 'Selecionar'; select.addEventListener('click', function(){ fillUser(u); });
      var pro30 = document.createElement('button'); pro30.type = 'button'; pro30.textContent = '+30 dias'; pro30.addEventListener('click', async function(){ fillUser(u); setExpirationDays(30); await setPlan(); });
      var free = document.createElement('button'); free.className = 'dangerBtn'; free.type = 'button'; free.textContent = 'FREE'; free.addEventListener('click', async function(){ fillUser(u); byId('plan').value='FREE'; byId('status').value='active'; byId('expiresAt').value=''; await setPlan(); });
      row.appendChild(select); row.appendChild(pro30); row.appendChild(free);
      div.appendChild(top); div.appendChild(meta); div.appendChild(row); box.appendChild(div);
    });
  }
  async function loadUsers(){
    try{ var q = encodeURIComponent(byId('search').value.trim()); var data = await api('/admin/users?limit=100&search=' + q); lastUsers = data.users || []; renderUsers(lastUsers); log(data); toast('Usuários carregados.'); }catch(e){ log('Erro: ' + e.message); toast('Erro ao carregar.'); }
  }
  async function setPlan(){
    try{ var body = { email: byId('email').value.trim(), plan: byId('plan').value, status: byId('status').value, expiresAt: byId('expiresAt').value || null }; var data = await api('/admin/set-plan', { method:'POST', body:JSON.stringify(body) }); log(data); toast('Plano salvo.'); await loadUsers(); }catch(e){ log('Erro: ' + e.message); toast('Erro ao salvar.'); }
  }
  function clearForm(){ byId('email').value=''; byId('plan').value='FREE'; byId('status').value='active'; byId('expiresAt').value=''; }
  byId('btnLoadUsers').addEventListener('click', loadUsers); byId('btnReload').addEventListener('click', loadUsers); byId('btnClearLog').addEventListener('click', function(){ log('Pronto.'); }); byId('btnSetPlan').addEventListener('click', setPlan); byId('btnForgetSecret').addEventListener('click', forgetSecret); byId('btnClearForm').addEventListener('click', clearForm);
  byId('btnPro30').addEventListener('click', async function(){ setExpirationDays(30); await setPlan(); }); byId('btnPro7').addEventListener('click', async function(){ setExpirationDays(7); await setPlan(); }); byId('btnSetFree').addEventListener('click', async function(){ byId('plan').value='FREE'; byId('status').value='active'; byId('expiresAt').value=''; await setPlan(); });
  byId('search').addEventListener('keydown', function(e){ if(e.key === 'Enter') loadUsers(); }); byId('secret').addEventListener('keydown', function(e){ if(e.key === 'Enter') loadUsers(); });
  loadSavedSecret(); if(secret()){ window.setTimeout(loadUsers, 250); }
})();
</script>
</body></html>`;
}

function oauthSuccessHtml() {
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LivePlay Login</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#080d1a;color:#e5e7eb;font-family:Inter,system-ui,Segoe UI,Arial,sans-serif}.card{max-width:520px;background:#0f172a;border:1px solid rgba(148,163,184,.24);border-radius:24px;padding:28px;box-shadow:0 24px 80px rgba(0,0,0,.35)}h1{margin:0 0 10px;font-size:28px}.muted{color:#a8b3cf;line-height:1.6}</style></head><body><div class="card"><h1>Login LivePlay confirmado ✅</h1><p class="muted">Você já pode voltar para o app. Esta janela pode ser fechada.</p></div></body></html>`;
}

function oauthErrorHtml(message) {
  const safe = String(message || 'Falha no login social.').replace(/[<>&"]/g, (c) => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LivePlay Login</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#080d1a;color:#e5e7eb;font-family:Inter,system-ui,Segoe UI,Arial,sans-serif}.card{max-width:520px;background:#0f172a;border:1px solid rgba(248,113,113,.32);border-radius:24px;padding:28px;box-shadow:0 24px 80px rgba(0,0,0,.35)}h1{margin:0 0 10px;font-size:28px}.muted{color:#fecaca;line-height:1.6}</style></head><body><div class="card"><h1>Não foi possível entrar</h1><p class="muted">${safe}</p></div></body></html>`;
}

function cleanExpiredOAuthPending() {
  const now = Date.now();
  for (const [key, value] of oauthPendingSessions.entries()) {
    if (!value?.expiresAt || value.expiresAt <= now) oauthPendingSessions.delete(key);
  }
}

async function createOrGetOAuthUser(email) {
  const cleanEmail = normalizeEmail(email);
  if (!validateEmail(cleanEmail)) throw new Error('O provedor não retornou um email válido.');
  const existing = await getUserByEmail(cleanEmail);
  if (existing?.id) return existing;
  const inserted = await supabaseRequest('liveplay_users', {
    method: 'POST',
    body: [{ email: cleanEmail, password_hash: hashPassword(crypto.randomUUID()) }],
  });
  const user = Array.isArray(inserted) ? inserted[0] || null : null;
  if (!user?.id) throw new Error('Falha ao criar conta LivePlay pelo login social.');
  await createFreeSubscription(user.id);
  return user;
}

async function createOAuthSessionPayload(user, req) {
  const subscription = await getSubscriptionForUser(user.id);
  const plan = resolvePlanFromSubscription(subscription);
  const session = await createActiveSessionTokenForUser(user, req);
  return {
    ok: true,
    token: session.token,
    refreshToken: session.refreshToken,
    refreshExpiresAt: session.refreshExpiresAt,
    sessionId: session.sessionId,
    user: { id: session.user.id, email: session.user.email },
    plan,
  };
}

async function handleOAuthStart(req, res) {
  try {
    const body = await readJsonBody(req);
    const provider = String(body.provider || '').toLowerCase();
    if (!['google', 'github'].includes(provider)) {
      return jsonResponse(res, 400, { ok: false, error: 'Provedor inválido.' });
    }

    if (provider === 'google' && (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET)) {
      return jsonResponse(res, 500, { ok: false, error: 'Google OAuth não configurado no Render.' });
    }
    if (provider === 'github' && (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET)) {
      return jsonResponse(res, 500, { ok: false, error: 'GitHub OAuth não configurado no Render.' });
    }

    cleanExpiredOAuthPending();
    const state = crypto.randomUUID();
    oauthPendingSessions.set(state, { provider, status: 'pending', createdAt: Date.now(), expiresAt: Date.now() + 10 * 60 * 1000 });
    const redirectUri = `${OAUTH_REDIRECT_BASE}/auth/oauth/${provider}/callback`;
    let authUrl = '';
    if (provider === 'google') {
      const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        access_type: 'offline',
        prompt: 'select_account',
        state,
      });
      authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    } else {
      const params = new URLSearchParams({
        client_id: GITHUB_CLIENT_ID,
        redirect_uri: redirectUri,
        scope: 'read:user user:email',
        state,
      });
      authUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;
    }
    return jsonResponse(res, 200, { ok: true, provider, state, authUrl, expiresInSeconds: 600 });
  } catch (error) {
    return jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao iniciar login social.' });
  }
}

async function fetchGoogleOAuthEmail(code, redirectUri) {
  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });
  const tokenData = await tokenResponse.json().catch(() => null);
  if (!tokenResponse.ok || !tokenData?.access_token) throw new Error('Falha ao autorizar Google.');
  const infoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  const info = await infoResponse.json().catch(() => null);
  if (!infoResponse.ok || !info?.email) throw new Error('Google não retornou email.');
  return normalizeEmail(info.email);
}

async function fetchGitHubOAuthEmail(code, redirectUri) {
  const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      redirect_uri: redirectUri,
    }),
  });
  const tokenData = await tokenResponse.json().catch(() => null);
  if (!tokenResponse.ok || !tokenData?.access_token) throw new Error('Falha ao autorizar GitHub.');

  const userResponse = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'LivePlay' },
  });
  const userInfo = await userResponse.json().catch(() => null);
  if (userResponse.ok && userInfo?.email) return normalizeEmail(userInfo.email);

  const emailsResponse = await fetch('https://api.github.com/user/emails', {
    headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'LivePlay' },
  });
  const emails = await emailsResponse.json().catch(() => null);
  const primary = Array.isArray(emails) ? emails.find((item) => item?.primary && item?.verified && item?.email) || emails.find((item) => item?.verified && item?.email) : null;
  if (!primary?.email) throw new Error('GitHub não retornou email verificado.');
  return normalizeEmail(primary.email);
}

async function handleOAuthCallback(req, res, provider) {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    const code = String(url.searchParams.get('code') || '').trim();
    const state = String(url.searchParams.get('state') || '').trim();
    const pending = oauthPendingSessions.get(state);
    if (!code || !state || !pending || pending.provider !== provider) {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(oauthErrorHtml('Sessão OAuth inválida ou expirada. Volte ao app e tente novamente.'));
      return;
    }

    const redirectUri = `${OAUTH_REDIRECT_BASE}/auth/oauth/${provider}/callback`;
    const email = provider === 'google'
      ? await fetchGoogleOAuthEmail(code, redirectUri)
      : await fetchGitHubOAuthEmail(code, redirectUri);

    const user = await createOrGetOAuthUser(email);
    const sessionPayload = await createOAuthSessionPayload(user, req);
    oauthPendingSessions.set(state, { ...pending, status: 'complete', session: sessionPayload, email, completedAt: Date.now(), expiresAt: Date.now() + 10 * 60 * 1000 });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(oauthSuccessHtml());
  } catch (error) {
    console.error('Erro OAuth callback:', error);
    res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(oauthErrorHtml(error instanceof Error ? error.message : 'Falha no login social.'));
  }
}

async function handleOAuthStatus(req, res) {
  try {
    cleanExpiredOAuthPending();
    const url = new URL(req.url || '/', 'http://localhost');
    const state = String(url.searchParams.get('state') || '').trim();
    const pending = oauthPendingSessions.get(state);
    if (!state || !pending) return jsonResponse(res, 404, { ok: false, error: 'Login social expirado ou não encontrado.' });
    if (pending.status !== 'complete' || !pending.session) return jsonResponse(res, 200, { ok: true, status: 'pending' });
    oauthPendingSessions.delete(state);
    return jsonResponse(res, 200, { ok: true, status: 'complete', session: pending.session });
  } catch (error) {
    return jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao consultar login social.' });
  }
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
    const session = await createActiveSessionTokenForUser(user, req);
    jsonResponse(res, 200, {
      ok: true,
      token: session.token,
      refreshToken: session.refreshToken,
      refreshExpiresAt: session.refreshExpiresAt,
      sessionId: session.sessionId,
      user: { id: session.user.id, email: session.user.email },
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
    const session = await createActiveSessionTokenForUser(user, req);
    jsonResponse(res, 200, {
      ok: true,
      token: session.token,
      refreshToken: session.refreshToken,
      refreshExpiresAt: session.refreshExpiresAt,
      sessionId: session.sessionId,
      user: { id: session.user.id, email: session.user.email },
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
    if (!isSessionValidForUser(payload, user)) {
      return jsonResponse(res, 401, { ok: false, error: 'Sessão encerrada porque esta conta entrou em outro dispositivo.' });
    }
    await touchCurrentDeviceSession(user, payload, req);
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


async function handleAuthRefresh(req, res) {
  try {
    const body = await readJsonBody(req);
    const refreshToken = String(body.refreshToken || '').trim();
    if (!refreshToken) {
      return jsonResponse(res, 401, { ok: false, error: 'Refresh token ausente.' });
    }

    const refreshTokenHash = hashRefreshToken(refreshToken);
    const sessions = await supabaseRequest('liveplay_device_sessions', {
      query: `refresh_token_hash=eq.${encodeURIComponent(refreshTokenHash)}&is_active=eq.true&limit=1`,
    });
    const deviceSession = Array.isArray(sessions) ? sessions[0] || null : null;
    if (!deviceSession?.user_id || !deviceSession?.session_id) {
      return jsonResponse(res, 401, { ok: false, error: 'Sessão inválida ou expirada.' });
    }

    const refreshExpiresAt = deviceSession.refresh_expires_at ? new Date(deviceSession.refresh_expires_at).getTime() : 0;
    if (!refreshExpiresAt || refreshExpiresAt <= Date.now()) {
      await supabaseRequest('liveplay_device_sessions', {
        method: 'PATCH',
        query: `id=eq.${encodeURIComponent(deviceSession.id)}`,
        body: { is_active: false, status: 'expired', revoked_at: new Date().toISOString(), updated_at: new Date().toISOString() },
        prefer: 'return=minimal',
      });
      return jsonResponse(res, 401, { ok: false, error: 'Sessão expirada. Entre novamente.' });
    }

    const user = await getUserById(deviceSession.user_id);
    if (!user || String(user.active_session_id || '') !== String(deviceSession.session_id || '')) {
      return jsonResponse(res, 401, { ok: false, error: 'Sessão encerrada porque esta conta entrou em outro dispositivo.' });
    }

    await saveDeviceSession(user, deviceSession.session_id, req, 'active', {
      refresh_token_hash: refreshTokenHash,
      refresh_expires_at: deviceSession.refresh_expires_at,
    });

    const subscription = await getSubscriptionForUser(user.id);
    const plan = resolvePlanFromSubscription(subscription);
    return jsonResponse(res, 200, {
      ok: true,
      token: signToken({ userId: user.id, email: user.email, sessionId: deviceSession.session_id }),
      refreshToken,
      refreshExpiresAt: deviceSession.refresh_expires_at,
      sessionId: deviceSession.session_id,
      user: { id: user.id, email: user.email },
      plan,
    });
  } catch (error) {
    return jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao renovar sessão.' });
  }
}


async function handleDeviceSessions(req, res) {
  try {
    const context = await getAuthenticatedLivePlayContext(req);
    if (!context?.user) {
      return jsonResponse(res, 401, { ok: false, error: 'Sessão inválida ou expirada.' });
    }

    await touchCurrentDeviceSession(context.user, context.payload, req);

    const sessions = await supabaseRequest('liveplay_device_sessions', {
      query: `user_id=eq.${encodeURIComponent(context.user.id)}&order=last_seen_at.desc&limit=20`,
    });

    const activeSessionId = String(context.user.active_session_id || '').trim();
    return jsonResponse(res, 200, {
      ok: true,
      currentSessionId: activeSessionId,
      devices: (Array.isArray(sessions) ? sessions : []).map((item) => ({
        id: item.id,
        deviceName: item.device_name || 'Dispositivo LivePlay',
        email: item.email || context.user.email,
        status: item.status || (item.is_active ? 'active' : 'inactive'),
        isActive: Boolean(item.is_active) && String(item.session_id || '') === activeSessionId && !item.revoked_at,
        isCurrent: String(item.session_id || '') === String(context.payload.sessionId || ''),
        ipAddress: item.ip_address || '',
        createdAt: item.created_at || null,
        lastSeenAt: item.last_seen_at || item.updated_at || null,
        revokedAt: item.revoked_at || null,
      })),
    });
  } catch (error) {
    return jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao listar dispositivos.' });
  }
}

async function handleRevokeAllDevices(req, res) {
  try {
    const context = await getAuthenticatedLivePlayContext(req);
    if (!context?.user) {
      return jsonResponse(res, 401, { ok: false, error: 'Sessão inválida ou expirada.' });
    }

    const now = new Date().toISOString();
    await supabaseRequest('liveplay_device_sessions', {
      method: 'PATCH',
      query: `user_id=eq.${encodeURIComponent(context.user.id)}`,
      body: {
        is_active: false,
        status: 'revoked',
        revoked_at: now,
        updated_at: now,
      },
      prefer: 'return=minimal',
    });

    await supabaseRequest('liveplay_users', {
      method: 'PATCH',
      query: `id=eq.${encodeURIComponent(context.user.id)}`,
      body: {
        active_session_id: null,
        active_session_updated_at: now,
      },
      prefer: 'return=minimal',
    });

    return jsonResponse(res, 200, { ok: true, revoked: true });
  } catch (error) {
    return jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao revogar sessões.' });
  }
}


async function handleRevokeDeviceSession(req, res) {
  try {
    const context = await getAuthenticatedLivePlayContext(req);
    if (!context?.user) {
      return jsonResponse(res, 401, { ok: false, error: 'Sessão inválida ou expirada.' });
    }

    const body = await readJsonBody(req);
    const deviceId = String(body.deviceId || body.id || '').trim();
    const sessionId = String(body.sessionId || '').trim();

    if (!deviceId && !sessionId) {
      return jsonResponse(res, 400, { ok: false, error: 'Dispositivo inválido.' });
    }

    const query = deviceId
      ? `id=eq.${encodeURIComponent(deviceId)}&user_id=eq.${encodeURIComponent(context.user.id)}&limit=1`
      : `session_id=eq.${encodeURIComponent(sessionId)}&user_id=eq.${encodeURIComponent(context.user.id)}&limit=1`;

    const found = await supabaseRequest('liveplay_device_sessions', { query });
    const device = Array.isArray(found) ? found[0] || null : null;

    if (!device?.id) {
      return jsonResponse(res, 404, { ok: false, error: 'Dispositivo não encontrado.' });
    }

    const now = new Date().toISOString();
    await supabaseRequest('liveplay_device_sessions', {
      method: 'PATCH',
      query: `id=eq.${encodeURIComponent(device.id)}&user_id=eq.${encodeURIComponent(context.user.id)}`,
      body: {
        is_active: false,
        status: 'revoked',
        revoked_at: now,
        updated_at: now,
      },
      prefer: 'return=minimal',
    });

    const revokedSessionId = String(device.session_id || '').trim();
    const currentTokenSessionId = String(context.payload?.sessionId || '').trim();
    const activeSessionId = String(context.user?.active_session_id || '').trim();
    const revokedCurrent = Boolean(revokedSessionId && revokedSessionId === currentTokenSessionId);
    const revokedActive = Boolean(revokedSessionId && revokedSessionId === activeSessionId);

    if (revokedActive) {
      await supabaseRequest('liveplay_users', {
        method: 'PATCH',
        query: `id=eq.${encodeURIComponent(context.user.id)}`,
        body: {
          active_session_id: null,
          active_session_updated_at: now,
        },
        prefer: 'return=minimal',
      });
    }

    return jsonResponse(res, 200, {
      ok: true,
      revoked: true,
      revokedCurrent,
      deviceId: device.id,
    });
  } catch (error) {
    return jsonResponse(res, 500, { ok: false, error: error instanceof Error ? error.message : 'Falha ao revogar dispositivo.' });
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
  const requestUrl = new URL(req.url || '/', 'http://localhost');
  const pathname = requestUrl.pathname;

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


  if (req.url === '/auth/oauth/start' && req.method === 'POST') {
    await handleOAuthStart(req, res);
    return;
  }

  if (pathname === '/auth/oauth/status' && req.method === 'GET') {
    await handleOAuthStatus(req, res);
    return;
  }

  if (pathname === '/auth/oauth/google/callback' && req.method === 'GET') {
    await handleOAuthCallback(req, res, 'google');
    return;
  }

  if (pathname === '/auth/oauth/github/callback' && req.method === 'GET') {
    await handleOAuthCallback(req, res, 'github');
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

  if (req.url === '/auth/refresh' && req.method === 'POST') {
    await handleAuthRefresh(req, res);
    return;
  }

  if (req.url === '/me/plan' && req.method === 'GET') {
    await handleMePlan(req, res);
    return;
  }

  if (req.url === '/devices/sessions' && req.method === 'GET') {
    await handleDeviceSessions(req, res);
    return;
  }

  if (req.url === '/devices/revoke-all' && req.method === 'POST') {
    await handleRevokeAllDevices(req, res);
    return;
  }

  if (req.url === '/devices/revoke-session' && req.method === 'POST') {
    await handleRevokeDeviceSession(req, res);
    return;
  }


  if (req.url === '/cloud/save' && req.method === 'POST') {
    await handleCloudSave(req, res);
    return;
  }

  if (req.url === '/cloud/load' && req.method === 'GET') {
    await handleCloudLoad(req, res);
    return;
  }

  if (req.url === '/payments/create-checkout' && req.method === 'POST') {
    await handleCreateCheckout(req, res);
    return;
  }


  if (pathname === '/payments/webhook' && req.method === 'GET') {
    return sendJson(res, 200, { ok: true, route: 'payments-webhook' });
  }

  if (pathname === '/payments/webhook' && req.method === 'POST') {
    await handleMercadoPagoWebhook(req, res);
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