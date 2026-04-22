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

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('LivePlay Backend Online 🚀');
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
