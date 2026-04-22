const http = require('http');

const PORT = process.env.PORT || 10000;

const clients = {
  overlay: new Set(),
  video: new Set(),
};

const latestPayloads = new Map();

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function makePayloadKey(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const type = typeof payload.type === 'string' ? payload.type : '';
  if (!type) return null;
  const board = typeof payload.board === 'string' ? payload.board : '';
  return board ? `${type}:${board}` : type;
}

function getLatestPayload(type, board) {
  if (!type) return null;
  if (board) return latestPayloads.get(`${type}:${board}`) ?? null;
  return latestPayloads.get(type) ?? null;
}

function writeSse(res, payload) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function registerSseClient(bucket, req, res, latest) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, no-transform',
    Pragma: 'no-cache',
    Expires: '0',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(': connected\n\n');
  bucket.add(res);

  if (latest) {
    try {
      writeSse(res, latest);
    } catch {}
  }

  req.on('close', () => {
    bucket.delete(res);
    try { res.end(); } catch {}
  });
}

function broadcast(bucketName, payload, options = {}) {
  const key = makePayloadKey(payload);
  if (bucketName === 'overlay' && key) {
    latestPayloads.set(key, payload);
  }

  for (const client of clients[bucketName]) {
    try {
      if (bucketName === 'overlay') {
        const clientType = client.__liveplayType;
        const clientBoard = client.__liveplayBoard;
        const payloadType = typeof payload.type === 'string' ? payload.type : '';
        const payloadBoard = typeof payload.board === 'string' ? payload.board : '';
        if (clientType && clientType !== payloadType) continue;
        if (clientBoard && clientBoard !== payloadBoard) continue;
      }
      writeSse(client, payload);
    } catch {
      clients[bucketName].delete(client);
    }
  }
}

const server = http.createServer((req, res) => {
  setCors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || '/', `http://localhost:${PORT}`);

  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('LivePlay Backend Online 🚀');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, { ok: true, port: PORT });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/overlay-bridge/events') {
    const type = url.searchParams.get('type') || '';
    const board = url.searchParams.get('board') || '';
    res.__liveplayType = type;
    res.__liveplayBoard = board;
    registerSseClient(clients.overlay, req, res, getLatestPayload(type || undefined, board || undefined));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/overlay-bridge/snapshot') {
    sendJson(res, 200, {
      ok: true,
      payload: getLatestPayload(url.searchParams.get('type') || undefined, url.searchParams.get('board') || undefined),
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/overlay-bridge/emit') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const payload = body ? JSON.parse(body) : null;
        if (payload) broadcast('overlay', payload);
        sendJson(res, 200, { ok: true });
      } catch (error) {
        sendJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
      }
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/video-alert-bridge/events') {
    registerSseClient(clients.video, req, res, null);
    return;
  }

  if (req.method === 'POST' && url.pathname === '/video-alert-bridge/emit') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const payload = body ? JSON.parse(body) : null;
        if (payload) broadcast('video', payload);
        sendJson(res, 200, { ok: true });
      } catch (error) {
        sendJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
      }
    });
    return;
  }

  sendJson(res, 404, { ok: false, error: 'Not found' });
});

server.listen(PORT, () => {
  console.log('Servidor rodando na porta', PORT);
});
