const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 10000;

let overlayClients = [];
let videoClients = [];

let lastOverlayPayload = null;

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // HEALTH
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('LivePlay Backend Online 🚀');
    return;
  }

  // =============================
  // OVERLAY BRIDGE
  // =============================

  if (req.url.startsWith('/overlay-bridge/events')) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });

    res.write('\n');

    overlayClients.push(res);

    req.on('close', () => {
      overlayClients = overlayClients.filter(c => c !== res);
    });

    return;
  }

  if (req.url === '/overlay-bridge/emit' && req.method === 'POST') {
    let body = '';

    req.on('data', chunk => body += chunk);

    req.on('end', () => {
      try {
        const data = JSON.parse(body);

        lastOverlayPayload = data;

        overlayClients.forEach(client => {
          client.write(`data: ${JSON.stringify(data)}\n\n`);
        });

        res.writeHead(200);
        res.end('ok');
      } catch {
        res.writeHead(400);
        res.end('error');
      }
    });

    return;
  }

  if (req.url.startsWith('/overlay-bridge/snapshot')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      payload: lastOverlayPayload
    }));
    return;
  }

  // =============================
  // VIDEO ALERT BRIDGE
  // =============================

  if (req.url.startsWith('/video-alert-bridge/events')) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });

    res.write('\n');

    videoClients.push(res);

    req.on('close', () => {
      videoClients = videoClients.filter(c => c !== res);
    });

    return;
  }

  if (req.url === '/video-alert-bridge/emit' && req.method === 'POST') {
    let body = '';

    req.on('data', chunk => body += chunk);

    req.on('end', () => {
      try {
        const data = JSON.parse(body);

        videoClients.forEach(client => {
          client.write(`data: ${JSON.stringify(data)}\n\n`);
        });

        res.writeHead(200);
        res.end('ok');
      } catch {
        res.writeHead(400);
        res.end('error');
      }
    });

    return;
  }

  // =============================
  // SERVIR ARQUIVOS DE VÍDEO (OPCIONAL)
  // =============================

  if (req.url.startsWith('/video-alert-bridge/assets/')) {
    const filePath = path.join(__dirname, req.url.replace('/video-alert-bridge/assets/', ''));

    if (!fs.existsSync(filePath)) {
      res.writeHead(404);
      res.end('not found');
      return;
    }

    const stream = fs.createReadStream(filePath);
    res.writeHead(200);
    stream.pipe(res);
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log('Servidor rodando na porta', PORT);
});
