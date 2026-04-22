const http = require('http');

const PORT = process.env.PORT || 10000;

let clients = [];

const server = http.createServer((req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');

  // HEALTH
  if (req.url === '/') {
    res.writeHead(200);
    res.end('LivePlay Backend Online 🚀');
    return;
  }

  // SSE EVENTS
  if (req.url.startsWith('/overlay-bridge/events')) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });

    res.write('\n');

    clients.push(res);

    req.on('close', () => {
      clients = clients.filter(c => c !== res);
    });

    return;
  }

  // EMIT EVENT
  if (req.url === '/overlay-bridge/emit' && req.method === 'POST') {
    let body = '';

    req.on('data', chunk => {
      body += chunk;
    });

    req.on('end', () => {
      try {
        const data = JSON.parse(body);

        clients.forEach(client => {
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

  // SNAPSHOT (básico)
  if (req.url.startsWith('/overlay-bridge/snapshot')) {
    res.writeHead(200, {
      'Content-Type': 'application/json'
    });

    res.end(JSON.stringify({
      ok: true,
      payload: null
    }));

    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log('Servidor rodando na porta', PORT);
});
