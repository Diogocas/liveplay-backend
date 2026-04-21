import express from 'express';

const app = express();
app.use(express.json());

app.get('/', (req, res) => {
  res.send('LivePlay Backend Online 🚀');
});

app.get('/overlay/:id', (req, res) => {
  const { id } = req.params;

  res.send(`
    <html>
      <head>
        <title>LivePlay Overlay</title>
        <style>
          body {
            margin: 0;
            background: transparent;
            overflow: hidden;
          }
        </style>
      </head>
      <body>
        <h1 style="color:white;">Overlay ID: ${id}</h1>
      </body>
    </html>
  `);
});

app.listen(3000, () => {
  console.log('Servidor rodando');
});