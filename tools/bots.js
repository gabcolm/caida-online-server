import WebSocket from 'ws';

const BASE = process.env.CAIDA_URL || 'http://localhost:3000';
const NUM = Number(process.env.BOTS || 3);
const bots = [];

function idUnico(i) {
  return 'Bot' + Date.now().toString().slice(-6) + i;
}

async function registrar(nombre) {
  const r = await fetch(BASE + '/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: nombre, password: 'secreto123' })
  });
  const texto = await r.text();
  if (!r.ok) throw new Error(texto);
  return JSON.parse(texto);
}

function conectar(token, nombre) {
  const ws = new WebSocket(BASE.replace('http', 'ws') + '/ws?token=' + token);
  const bot = { ws, nombre, jugada: false };
  ws.on('open', () => {
    console.log('bot conectado', nombre);
    ws.send(JSON.stringify({ type: 'quickMatch' }));
  });
  ws.on('message', (data) => {
    const m = JSON.parse(String(data));
    if (m.type === 'error') console.log(nombre, 'error:', m.message);
    if (m.type === 'gameState' && m.state && m.room) {
      if (m.state.phase === 'voting' && !bot.voto) {
        bot.voto = true;
        ws.send(JSON.stringify({ type: 'voteTribilin', vote: Math.random() > 0.5 ? 1 : 2 }));
      }
      if (m.room.yourSeat === m.state.turnSeat && m.state.phase === 'playing' && !bot.jugada) {
        bot.jugada = true;
        const carta = m.state.ownHand?.[0];
        setTimeout(() => {
          if (carta) ws.send(JSON.stringify({ type: 'playCard', cardId: carta }));
          bot.jugada = false;
        }, 500);
      }
    }
    if (m.type === 'hello') console.log(nombre, 'listo para jugar');
  });
  ws.on('close', () => console.log('bot desconectado', nombre));
  bots.push(bot);
}

const usuarios = [];
for (let i = 0; i < NUM; i++) {
  const nombre = idUnico(i);
  const datos = await registrar(nombre);
  usuarios.push({ nombre, token: datos.token });
}
for (const u of usuarios) conectar(u.token, u.nombre);

process.on('SIGINT', () => {
  for (const b of bots) b.ws.close();
  process.exit(0);
});
