import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { URL, fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import WebSocket from 'ws';
import { codigoTotp } from '../src/security.js';
import { reiniciarBaseDePruebas, urlPruebas } from './helpers/test-db.js';

const PUERTO = 31337;
const BASE = `http://127.0.0.1:${PUERTO}`;
const WS = `ws://127.0.0.1:${PUERTO}/ws?token=`;
const dirTemp = mkdtempSync(path.join(os.tmpdir(), 'caida-test-'));
let proceso;

class Cliente {
  constructor(token) {
    this.mensajes = [];
    this.esperas = [];
    this.ws = new WebSocket(WS + token);
    this.ws.on('message', (data) => {
      const mensaje = JSON.parse(String(data));
      const indice = this.esperas.findIndex((e) => e.tipo === mensaje.type);
      if (indice >= 0) {
        const [espera] = this.esperas.splice(indice, 1);
        clearTimeout(espera.timer);
        espera.resolve(mensaje);
      } else {
        this.mensajes.push(mensaje);
      }
    });
  }

  abrir() {
    return new Promise((resolve, reject) => {
      this.ws.once('open', resolve);
      this.ws.once('error', reject);
    });
  }

  esperar(tipo, timeout = 5000) {
    const existente = this.mensajes.findIndex((m) => m.type === tipo);
    if (existente >= 0) return Promise.resolve(this.mensajes.splice(existente, 1)[0]);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Timeout esperando ' + tipo)), timeout);
      this.esperas.push({ tipo, resolve, timer });
    });
  }

  async esperarFase(fase, timeout = 8000) {
    const inicio = Date.now();
    while (Date.now() - inicio < timeout) {
      const mensaje = await this.esperar('gameState', timeout);
      if (mensaje.state && mensaje.state.phase === fase) return mensaje;
    }
    throw new Error('No llegó la fase ' + fase);
  }

  enviar(payload) {
    this.ws.send(JSON.stringify(payload));
  }

  cerrar() {
    this.ws.close();
  }
}

async function esperarServidor() {
  for (let i = 0; i < 80; i++) {
    try {
      const r = await fetch(BASE + '/api/health');
      if (r.ok) return;
    } catch { /* reintentar */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error('El servidor no arrancó.');
}

async function registrar(nombre) {
  const r = await fetch(BASE + '/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: nombre, password: 'secreto123' })
  });
  const texto = await r.text();
  assert.equal(r.status, 201, texto);
  return JSON.parse(texto);
}

async function postJson(ruta, cuerpo, token = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  const r = await fetch(BASE + ruta, { method: 'POST', headers, body: JSON.stringify(cuerpo) });
  const texto = await r.text();
  return { status: r.status, body: texto ? JSON.parse(texto) : null };
}

test.before(async () => {
  await reiniciarBaseDePruebas();
  const raiz = path.dirname(fileURLToPath(import.meta.url));
  proceso = spawn(process.execPath, [path.join(raiz, '..', 'src', 'index.js')], {
    cwd: path.join(raiz, '..'),
    env: {
      ...process.env,
      PORT: String(PUERTO),
      DATABASE_URL: urlPruebas(),
      ENV_FILE: path.join(dirTemp, 'test.env'),
      TURN_MS: '5000',
      DEV_CODES: '1',
      AUTH_RATE_MAX: '80',
      ADMIN_TOKEN: 'test-admin'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  proceso.stderr.on('data', (d) => process.stderr.write(d));
  await esperarServidor();
});

test.after(() => {
  proceso?.kill();
  try { rmSync(dirTemp, { recursive: true, force: true }); } catch { /* ignore */ }
});

test('flujo HTTP + WebSocket: 4 jugadores, matchmaking, turno y reconexión', async () => {
  const sufijo = Date.now().toString().slice(-6);
  const usuarios = [];
  for (let i = 0; i < 4; i++) {
    const datos = await registrar('Test' + sufijo + i);
    usuarios.push(datos);
  }

  const clientes = usuarios.map((u) => new Cliente(u.token));
  await Promise.all(clientes.map((c) => c.abrir()));
  await Promise.all(clientes.map((c) => c.esperar('hello')));

  for (const cliente of clientes) cliente.enviar({ type: 'quickMatch' });

  const iniciales = [];
  for (const cliente of clientes) {
    const mensaje = await cliente.esperar('gameState', 8000);
    iniciales.push(mensaje);
  }
  assert.equal(iniciales[0].state.phase, 'voting');
  assert.equal(iniciales[0].state.votosEmitidos, 0);
  assert.equal(iniciales[0].room.players.length, 4);
  assert.ok(iniciales[0].room.players.every((p) => p && p.userId > 0));

  for (const cliente of clientes) cliente.enviar({ type: 'voteTribilin', vote: 1 });

  const estados = [];
  const salas = [];
  for (const cliente of clientes) {
    const mensaje = await cliente.esperarFase('playing', 8000);
    estados.push(mensaje.state);
    salas.push(mensaje.room);
  }

  for (const estado of estados) {
    assert.equal(estado.ownHand.length, 3);
    assert.equal(estado.table.length, 4);
    assert.ok(estado.dealerSeat >= 0 && estado.dealerSeat <= 3);
  }

  const turno = estados[0].turnSeat;
  const indiceTurno = salas.findIndex((s) => s.yourSeat === turno);
  const clienteTurno = clientes[indiceTurno];
  const carta = estados[indiceTurno].ownHand[0];
  const turnoAnterior = estados[0].turnSeat;
  clienteTurno.enviar({ type: 'playCard', cardId: carta });

  const siguiente = await clienteTurno.esperar('gameState', 5000);
  assert.notEqual(siguiente.state.turnSeat, turnoAnterior);
  assert.ok(siguiente.state.table.length >= 1);

  const reconectado = new Cliente(usuarios[0].token);
  await reconectado.abrir();
  await reconectado.esperar('hello');
  reconectado.enviar({ type: 'sync' });
  const estadoReconectado = await reconectado.esperar('gameState', 5000);
  assert.ok(estadoReconectado.room);
  assert.equal(estadoReconectado.room.players.filter((p) => p && p.userId > 0).length, 4);

  for (const c of clientes) c.cerrar();
  reconectado.cerrar();
  await new Promise((r) => setTimeout(r, 100));
});

test('sala privada: crear, unirse, iniciar y código inválido', async () => {  const sufijo = Date.now().toString().slice(-6);
  const usuarios = [];
  for (let i = 0; i < 4; i++) usuarios.push(await registrar('Priv' + sufijo + i));

  const clientes = usuarios.map((u) => new Cliente(u.token));
  await Promise.all(clientes.map((c) => c.abrir()));
  await Promise.all(clientes.map((c) => c.esperar('hello')));

  clientes[0].enviar({ type: 'createRoom' });
  const salaCreada = await clientes[0].esperar('roomState', 5000);
  const codigo = salaCreada.room.code;
  assert.ok(codigo);
  assert.equal(salaCreada.room.hostSeat, salaCreada.room.yourSeat);
  assert.equal(salaCreada.room.players.filter((p) => p && p.userId > 0).length, 1);

  for (let i = 1; i < 4; i++) clientes[i].enviar({ type: 'joinRoom', code: codigo });
  for (let i = 1; i < 4; i++) {
    const sala = await clientes[i].esperar('roomState', 5000);
    assert.equal(sala.room.code, codigo);
  }

  clientes[0].enviar({ type: 'startRoom' });
  const votaciones = [];
  for (const cliente of clientes) {
    const mensaje = await cliente.esperar('gameState', 5000);
    assert.equal(mensaje.state.phase, 'voting');
    votaciones.push(mensaje);
    cliente.enviar({ type: 'voteTribilin', vote: 2 });
  }
  const estados = [];
  for (const cliente of clientes) {
    const mensaje = await cliente.esperarFase('playing', 5000);
    estados.push(mensaje.state);
  }
  assert.ok(estados.every((e) => e.ownHand.length === 3));

  const extra = new Cliente(usuarios[0].token);
  await extra.abrir();
  await extra.esperar('hello');
  extra.enviar({ type: 'joinRoom', code: 'NOEXIS' });
  const error = await extra.esperar('error', 5000);
  assert.match(error.message, /no existe|comenzó|sala/i);
  extra.cerrar();
  for (const c of clientes) c.cerrar();
  await new Promise((r) => setTimeout(r, 100));
});

async function jugarHastaTerminar(cliente, timeout = 120000) {
  const inicio = Date.now();
  while (Date.now() - inicio < timeout) {
    const mensaje = await cliente.esperar('gameState', timeout);
    const estado = mensaje.state;
    if (!estado) continue;
    if (estado.phase === 'finished') return mensaje;
    if (estado.phase === 'playing' && mensaje.room &&
        mensaje.room.yourSeat === estado.turnSeat &&
        estado.ownHand && estado.ownHand.length > 0) {
      cliente.enviar({ type: 'playCard', cardId: estado.ownHand[0] });
    }
  }
  throw new Error('La partida no terminó a tiempo.');
}

test('partida completa: se guarda en historial y ranking persistente', async () => {
  const sufijo = Date.now().toString().slice(-6);
  const usuarios = [];
  for (let i = 0; i < 4; i++) usuarios.push(await registrar('Hist' + sufijo + i));

  const clientes = usuarios.map((u) => new Cliente(u.token));
  await Promise.all(clientes.map((c) => c.abrir()));
  await Promise.all(clientes.map((c) => c.esperar('hello')));

  for (const cliente of clientes) cliente.enviar({ type: 'quickMatch' });

  for (const cliente of clientes) {
    const mensaje = await cliente.esperar('gameState', 8000);
    assert.equal(mensaje.state.phase, 'voting');
    cliente.enviar({ type: 'voteTribilin', vote: 2 });
  }

  const finales = await Promise.all(clientes.map((c) => jugarHastaTerminar(c)));
  const final = finales[0];
  const asientos = finales.map((f) => f.room.yourSeat);
  assert.equal(final.state.phase, 'finished');
  assert.ok(final.state.winnerTeam === 0 || final.state.winnerTeam === 1);
  const codigo = final.room.code;
  await new Promise((r) => setTimeout(r, 100));

  const historialResp = await fetch(BASE + '/api/history', {
    headers: { Authorization: 'Bearer ' + usuarios[0].token }
  });
  assert.equal(historialResp.status, 200);
  const { history } = await historialResp.json();
  assert.equal(history.length, 1, JSON.stringify(history));
  assert.equal(history[0].roomCode, codigo);
  assert.equal(history[0].won, asientos[0] % 2 === final.state.winnerTeam);
  assert.ok(history[0].teammates.length > 0);
  assert.ok(history[0].rivals.length > 0);

  const rankingResp = await fetch(BASE + '/api/ranking?limit=50', {
    headers: { Authorization: 'Bearer ' + usuarios[0].token }
  });
  assert.equal(rankingResp.status, 200);
  const { ranking } = await rankingResp.json();
  for (let i = 0; i < usuarios.length; i++) {
    const fila = ranking.find((r) => r.username === usuarios[i].user.username);
    assert.ok(fila, 'Falta ' + usuarios[i].user.username);
    assert.equal(fila.games, 1);
    assert.equal(fila.wins, (asientos[i] % 2) === final.state.winnerTeam ? 1 : 0);
  }

  const sinSesion = await fetch(BASE + '/api/ranking');
  assert.equal(sinSesion.status, 401);

  const meResp = await fetch(BASE + '/api/me', {
    headers: { Authorization: 'Bearer ' + usuarios[0].token }
  });
  assert.equal(meResp.status, 200);
  const me = await meResp.json();
  assert.equal(me.stats.games, 1);
  assert.equal(me.stats.wins, asientos[0] % 2 === final.state.winnerTeam ? 1 : 0);

  for (const c of clientes) c.cerrar();
  await new Promise((r) => setTimeout(r, 100));
});

test('verificación de correo y recuperación de contraseña', async () => {
  const sufijo = Date.now().toString().slice(-6);
  const usuario = 'Seg' + sufijo;
  const email = usuario.toLowerCase() + '@example.com';

  const registro = await postJson('/api/register', { username: usuario, password: 'secreto123', email });
  assert.equal(registro.status, 201, JSON.stringify(registro.body));
  assert.equal(registro.body.user.email, email);
  assert.equal(registro.body.user.verified, false);
  assert.match(registro.body.verification.devCode, /^\d{6}$/);
  const token = registro.body.token;
  const codigo = registro.body.verification.devCode;

  const incorrecto = codigo === '000000' ? '000001' : '000000';
  const malCodigo = await postJson('/api/verify', { code: incorrecto }, token);
  assert.equal(malCodigo.status, 400);

  const verificado = await postJson('/api/verify', { code: codigo }, token);
  assert.equal(verificado.status, 200, JSON.stringify(verificado.body));
  assert.equal(verificado.body.user.verified, true);

  const me = await fetch(BASE + '/api/me', { headers: { Authorization: 'Bearer ' + token } });
  assert.equal(me.status, 200);
  assert.equal(me.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(me.headers.get('cache-control'), 'no-store');
  assert.equal(me.headers.get('access-control-allow-origin'), '*');
  assert.equal((await me.json()).user.verified, true);

  const duplicado = await postJson('/api/register', { username: 'Otro' + sufijo, password: 'secreto123', email });
  assert.equal(duplicado.status, 409);

  const solicitud = await postJson('/api/recovery/request', { identifier: email });
  assert.equal(solicitud.status, 200);
  assert.match(solicitud.body.devCode, /^\d{6}$/);

  const alias = await postJson('/api/recover', { identifier: email });
  assert.equal(alias.status, 200);
  assert.match(alias.body.devCode, /^\d{6}$/);
  const codigoRecuperacion = alias.body.devCode;
  const codigoIncorrecto = codigoRecuperacion === '999999' ? '999998' : '999999';

  const verifMal = await postJson('/api/recover/verify', { identifier: email, code: codigoIncorrecto });
  assert.equal(verifMal.status, 400);

  const verifOk = await postJson('/api/recover/verify', { identifier: email, code: codigoRecuperacion });
  assert.equal(verifOk.status, 200, JSON.stringify(verifOk.body));

  const resetMal = await postJson('/api/recovery/reset', {
    identifier: email,
    code: codigoIncorrecto,
    password: 'nuevaClave1'
  });
  assert.equal(resetMal.status, 400);

  const reset = await postJson('/api/recovery/reset', {
    identifier: email,
    code: codigoRecuperacion,
    password: 'nuevaClave1'
  });
  assert.equal(reset.status, 200, JSON.stringify(reset.body));

  const viejo = await postJson('/api/login', { username: usuario, password: 'secreto123' });
  assert.equal(viejo.status, 401);

  const nuevo = await postJson('/api/login', { username: usuario, password: 'nuevaClave1' });
  assert.equal(nuevo.status, 200);
  assert.equal(nuevo.body.user.verified, true);

  const sesionVieja = await fetch(BASE + '/api/me', { headers: { Authorization: 'Bearer ' + token } });
  assert.equal(sesionVieja.status, 401);
});

test('2FA TOTP, códigos de recuperación y auditoría de accesos', async () => {
  const sufijo = Date.now().toString().slice(-6);
  const usuario = 'Dos' + sufijo;
  const email = usuario.toLowerCase() + '@example.com';

  const registro = await postJson('/api/register', { username: usuario, password: 'secreto123', email });
  assert.equal(registro.status, 201);
  const token = registro.body.token;

  const setup = await postJson('/api/2fa/setup', {}, token);
  assert.equal(setup.status, 200);
  assert.match(setup.body.secret, /^[A-Z2-7]+$/);
  assert.match(setup.body.otpauth, /^otpauth:\/\/totp\//);
  assert.ok(setup.body.qr.startsWith('data:image/png;base64,'));

  const codigo = codigoTotp(setup.body.secret);
  const activado = await postJson('/api/2fa/enable', { code: codigo }, token);
  assert.equal(activado.status, 200, JSON.stringify(activado.body));
  assert.equal(activado.body.user.totpEnabled, true);
  assert.equal(activado.body.recoveryCodes.length, 8);

  const login1 = await postJson('/api/login', { username: usuario, password: 'secreto123' });
  assert.equal(login1.status, 200);
  assert.equal(login1.body.requires2fa, true);
  assert.ok(login1.body.challengeToken);

  const malo = codigo === '000000' ? '000001' : '000000';
  const mal2fa = await postJson('/api/login/2fa', { challengeToken: login1.body.challengeToken, code: malo });
  assert.equal(mal2fa.status, 401);

  const buen2fa = await postJson('/api/login/2fa', {
    challengeToken: login1.body.challengeToken,
    code: codigoTotp(setup.body.secret)
  });
  assert.equal(buen2fa.status, 200, JSON.stringify(buen2fa.body));
  assert.ok(buen2fa.body.token);
  assert.equal(buen2fa.body.user.totpEnabled, true);

  const login2 = await postJson('/api/login', { username: usuario, password: 'secreto123' });
  const recuperacion = await postJson('/api/login/2fa', {
    challengeToken: login2.body.challengeToken,
    code: activado.body.recoveryCodes[0]
  });
  assert.equal(recuperacion.status, 200);
  assert.ok(recuperacion.body.token);

  const login3 = await postJson('/api/login', { username: usuario, password: 'secreto123' });
  const repetido = await postJson('/api/login/2fa', {
    challengeToken: login3.body.challengeToken,
    code: activado.body.recoveryCodes[0]
  });
  assert.equal(repetido.status, 401);

  const desactivado = await postJson('/api/2fa/disable', { code: codigoTotp(setup.body.secret) }, buen2fa.body.token);
  assert.equal(desactivado.status, 200, JSON.stringify(desactivado.body));
  assert.equal(desactivado.body.user.totpEnabled, false);

  const sinToken = await fetch(BASE + '/api/admin/audit');
  assert.equal(sinToken.status, 401);

  const auditoria = await fetch(BASE + '/api/admin/audit?limit=200', { headers: { 'x-admin-token': 'test-admin' } });
  assert.equal(auditoria.status, 200);
  const { audit } = await auditoria.json();
  const eventos = new Set(audit.map((e) => e.event));
  assert.ok(eventos.has('2fa_enabled'));
  assert.ok(eventos.has('login_2fa_required'));
  assert.ok(eventos.has('login_2fa_fail'));
  assert.ok(eventos.has('login_recovery_code'));
  assert.ok(eventos.has('2fa_disabled'));
  assert.ok(eventos.has('login_ok'));

  const pagina = await fetch(BASE + '/admin/auditoria');
  assert.equal(pagina.status, 200);
  const html = await pagina.text();
  assert.match(html, /Auditoría/);
  assert.match(html, /CARGAR EVENTOS/);
});

test('limita intentos de autenticación por IP', async () => {
  let bloqueado = false;
  for (let i = 0; i < 60 && !bloqueado; i++) {
    const respuesta = await postJson('/api/login', { username: 'Rate' + i, password: 'incorrecta' });
    if (respuesta.status === 429) bloqueado = true;
  }
  assert.equal(bloqueado, true);
});
