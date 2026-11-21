import test from 'node:test';
import assert from 'node:assert/strict';
import { BaseDatos } from '../src/db.js';

function crearBase() {
  const db = new BaseDatos(':memory:');
  const ana = db.crearUsuario('Ana', 'secreto123');
  const beto = db.crearUsuario('Beto', 'secreto123');
  const caro = db.crearUsuario('Caro', 'secreto123');
  const dino = db.crearUsuario('Dino', 'secreto123');
  return { db, ana, beto, caro, dino };
}

function registrar(db, usuarios, { codigo = 'ABC123', winnerTeam = 0, scoreA = 24, scoreB = 18, startedAt = 1000, finishedAt = 61000 } = {}) {
  return db.registrarPartida({
    roomCode: codigo,
    roomType: 'quick',
    winnerTeam,
    scoreA,
    scoreB,
    hands: 3,
    startedAt,
    finishedAt,
    players: usuarios.map((u, seat) => ({
      userId: u.id,
      seat,
      name: u.username,
      team: seat % 2,
      won: seat % 2 === winnerTeam,
      teamScore: seat % 2 === 0 ? scoreA : scoreB,
      rivalScore: seat % 2 === 0 ? scoreB : scoreA
    }))
  });
}

test('ranking e historial persistente por partida', () => {
  const { db, ana, beto, caro, dino } = crearBase();
  const usuarios = [ana, beto, caro, dino];

  const id = registrar(db, usuarios);
  assert.ok(id > 0);

  const ranking = db.ranking(10);
  assert.equal(ranking.length, 4);
  const porNombre = Object.fromEntries(ranking.map((r) => [r.username, r]));
  assert.equal(porNombre.Ana.games, 1);
  assert.equal(porNombre.Ana.wins, 1);
  assert.equal(porNombre.Ana.losses, 0);
  assert.equal(porNombre.Ana.winRate, 100);
  assert.equal(porNombre.Ana.points, 24);
  assert.equal(porNombre.Beto.wins, 0);
  assert.equal(porNombre.Beto.losses, 1);
  assert.equal(porNombre.Beto.points, 18);

  const historial = db.historialUsuario(ana.id, 10);
  assert.equal(historial.length, 1);
  assert.equal(historial[0].roomCode, 'ABC123');
  assert.equal(historial[0].won, true);
  assert.equal(historial[0].teamScore, 24);
  assert.equal(historial[0].rivalScore, 18);
  assert.equal(historial[0].durationMs, 60000);
  assert.equal(historial[0].teammates, 'Caro');
  assert.equal(historial[0].rivals, 'Beto · Dino');
  assert.equal(db.historialUsuario(beto.id, 10)[0].won, false);

  registrar(db, usuarios, { codigo: 'XYZ789', winnerTeam: 1, scoreA: 20, scoreB: 24, startedAt: 100000, finishedAt: 160000 });

  const ranking2 = db.ranking(10);
  assert.equal(ranking2.length, 4);
  assert.ok(ranking2.every((r) => r.games === 2));
  assert.ok(ranking2.every((r) => r.wins === 1));
  assert.ok(ranking2.every((r) => r.winRate === 50));

  const historial2 = db.historialUsuario(ana.id, 10);
  assert.equal(historial2.length, 2);
  assert.equal(historial2[0].roomCode, 'XYZ789');
  assert.equal(historial2[0].won, false);
  assert.equal(historial2[1].roomCode, 'ABC123');

  assert.deepEqual(db.estadisticasUsuario(ana.id), {
    games: 2, wins: 1, losses: 1, winRate: 50, points: 44
  });

  db.cerrar();
});

test('el historial respeta el límite y no mezcla jugadores', () => {
  const { db, ana, beto, caro, dino } = crearBase();
  const usuarios = [ana, beto, caro, dino];
  for (let i = 0; i < 5; i++) {
    registrar(db, usuarios, { codigo: `M${i}`, startedAt: i * 1000, finishedAt: i * 1000 + 500 });
  }

  const top = db.ranking(2);
  assert.equal(top.length, 2);
  assert.ok(top.every((r) => r.games === 5));

  const historial = db.historialUsuario(ana.id, 3);
  assert.equal(historial.length, 3);
  assert.equal(historial[0].roomCode, 'M4');
  assert.equal(historial[2].roomCode, 'M2');

  db.cerrar();
});

test('correo, verificación y recuperación de contraseña', () => {
  const db = new BaseDatos(':memory:');
  const ana = db.crearUsuario('AnaMail', 'secreto123', 'Ana@Example.com');
  assert.equal(ana.email, 'Ana@Example.com');
  assert.equal(ana.verified, false);

  assert.throws(
    () => db.crearUsuario('Otra', 'secreto123', 'ana@example.com'),
    (error) => error.code === 'EMAIL_EXISTS'
  );

  const codigo = db.crearCodigo(ana.id, 'verify');
  assert.match(codigo.codigo, /^\d{6}$/);
  const incorrecto = codigo.codigo === '000000' ? '000001' : '000000';
  assert.equal(db.consumirCodigo(ana.id, 'verify', incorrecto).ok, false);
  assert.equal(db.consumirCodigo(ana.id, 'verify', codigo.codigo).ok, true);
  assert.equal(db.consumirCodigo(ana.id, 'verify', codigo.codigo).ok, false);

  const otro = db.crearCodigo(ana.id, 'verify');
  const otroIncorrecto = otro.codigo === '999999' ? '999998' : '999999';
  for (let i = 0; i < 5; i++) db.consumirCodigo(ana.id, 'verify', otroIncorrecto);
  assert.equal(db.consumirCodigo(ana.id, 'verify', otro.codigo).ok, false);

  const verificado = db.marcarVerificado(ana.id);
  assert.equal(verificado.verified, true);
  assert.equal(db.usuarioPorIdentificador('anamail').verified, true);
  assert.equal(db.usuarioPorIdentificador('ana@example.com').verified, true);

  const token = db.crearSesion(ana.id);
  assert.ok(db.usuarioPorToken(token));
  const recuperacion = db.crearCodigo(ana.id, 'reset');
  assert.equal(db.consumirCodigo(ana.id, 'reset', recuperacion.codigo).ok, true);
  db.actualizarPassword(ana.id, 'nuevaClave1');
  assert.equal(db.usuarioPorToken(token), null);
  assert.equal(db.verificarCredenciales('AnaMail', 'secreto123'), null);
  assert.ok(db.verificarCredenciales('AnaMail', 'nuevaClave1'));

  db.cerrar();
});

test('2FA, códigos de recuperación, desafíos y auditoría', () => {
  const db = new BaseDatos(':memory:');
  const ana = db.crearUsuario('AnaTotp', 'secreto123', 'ana@totp.com');
  assert.equal(db.datosTotp(ana.id).enabled, false);

  const secreto = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
  db.guardarTotpPendiente(ana.id, secreto);
  assert.equal(db.datosTotp(ana.id).pending, secreto);
  db.activarTotp(ana.id, secreto);
  assert.equal(db.datosTotp(ana.id).enabled, true);
  assert.equal(db.usuarioPorId(ana.id).totpEnabled, true);

  const codigos = db.crearCodigosRecuperacion(ana.id);
  assert.equal(codigos.length, 8);
  assert.match(codigos[0], /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  assert.equal(db.consumirCodigoRecuperacion(ana.id, codigos[0]), true);
  assert.equal(db.consumirCodigoRecuperacion(ana.id, codigos[0]), false);
  assert.equal(db.consumirCodigoRecuperacion(ana.id, 'AAAA-AAAA'), false);

  const desafio = db.crearDesafioLogin(ana.id);
  assert.ok(db.desafioLogin(desafio));
  for (let i = 0; i < 5; i++) db.fallarDesafio(desafio);
  assert.equal(db.desafioLogin(desafio), null);

  db.registrarAuditoria({ event: 'test_event', severity: 'warn', userId: ana.id, username: 'AnaTotp', detail: { motivo: 'test' } });
  const auditoria = db.listarAuditoria(10);
  assert.equal(auditoria[0].event, 'test_event');
  assert.equal(auditoria[0].detail.motivo, 'test');

  db.actualizarUltimoAcceso(ana.id, '127.0.0.1');
  assert.equal(db.datosAcceso(ana.id).lastIp, '127.0.0.1');

  db.desactivarTotp(ana.id);
  assert.equal(db.datosTotp(ana.id).enabled, false);
  assert.equal(db.consumirCodigoRecuperacion(ana.id, codigos[1]), false);

  db.cerrar();
});
