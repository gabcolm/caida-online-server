import test from 'node:test';
import assert from 'node:assert/strict';
import { PartidaCaida, evaluarCantoDesdeValores, puntosCaida, siguienteValor } from '../src/game.js';
import { BaseDatos, validarCredenciales } from '../src/db.js';
import { reiniciarBaseDePruebas, urlPruebas } from './helpers/test-db.js';

function iniciarJuego(nombres = ['A', 'B', 'C', 'D']) {
  const juego = new PartidaCaida(nombres);
  // Votar "no mata" evita que un Tribilín aleatorio cierre la partida al repartir.
  for (let i = 0; i < 4; i++) juego.votar(i, 2);
  return juego;
}

test('reglas auxiliares de la caída', () => {
  assert.equal(puntosCaida(1), 1);
  assert.equal(puntosCaida(10), 2);
  assert.equal(puntosCaida(11), 3);
  assert.equal(puntosCaida(12), 4);
  assert.equal(siguienteValor(7), 10);
  assert.equal(siguienteValor(12), -1);
  assert.equal(siguienteValor(4), 5);
});

test('votación del Tribilín y sorteo de mano', () => {
  const juego = new PartidaCaida(['A', 'B', 'C', 'D']);
  assert.equal(juego.phase, 'voting');
  assert.equal(juego.estadoPara(0).votosEmitidos, 0);
  juego.votar(0, 1);
  juego.votar(1, 1);
  assert.equal(juego.phase, 'voting');
  assert.equal(juego.estadoPara(0).votosEmitidos, 2);
  juego.votar(2, 2);
  juego.votar(3, 2);
  assert.equal(juego.phase, 'playing');
  assert.equal(typeof juego.tribilinMata, 'boolean');
  assert.ok(juego.dealer >= 0 && juego.dealer <= 3);
  assert.ok(juego.sorteo.includes('Mano:'));
  assert.equal(juego.estadoPara(0).ownHand.length, 3);
});

test('detección de los cinco cantos', () => {
  assert.equal(evaluarCantoDesdeValores([1, 11, 12], true).tipo, 'Registro');
  assert.equal(evaluarCantoDesdeValores([5, 5, 5], true).tipo, 'Tribilín');
  assert.equal(evaluarCantoDesdeValores([5, 5, 5], true).puntos, 24);
  assert.equal(evaluarCantoDesdeValores([5, 5, 5], false).puntos, 5);
  assert.equal(evaluarCantoDesdeValores([1, 2, 3], true).tipo, 'Patrulla');
  assert.equal(evaluarCantoDesdeValores([3, 3, 4], true).tipo, 'Vigía');
  const ronda = evaluarCantoDesdeValores([10, 10, 2], true);
  assert.equal(ronda.tipo, 'Ronda');
  assert.equal(ronda.puntos, 2);
  assert.equal(ronda.fueVisto, false);
  assert.equal(evaluarCantoDesdeValores([1, 3, 8], true), null);
});

test('el canto ganador suma puntos y la Ronda oculta no suma hasta verse', () => {
  const carta = (valor, palo = 'Oro') => ({ id: `${palo}_${valor}`, palo, valor });
  const juego = iniciarJuego();
  juego.hands[0] = [carta(1), carta(11), carta(12)];
  juego.hands[1] = [carta(2), carta(4), carta(8)];
  juego.hands[2] = [carta(3), carta(5), carta(9)];
  juego.hands[3] = [carta(6), carta(7), carta(10)];
  juego.evaluarCantos();
  assert.ok(juego.cantos.some((c) => c.seat === 0 && c.tipo === 'Registro'));
  const antes = juego.scores[0];
  juego.resolverCantosMano();
  assert.equal(juego.scores[0], antes + 8);

  const ronda = new PartidaCaida(['A', 'B', 'C', 'D']);
  for (let i = 0; i < 4; i++) ronda.votar(i, 2);
  ronda.hands[0] = [carta(10), carta(10, 'Copa'), carta(2)];
  ronda.hands[1] = [carta(3), carta(4), carta(8)];
  ronda.hands[2] = [carta(5), carta(6), carta(9)];
  ronda.hands[3] = [carta(7), carta(11), carta(12)];
  ronda.evaluarCantos();
  assert.equal(ronda.cantos.some((c) => c.tipo === 'Ronda' && c.fueVisto), false);
});

test('los cantos se cobran una sola vez al final de la mano, no en cada reparto', () => {
  const juego = iniciarJuego();
  juego.scores = [0, 0];
  juego.cantos = [{
    seat: 0, tipo: 'Registro', rango: 5, puntos: 8, valorAlto: 12, fueVisto: true, distanciaMano: 0
  }];
  juego.hands = [[], [], [], []];

  juego.terminarDeal();
  assert.equal(juego.dealsRealizados, 2);
  assert.equal(juego.cantos.length, 1);
  assert.deepEqual(juego.scores, [0, 0]);

  juego.hands = [[], [], [], []];
  juego.terminarDeal();
  assert.equal(juego.dealsRealizados, 3);
  assert.deepEqual(juego.scores, [0, 0]);

  juego.hands = [[], [], [], []];
  juego.terminarDeal();
  assert.deepEqual(juego.scores, [8, 0]);
});

test('historial de cantos y privacidad de la Ronda oculta', () => {
  const carta = (valor, palo = 'Oro') => ({ id: `${palo}_${valor}`, palo, valor });
  const juego = iniciarJuego();
  juego.cantoHistorial = [];
  juego.cantoEventId = 0;
  juego.hands[0] = [carta(10), carta(10, 'Copa'), carta(2)];
  juego.hands[1] = [carta(3), carta(4), carta(8)];
  juego.hands[2] = [carta(5), carta(6), carta(9)];
  juego.hands[3] = [carta(7), carta(11), carta(12)];
  juego.evaluarCantos();

  const propio = juego.estadoPara(0);
  assert.ok(propio.cantos.some((c) => c.seat === 0 && c.tipo === 'Ronda' && !c.fueVisto));
  assert.ok(propio.cantoHistorial.some((e) => e.seat === 0 && e.tipo === 'Ronda' && e.estado === 'cantado'));

  const ajeno = juego.estadoPara(1);
  assert.equal(ajeno.cantos.some((c) => c.seat === 0), false);
  assert.equal(ajeno.cantoHistorial.some((e) => e.seat === 0 && e.tipo === 'Ronda'), false);

  juego.table = [];
  juego.turn = 0;
  assert.equal(juego.jugar(0, 'Oro_10').ok, true);
  juego.turn = 0;
  assert.equal(juego.jugar(0, 'Copa_10').ok, true);

  assert.ok(juego.estadoPara(1).cantos.some((c) => c.seat === 0 && c.tipo === 'Ronda' && c.fueVisto));

  const antes = juego.scores[0];
  juego.resolverCantosMano();
  assert.equal(juego.scores[0], antes + 2);
  assert.ok(juego.estadoPara(0).cantoHistorial.some((e) => e.seat === 0 && e.estado === 'cobrado' && e.puntos === 2));
  assert.ok(juego.estadoPara(1).cantoHistorial.some((e) => e.seat === 0 && e.estado === 'cobrado' && e.puntos === 2));
  assert.equal(juego.estadoPara(1).cantoHistorial.filter((e) => e.seat === 0 && e.tipo === 'Ronda').length, 1);
});

test('reparto inicial: 4 en mesa, 3 por jugador y 24 en mazo', () => {
  const juego = iniciarJuego();
  const estado = juego.estadoPara(0);
  assert.equal(estado.table.length, 4);
  assert.deepEqual(estado.handCounts, [3, 3, 3, 3]);
  assert.equal(estado.ownHand.length, 3);
  assert.equal(estado.deckRemaining, 24);
  assert.equal(new Set(estado.table).size, 4);
});

test('solo el jugador en turno puede jugar y la carta debe estar en su mano', () => {
  const juego = iniciarJuego();
  const turno = juego.turnSeat;
  const otro = (turno + 1) % 4;
  const carta = juego.estadoPara(turno).ownHand[0];
  assert.equal(juego.jugar(otro, carta).ok, false);
  assert.equal(juego.jugar(turno, 'Oro_99').ok, false);
  assert.equal(juego.jugar(turno, carta).ok, true);
});

test('la partida termina con un ganador y no acepta jugadas después', () => {
  const juego = iniciarJuego();
  let pasos = 0;
  while (juego.phase === 'playing' && pasos < 20000) {
    const turno = juego.turnSeat;
    const mano = juego.estadoPara(turno).ownHand;
    if (mano.length === 0) {
      const auto = juego.jugadaAutomatica(turno);
      assert.equal(auto.ok, false);
      break;
    }
    const resultado = juego.jugar(turno, mano[0]);
    assert.equal(resultado.ok, true);
    pasos += 1;
  }
  assert.equal(juego.phase, 'finished');
  assert.ok(juego.winnerTeam === 0 || juego.winnerTeam === 1);
  assert.ok(juego.scores[juego.winnerTeam] >= 24);
  assert.equal(juego.jugar(0, 'Oro_1').ok, false);
});

test('registro, login y validación de credenciales', async () => {
  await reiniciarBaseDePruebas();
  const db = new BaseDatos(urlPruebas());
  await db.iniciar();

  try {
    assert.equal(validarCredenciales('ab', '123456'), 'El alias debe tener entre 3 y 18 caracteres.');
    assert.equal(validarCredenciales('jugador', '123'), 'La contraseña debe tener al menos 6 caracteres.');
    const user = await db.crearUsuario('Gabriel', 'secreto123');
    assert.equal(user.username, 'Gabriel');
    assert.equal(user.coins, 2000);
    assert.equal((await db.verificarCredenciales('gabriel', 'secreto123'))?.id, user.id);
    assert.equal(await db.verificarCredenciales('Gabriel', 'incorrecta'), null);
    await assert.rejects(() => db.crearUsuario('GABRIEL', 'otra1234'), /registrado/i);
    const token = await db.crearSesion(user.id);
    assert.equal((await db.usuarioPorToken(token))?.username, 'Gabriel');
    await db.revocarSesion(token);
    assert.equal(await db.usuarioPorToken(token), null);
  } finally {
    await db.cerrar();
  }
});
