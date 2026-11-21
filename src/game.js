export const PALOS = ['Oro', 'Copa', 'Espada', 'Basto'];
export const VALORES = [1, 2, 3, 4, 5, 6, 7, 10, 11, 12];

export function equipoDeAsiento(asiento) {
  return asiento % 2;
}

export function puntosCaida(valor) {
  if (valor === 10) return 2;
  if (valor === 11) return 3;
  if (valor === 12) return 4;
  return 1;
}

export function siguienteValor(valor) {
  if (valor === 7) return 10;
  if (valor === 12) return -1;
  return valor + 1;
}

export function sonConsecutivos(a, b) {
  if ((a === 7 && b === 10) || (b === 7 && a === 10)) return true;
  return Math.abs(a - b) === 1;
}

export function evaluarCantoDesdeValores(valores, tribilinMata, distanciaMano = 0) {
  const v = valores.slice().sort((a, b) => a - b);
  if (v.length < 3) return null;

  if (v[0] === 1 && v[1] === 11 && v[2] === 12) {
    return { tipo: 'Registro', rango: 5, puntos: 8, valorAlto: 12, fueVisto: true, distanciaMano };
  }
  if (v[0] === v[1] && v[1] === v[2]) {
    return {
      tipo: 'Tribilín',
      rango: tribilinMata ? 6 : 2,
      puntos: tribilinMata ? 24 : 5,
      valorAlto: v[0],
      fueVisto: true,
      distanciaMano
    };
  }
  if (sonConsecutivos(v[0], v[1]) && sonConsecutivos(v[1], v[2])) {
    return { tipo: 'Patrulla', rango: 3, puntos: 6, valorAlto: v[2], fueVisto: true, distanciaMano };
  }
  if (v[0] === v[1] && (sonConsecutivos(v[0], v[2]) || sonConsecutivos(v[2], v[0]))) {
    return { tipo: 'Vigía', rango: 4, puntos: 7, valorAlto: v[2], fueVisto: true, distanciaMano };
  }
  if (v[1] === v[2] && (sonConsecutivos(v[1], v[0]) || sonConsecutivos(v[0], v[1]))) {
    return { tipo: 'Vigía', rango: 4, puntos: 7, valorAlto: v[2], fueVisto: true, distanciaMano };
  }
  if (v[0] === v[1] || v[1] === v[2] || v[0] === v[2]) {
    const par = v[0] === v[1] ? v[0] : (v[1] === v[2] ? v[1] : v[0]);
    const puntos = par === 10 ? 2 : (par === 11 ? 3 : (par === 12 ? 4 : 1));
    return { tipo: 'Ronda', rango: 1, puntos, valorAlto: par, fueVisto: false, distanciaMano };
  }
  return null;
}

export function compararCantos(a, b) {
  if (a.rango !== b.rango) return b.rango - a.rango;
  if (a.valorAlto !== b.valorAlto) return b.valorAlto - a.valorAlto;
  return a.distanciaMano - b.distanciaMano;
}

function crearMazo() {
  const mazo = [];
  for (const palo of PALOS) {
    for (const valor of VALORES) {
      mazo.push({ id: `${palo}_${valor}`, palo, valor });
    }
  }
  return mazo;
}

function barajar(mazo) {
  for (let i = mazo.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [mazo[i], mazo[j]] = [mazo[j], mazo[i]];
  }
  return mazo;
}

/**
 * Motor autoritativo de Caída Online.
 *
 * Incluye votación del Tribilín, sorteo de mano, cantos por mano
 * (Ronda, Vigía, Patrulla, Tribilín y Registro), capturas consecutivas,
 * caída, mesa limpia, mayoría de cartas y carrera a 24.
 */
export class PartidaCaida {
  constructor(nombres, opciones = {}) {
    this.nombres = nombres.slice(0, 4);
    this.objetivo = opciones.objetivo ?? 24;
    this.scores = [0, 0];
    this.phase = 'voting';
    this.votos = [null, null, null, null];
    this.tribilinMata = null;
    this.dealer = null;
    this.winnerTeam = null;
    this.handNumber = 0;
    this.dealsRealizados = 0;
    this.lastEvent = 'Votación: ¿Tribilín mata partida?';
    this.sorteo = null;
    this.eventSeq = 0;
    this.startedAt = Date.now();
    this.cantos = [];
    this.cantoHistorial = [];
    this.cantoEventId = 0;
    this.deck = [];
    this.hands = [[], [], [], []];
    this.table = [];
    this.captured = [0, 0];
    this.turn = 0;
    this.lastUncaptured = null;
    this.lastUncapturedOwner = null;
    this.lastCapturer = null;
  }

  votar(asiento, voto) {
    if (this.phase !== 'voting') return { ok: false, error: 'La votación ya terminó.' };
    if (!Number.isInteger(asiento) || asiento < 0 || asiento > 3) return { ok: false, error: 'Asiento inválido.' };
    if (voto !== 1 && voto !== 2) return { ok: false, error: 'Voto inválido.' };
    this.votos[asiento] = voto;
    this.eventSeq += 1;

    if (this.votos.every((v) => v !== null)) {
      const si = this.votos.filter((v) => v === 1).length;
      const no = this.votos.filter((v) => v === 2).length;
      this.tribilinMata = si === no ? Math.random() > 0.5 : si > no;
      this.resolverSorteo();
      return { ok: true, resuelto: true };
    }

    return { ok: true, resuelto: false };
  }

  resolverSorteo() {
    const mazo = barajar(crearMazo());
    let participantes = [0, 1, 2, 3];
    let ronda = 0;
    let detalle = '';

    while (participantes.length > 1) {
      ronda += 1;
      const tiradas = participantes.map((seat) => ({ seat, carta: mazo.pop() }));
      const max = Math.max(...tiradas.map((t) => t.carta.valor));
      participantes = tiradas.filter((t) => t.carta.valor === max).map((t) => t.seat);
      detalle = tiradas.map((t) => `${this.nombres[t.seat]}: ${t.carta.valor}`).join(' · ');
      if (ronda > 20) break;
    }

    this.dealer = participantes[0] ?? 0;
    this.sorteo = `Mano: ${this.nombres[this.dealer]} (${detalle})`;
    this.phase = 'playing';
    this.iniciarMano();
  }

  iniciarMano() {
    this.handNumber += 1;
    this.deck = barajar(crearMazo());
    this.table = [];
    this.hands = [[], [], [], []];
    this.captured = [0, 0];
    this.dealsRealizados = 0;
    this.lastUncaptured = null;
    this.lastUncapturedOwner = null;
    this.lastCapturer = null;
    this.cantos = [];

    this.repartirMesaInicial();
    this.repartirManos();
    this.dealsRealizados = 1;
    this.turn = (this.dealer + 1) % 4;
    this.lastEvent = `Mano ${this.handNumber} · ${this.sorteo}`;
    this.eventSeq += 1;
    this.evaluarCantos();
  }

  repartirMesaInicial() {
    let intentos = 0;
    while (this.table.length < 4 && this.deck.length > 0 && intentos < 500) {
      const carta = this.deck.pop();
      if (this.table.some((c) => c.valor === carta.valor)) {
        const pos = Math.floor(Math.random() * (this.deck.length + 1));
        this.deck.splice(pos, 0, carta);
        intentos += 1;
      } else {
        this.table.push(carta);
      }
    }
  }

  repartirManos() {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 3; j++) {
        const carta = this.deck.pop();
        if (carta) this.hands[i].push(carta);
      }
    }
  }

  evaluarCantos() {
    const indiceMano = (this.dealer + 1) % 4;
    const candidatos = [];

    for (let seat = 0; seat < 4; seat++) {
      const mano = this.hands[seat];
      if (mano.length < 3) continue;
      const distanciaMano = (seat - indiceMano + 4) % 4;
      const canto = evaluarCantoDesdeValores(mano.map((c) => c.valor), this.tribilinMata === true, distanciaMano);
      if (canto) {
        canto.seat = seat;
        canto.cartasJugadas = 0;
        canto.orden = distanciaMano;
        candidatos.push(canto);
      }
    }

    // Un único canto por jugador, anunciado en orden de turno desde el Mano.
    this.cantos = candidatos.sort((a, b) => a.distanciaMano - b.distanciaMano);

    this.eventSeq += 1;
    if (this.cantos.length > 0) {
      this.lastEvent = 'Cantos: ' + this.cantos
        .map((c) => `${this.nombres[c.seat]} ${c.tipo}${c.tipo === 'Ronda' ? ' (oculta)' : ''}`)
        .join(' · ');
    }

    for (const c of this.cantos) {
      const yaRegistrado = this.cantoHistorial.some((e) => (
        e.handNumber === this.handNumber && e.seat === c.seat && e.tipo === c.tipo && e.estado === 'cantado'
      ));
      if (yaRegistrado) continue;

      const oculta = c.tipo === 'Ronda' && !c.fueVisto;
      this.registrarCanto(c.seat, c.tipo, c.puntos, 'cantado', {
        oculto: oculta,
        texto: oculta
          ? `${this.nombres[c.seat]} tiene una Ronda oculta`
          : `${this.nombres[c.seat]} canta ${c.tipo}`
      });
    }

    this.resolverPaViajeInmediato();
  }

  registrarCanto(seat, tipo, puntos, estado, opciones = {}) {
    this.cantoEventId += 1;
    const entrada = {
      id: this.cantoEventId,
      handNumber: this.handNumber,
      dealNumber: this.dealsRealizados,
      seat,
      tipo,
      puntos,
      estado,
      oculto: !!opciones.oculto,
      texto: opciones.texto ?? ''
    };
    this.cantoHistorial.push(entrada);
    if (this.cantoHistorial.length > 30) this.cantoHistorial.shift();
    return entrada;
  }

  limpiarHistorialCanto(seat, tipo) {
    this.cantoHistorial = this.cantoHistorial.filter((e) => !(
      e.handNumber === this.handNumber && e.seat === seat && e.tipo === tipo &&
      (e.estado === 'cantado' || e.estado === 'visto')
    ));
  }

  resolverPaViajeInmediato() {
    if (this.phase !== 'playing' || this.cantos.length === 0) return;
    const validos = this.cantos.filter((c) => c.tipo !== 'Ronda' || c.fueVisto);
    if (!validos.length) return;
    const ordenados = validos.slice().sort(compararCantos);
    const mejor = ordenados[0];
    const equipo = equipoDeAsiento(mejor.seat);
    if (this.scores[equipo] + mejor.puntos < this.objetivo) return;

    const enemigos = ordenados.filter((c) => equipoDeAsiento(c.seat) !== equipo);
    const mejorEnemigo = enemigos.length ? enemigos[0] : null;
    const ganaMejor = !mejorEnemigo || compararCantos(mejor, mejorEnemigo) < 0;
    if (!ganaMejor) return;

    mejor.cobrado = true;
    this.registrarCanto(mejor.seat, mejor.tipo, mejor.puntos, 'cobrado', {
      texto: `¡${this.nombres[mejor.seat]} canta ${mejor.tipo} pa' viaje! +${mejor.puntos}`
    });
    this.sumarPuntos(equipo, mejor.puntos);
    this.lastEvent = `¡${this.nombres[mejor.seat]} canta ${mejor.tipo} pa' viaje! +${mejor.puntos}`;
    this.eventSeq += 1;
  }

  jugar(asiento, cartaId) {
    if (this.phase !== 'playing') return { ok: false, error: 'La partida no está en juego.' };
    if (!Number.isInteger(asiento) || asiento < 0 || asiento > 3) return { ok: false, error: 'Asiento inválido.' };
    if (asiento !== this.turn) return { ok: false, error: 'No es tu turno.' };

    const indice = this.hands[asiento].findIndex((c) => c.id === cartaId);
    if (indice < 0) return { ok: false, error: 'Esa carta no está en tu mano.' };

    const carta = this.hands[asiento].splice(indice, 1)[0];
    const equipo = equipoDeAsiento(asiento);
    const capturadas = [];
    let caida = 0;
    let mesaLimpia = 0;

    const ronda = this.cantos.find((c) => c.seat === asiento && c.tipo === 'Ronda' && !c.fueVisto);
    if (ronda && carta.valor === ronda.valorAlto) {
      ronda.cartasJugadas += 1;
      if (ronda.cartasJugadas >= 2) {
        ronda.fueVisto = true;
        this.limpiarHistorialCanto(asiento, 'Ronda');
        this.registrarCanto(asiento, 'Ronda', ronda.puntos, 'visto', {
          texto: `¡${this.nombres[asiento]} mostró su Ronda Vista!`
        });
        this.lastEvent = `¡Ronda Vista de ${this.nombres[asiento]}!`;
      }
    }

    const coincidencia = this.table.find((c) => c.valor === carta.valor);
    if (coincidencia) {
      capturadas.push(coincidencia);
      let siguiente = siguienteValor(carta.valor);
      while (siguiente !== -1) {
        const pos = this.table.findIndex((c) => c.valor === siguiente);
        if (pos < 0) break;
        capturadas.push(this.table.splice(pos, 1)[0]);
        siguiente = siguienteValor(siguiente);
      }
      const posMatch = this.table.indexOf(coincidencia);
      if (posMatch >= 0) this.table.splice(posMatch, 1);

      this.captured[equipo] += capturadas.length + 1;
      this.lastCapturer = asiento;

      if (this.lastUncaptured && this.lastUncaptured.valor === carta.valor) {
        caida = puntosCaida(carta.valor);
        this.sumarPuntos(equipo, caida);
      }
      this.lastUncaptured = null;
      this.lastUncapturedOwner = null;

      if (this.table.length === 0 && this.dealsRealizados < 3) {
        mesaLimpia = 4;
        this.sumarPuntos(equipo, mesaLimpia);
      }

      const extra = [
        caida ? `¡CAÍDA! +${caida}` : '',
        mesaLimpia ? `¡MESA LIMPIA! +${mesaLimpia}` : ''
      ].filter(Boolean).join(' · ');
      this.lastEvent = `${this.nombres[asiento]} jugó ${carta.id} y capturó ${capturadas.length + 1}${extra ? ' · ' + extra : ''}.`;
    } else {
      this.table.push(carta);
      this.lastUncaptured = carta;
      this.lastUncapturedOwner = asiento;
      this.lastEvent = `${this.nombres[asiento]} jugó ${carta.id}.`;
    }

    this.eventSeq += 1;
    this.turn = (this.turn + 1) % 4;

    if (this.phase === 'playing' && this.hands.every((h) => h.length === 0)) {
      this.terminarDeal();
    }

    return { ok: true, caida, mesaLimpia, capturadas: capturadas.map((c) => c.id) };
  }

  terminarDeal() {
    if (this.dealsRealizados < 3) {
      this.dealsRealizados += 1;
      this.repartirManos();
      this.lastEvent += ` Se reparte la mano ${this.dealsRealizados}.`;
      this.eventSeq += 1;
      return;
    }

    this.resolverCantosMano();
    if (this.phase !== 'playing') return;
    this.finalizarMano();
  }

  resolverCantosMano() {
    for (const c of this.cantos) {
      if (c.tipo === 'Ronda' && !c.fueVisto && !c.cobrado) {
        this.limpiarHistorialCanto(c.seat, c.tipo);
        this.registrarCanto(c.seat, c.tipo, 0, 'anulado', {
          oculto: true,
          texto: 'Tu Ronda no se vio y no cobró'
        });
      }
    }

    const validos = this.cantos.filter((c) => (c.tipo !== 'Ronda' || c.fueVisto) && !c.cobrado);
    if (!validos.length) {
      this.cantos = [];
      return;
    }

    const ordenados = validos.slice().sort(compararCantos);
    const ganador = ordenados[0];

    for (const c of ordenados) {
      this.limpiarHistorialCanto(c.seat, c.tipo);
      if (c === ganador) {
        this.registrarCanto(c.seat, c.tipo, c.puntos, 'cobrado', {
          texto: `¡${this.nombres[c.seat]} cobró ${c.tipo}! +${c.puntos}`
        });
      } else {
        this.registrarCanto(c.seat, c.tipo, 0, 'anulado', {
          texto: `${this.nombres[c.seat]} · ${c.tipo} no valió`
        });
      }
    }

    const equipo = equipoDeAsiento(ganador.seat);
    this.sumarPuntos(equipo, ganador.puntos);
    this.lastEvent = `Canto: ${this.nombres[ganador.seat]} ${ganador.tipo} +${ganador.puntos}.`;
    this.eventSeq += 1;
    this.cantos = [];
  }

  sumarPuntos(equipo, puntos) {
    if (this.phase !== 'playing' || puntos <= 0) return;
    this.scores[equipo] += puntos;
    if (this.scores[equipo] >= this.objetivo) {
      this.phase = 'finished';
      this.winnerTeam = equipo;
      this.lastEvent += ` ¡Equipo ${equipo === 0 ? 'A' : 'B'} llega a ${this.objetivo}!`;
      this.eventSeq += 1;
    }
  }

  finalizarMano() {
    if (this.table.length > 0 && this.lastCapturer !== null) {
      this.captured[equipoDeAsiento(this.lastCapturer)] += this.table.length;
      this.table = [];
    }

    for (let equipo = 0; equipo < 2; equipo++) {
      if (this.captured[equipo] > 20) {
        this.sumarPuntos(equipo, this.captured[equipo] - 20);
      }
    }

    if (this.phase === 'playing') {
      this.dealer = (this.dealer + 1) % 4;
      this.iniciarMano();
    }
  }

  jugadaAutomatica(asiento) {
    if (this.phase !== 'playing' || asiento !== this.turn) return { ok: false };
    const mano = this.hands[asiento];
    if (!mano.length) return { ok: false };
    const orden = mano.slice().sort((a, b) => a.valor - b.valor);
    return this.jugar(asiento, orden[0].id);
  }

  get turnSeat() {
    return this.turn;
  }

  get votosFaltantes() {
    return this.votos.filter((v) => v === null).length;
  }

  estadoPara(asiento) {
    const cantosVisibles = this.cantos
      .filter((c) => c.tipo !== 'Ronda' || c.fueVisto || c.seat === asiento)
      .map((c) => ({
        seat: c.seat,
        tipo: c.tipo,
        rango: c.rango,
        puntos: c.puntos,
        valorAlto: c.valorAlto,
        fueVisto: c.fueVisto,
        cartasJugadas: c.cartasJugadas ?? 0,
        cobrado: !!c.cobrado
      }));

    const cantoHistorial = this.cantoHistorial
      .filter((e) => !e.oculto || e.seat === asiento)
      .slice(-14)
      .map((e) => ({
        id: e.id,
        handNumber: e.handNumber,
        dealNumber: e.dealNumber,
        seat: e.seat,
        tipo: e.tipo,
        puntos: e.puntos,
        estado: e.estado,
        texto: e.texto
      }));

    return {
      phase: this.phase,
      handNumber: this.handNumber,
      dealNumber: this.dealsRealizados,
      turnSeat: this.turn,
      dealerSeat: this.dealer ?? -1,
      scores: this.scores,
      captured: this.captured,
      table: this.table.map((c) => c.id),
      ownHand: this.hands[asiento] ? this.hands[asiento].map((c) => c.id) : [],
      handCounts: this.hands.map((h) => h.length),
      lastEvent: this.lastEvent,
      winnerTeam: this.winnerTeam,
      objective: this.objetivo,
      deckRemaining: this.deck.length,
      dealsRealizados: this.dealsRealizados,
      tribilinMata: this.tribilinMata,
      votosEmitidos: this.votos.filter((v) => v !== null).length,
      tuVoto: this.votos[asiento] ?? 0,
      sorteo: this.sorteo,
      cantos: cantosVisibles,
      cantoHistorial
    };
  }
}
