import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomInt, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { compararCodigo, generarCodigo, generarSalt, hashCodigo, normalizarEmail } from './security.js';

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export class BaseDatos {
  constructor(ruta) {
    if (ruta !== ':memory:') mkdirSync(dirname(ruta), { recursive: true });
    this.db = new DatabaseSync(ruta);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        username_key TEXT NOT NULL UNIQUE,
        salt TEXT NOT NULL,
        hash TEXT NOT NULL,
        coins INTEGER NOT NULL DEFAULT 2000,
        email TEXT,
        email_key TEXT,
        verified INTEGER NOT NULL DEFAULT 0,
        verified_at INTEGER,
        totp_secret TEXT,
        totp_pending TEXT,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        totp_enabled_at INTEGER,
        last_ip TEXT,
        last_login_at INTEGER,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS account_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        purpose TEXT NOT NULL,
        salt TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_account_codes_user ON account_codes(user_id, purpose, used_at);
      CREATE TABLE IF NOT EXISTS recovery_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        salt TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        used_at INTEGER,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id, used_at);
      CREATE TABLE IF NOT EXISTS login_challenges (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        event TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        user_id INTEGER,
        username TEXT,
        ip TEXT,
        user_agent TEXT,
        detail TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event, created_at DESC);
      CREATE TABLE IF NOT EXISTS matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_code TEXT NOT NULL,
        room_type TEXT NOT NULL,
        winner_team INTEGER NOT NULL,
        score_a INTEGER NOT NULL,
        score_b INTEGER NOT NULL,
        hands INTEGER NOT NULL,
        started_at INTEGER NOT NULL,
        finished_at INTEGER NOT NULL,
        duration_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS match_players (
        match_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        seat INTEGER NOT NULL,
        team INTEGER NOT NULL,
        name TEXT NOT NULL,
        won INTEGER NOT NULL,
        team_score INTEGER NOT NULL,
        rival_score INTEGER NOT NULL,
        PRIMARY KEY(match_id, user_id),
        FOREIGN KEY(match_id) REFERENCES matches(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_match_players_user ON match_players(user_id);
      CREATE INDEX IF NOT EXISTS idx_matches_finished ON matches(finished_at DESC);
    `);
    this.migrarEsquema();
  }

  migrarEsquema() {
    const columnas = new Set(this.db.prepare('PRAGMA table_info(users)').all().map((c) => c.name));
    // Bases anteriores: las cuentas existentes quedan verificadas para no bloquearlas.
    if (!columnas.has('email')) this.db.exec('ALTER TABLE users ADD COLUMN email TEXT');
    if (!columnas.has('email_key')) this.db.exec('ALTER TABLE users ADD COLUMN email_key TEXT');
    if (!columnas.has('verified')) this.db.exec('ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 1');
    if (!columnas.has('verified_at')) this.db.exec('ALTER TABLE users ADD COLUMN verified_at INTEGER');
    if (!columnas.has('totp_secret')) this.db.exec('ALTER TABLE users ADD COLUMN totp_secret TEXT');
    if (!columnas.has('totp_pending')) this.db.exec('ALTER TABLE users ADD COLUMN totp_pending TEXT');
    if (!columnas.has('totp_enabled')) this.db.exec('ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0');
    if (!columnas.has('totp_enabled_at')) this.db.exec('ALTER TABLE users ADD COLUMN totp_enabled_at INTEGER');
    if (!columnas.has('last_ip')) this.db.exec('ALTER TABLE users ADD COLUMN last_ip TEXT');
    if (!columnas.has('last_login_at')) this.db.exec('ALTER TABLE users ADD COLUMN last_login_at INTEGER');
    this.db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_key ON users(email_key) WHERE email_key IS NOT NULL');
  }

  crearUsuario(username, password, email = null) {
    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 64).toString('hex');
    const key = normalizarUsuario(username);
    const emailLimpio = email ? String(email).trim() : null;
    const emailKey = emailLimpio ? normalizarEmail(emailLimpio) : null;
    try {
      const info = this.db.prepare(
        'INSERT INTO users (username, username_key, salt, hash, email, email_key, verified, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)'
      ).run(username, key, salt, hash, emailLimpio, emailKey, Date.now());
      return this.usuarioPorId(Number(info.lastInsertRowid));
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) {
        const porCorreo = String(error.message).includes('email_key');
        const e = new Error(porCorreo ? 'Ese correo ya está registrado.' : 'Ese alias ya está registrado.');
        e.code = porCorreo ? 'EMAIL_EXISTS' : 'USER_EXISTS';
        throw e;
      }
      throw error;
    }
  }

  actualizarEmail(userId, email) {
    const emailLimpio = String(email || '').trim();
    const emailKey = normalizarEmail(emailLimpio);
    try {
      this.db.prepare('UPDATE users SET email = ?, email_key = ?, verified = 0, verified_at = NULL WHERE id = ?')
        .run(emailLimpio, emailKey, Number(userId));
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) {
        const e = new Error('Ese correo ya está registrado.');
        e.code = 'EMAIL_EXISTS';
        throw e;
      }
      throw error;
    }
    return this.usuarioPorId(userId);
  }

  marcarVerificado(userId) {
    this.db.prepare('UPDATE users SET verified = 1, verified_at = ? WHERE id = ?')
      .run(Date.now(), Number(userId));
    return this.usuarioPorId(userId);
  }

  crearCodigo(userId, purpose, ttlMs = 15 * 60 * 1000) {
    const codigo = generarCodigo(6);
    const salt = generarSalt();
    const ahora = Date.now();
    this.db.prepare('UPDATE account_codes SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL')
      .run(ahora, Number(userId), String(purpose));
    this.db.prepare(`
      INSERT INTO account_codes (user_id, purpose, salt, code_hash, attempts, created_at, expires_at)
      VALUES (?, ?, ?, ?, 0, ?, ?)
    `).run(Number(userId), String(purpose), salt, hashCodigo(codigo, salt), ahora, ahora + ttlMs);
    return { codigo, expira: ahora + ttlMs };
  }

  consumirCodigo(userId, purpose, codigo) {
    const ahora = Date.now();
    const fila = this.db.prepare(`
      SELECT * FROM account_codes
      WHERE user_id = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
      ORDER BY id DESC LIMIT 1
    `).get(Number(userId), String(purpose), ahora);
    if (!fila) return { ok: false, error: 'El código expiró o ya se usó. Solicita otro.' };

    const intentos = Number(fila.attempts) + 1;
    if (compararCodigo(codigo, fila.salt, fila.code_hash)) {
      this.db.prepare('UPDATE account_codes SET used_at = ? WHERE id = ?').run(ahora, fila.id);
      return { ok: true };
    }

    const bloquear = intentos >= 5;
    this.db.prepare('UPDATE account_codes SET attempts = ?, used_at = ? WHERE id = ?')
      .run(intentos, bloquear ? ahora : null, fila.id);
    return {
      ok: false,
      error: bloquear ? 'Demasiados intentos. Solicita un código nuevo.' : 'Código incorrecto.'
    };
  }

  /**
   * Verifica un código sin consumirlo. El código sigue sirviendo para el
   * paso final de cambio de contraseña.
   */
  verificarCodigo(userId, purpose, codigo) {
    const ahora = Date.now();
    const fila = this.db.prepare(`
      SELECT * FROM account_codes
      WHERE user_id = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
      ORDER BY id DESC LIMIT 1
    `).get(Number(userId), String(purpose), ahora);
    if (!fila) return { ok: false, error: 'El código expiró o ya se usó. Solicita otro.' };

    const intentos = Number(fila.attempts) + 1;
    if (compararCodigo(codigo, fila.salt, fila.code_hash)) {
      this.db.prepare('UPDATE account_codes SET attempts = 0 WHERE id = ?').run(fila.id);
      return { ok: true };
    }

    const bloquear = intentos >= 5;
    this.db.prepare('UPDATE account_codes SET attempts = ?, used_at = ? WHERE id = ?')
      .run(intentos, bloquear ? ahora : null, fila.id);
    return {
      ok: false,
      error: bloquear ? 'Demasiados intentos. Solicita un código nuevo.' : 'Código incorrecto.'
    };
  }

  actualizarPassword(userId, password) {
    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 64).toString('hex');
    this.db.prepare('UPDATE users SET salt = ?, hash = ? WHERE id = ?').run(salt, hash, Number(userId));
    this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(Number(userId));
    return this.usuarioPorId(userId);
  }

  usuarioPorIdentificador(identificador) {
    const limpio = String(identificador || '').trim();
    if (!limpio) return null;
    let row = this.db.prepare('SELECT * FROM users WHERE username_key = ?').get(normalizarUsuario(limpio));
    if (!row && limpio.includes('@')) {
      row = this.db.prepare('SELECT * FROM users WHERE email_key = ?').get(normalizarEmail(limpio));
    }
    return row ? this.publico(row) : null;
  }

  datosTotp(userId) {
    const row = this.db.prepare('SELECT totp_secret, totp_pending, totp_enabled FROM users WHERE id = ?').get(Number(userId));
    if (!row) return null;
    return {
      secret: row.totp_secret || null,
      pending: row.totp_pending || null,
      enabled: Number(row.totp_enabled) === 1
    };
  }

  guardarTotpPendiente(userId, secreto) {
    this.db.prepare('UPDATE users SET totp_pending = ?, totp_secret = NULL, totp_enabled = 0, totp_enabled_at = NULL WHERE id = ?')
      .run(String(secreto), Number(userId));
  }

  activarTotp(userId, secreto) {
    this.db.prepare('UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_enabled = 1, totp_enabled_at = ? WHERE id = ?')
      .run(String(secreto), Date.now(), Number(userId));
  }

  desactivarTotp(userId) {
    this.db.prepare('UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_enabled = 0, totp_enabled_at = NULL WHERE id = ?')
      .run(Number(userId));
    this.db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(Number(userId));
  }

  crearCodigosRecuperacion(userId, cantidad = 8) {
    const alfabeto = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const codigos = [];
    this.db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(Number(userId));
    const insertar = this.db.prepare('INSERT INTO recovery_codes (user_id, salt, code_hash, created_at) VALUES (?, ?, ?, ?)');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (let i = 0; i < cantidad; i++) {
        let compacto = '';
        for (let j = 0; j < 8; j++) compacto += alfabeto[randomInt(0, alfabeto.length)];
        const salt = generarSalt();
        insertar.run(Number(userId), salt, hashCodigo(compacto, salt), Date.now());
        codigos.push(`${compacto.slice(0, 4)}-${compacto.slice(4)}`);
      }
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    return codigos;
  }

  consumirCodigoRecuperacion(userId, codigo) {
    const limpio = String(codigo || '').toUpperCase().replace(/[^A-Z2-9]/g, '');
    if (limpio.length < 8) return false;
    const filas = this.db.prepare('SELECT * FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').all(Number(userId));
    for (const fila of filas) {
      if (compararCodigo(limpio, fila.salt, fila.code_hash)) {
        this.db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ?').run(Date.now(), fila.id);
        return true;
      }
    }
    return false;
  }

  crearDesafioLogin(userId) {
    const token = randomBytes(32).toString('hex');
    const ahora = Date.now();
    this.db.prepare('DELETE FROM login_challenges WHERE expires_at <= ?').run(ahora);
    this.db.prepare('INSERT INTO login_challenges (token, user_id, attempts, created_at, expires_at) VALUES (?, ?, 0, ?, ?)')
      .run(token, Number(userId), ahora, ahora + 5 * 60 * 1000);
    return token;
  }

  desafioLogin(token) {
    const row = this.db.prepare('SELECT * FROM login_challenges WHERE token = ? AND expires_at > ?')
      .get(String(token || ''), Date.now());
    return row || null;
  }

  fallarDesafio(token) {
    const row = this.desafioLogin(token);
    if (!row) return 5;
    const intentos = Number(row.attempts) + 1;
    if (intentos >= 5) this.db.prepare('DELETE FROM login_challenges WHERE token = ?').run(row.token);
    else this.db.prepare('UPDATE login_challenges SET attempts = ? WHERE token = ?').run(intentos, row.token);
    return intentos;
  }

  borrarDesafio(token) {
    this.db.prepare('DELETE FROM login_challenges WHERE token = ?').run(String(token || ''));
  }

  datosAcceso(userId) {
    const row = this.db.prepare('SELECT last_ip, last_login_at FROM users WHERE id = ?').get(Number(userId));
    return row ? { lastIp: row.last_ip || null, lastLoginAt: row.last_login_at ? Number(row.last_login_at) : null } : null;
  }

  actualizarUltimoAcceso(userId, ip) {
    this.db.prepare('UPDATE users SET last_ip = ?, last_login_at = ? WHERE id = ?')
      .run(ip || null, Date.now(), Number(userId));
  }

  registrarAuditoria({ event, severity = 'info', userId = null, username = null, ip = null, userAgent = null, detail = null }) {
    this.db.prepare(`
      INSERT INTO audit_log (created_at, event, severity, user_id, username, ip, user_agent, detail)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      Date.now(),
      String(event),
      String(severity),
      userId === null ? null : Number(userId),
      username || null,
      ip || null,
      userAgent || null,
      detail == null ? null : (typeof detail === 'string' ? detail : JSON.stringify(detail))
    );
  }

  listarAuditoria(limite = 100) {
    const tope = Math.max(1, Math.min(500, Number(limite) || 100));
    return this.db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(tope).map((fila) => {
      let detalle = fila.detail || null;
      if (detalle) {
        try { detalle = JSON.parse(detalle); } catch { /* texto plano */ }
      }
      return {
        id: Number(fila.id),
        createdAt: Number(fila.created_at),
        event: fila.event,
        severity: fila.severity,
        userId: fila.user_id === null ? null : Number(fila.user_id),
        username: fila.username,
        ip: fila.ip,
        userAgent: fila.user_agent,
        detail: detalle
      };
    });
  }

  limpiarAuditoria(dias = 90) {
    const corte = Date.now() - Math.max(1, Number(dias) || 90) * 24 * 60 * 60 * 1000;
    this.db.prepare('DELETE FROM audit_log WHERE created_at < ?').run(corte);
  }

  limpiarCodigosExpirados() {
    const ahora = Date.now();
    this.db.prepare('DELETE FROM account_codes WHERE expires_at < ?').run(ahora - 24 * 60 * 60 * 1000);
    this.db.prepare('DELETE FROM login_challenges WHERE expires_at < ?').run(ahora);
  }

  verificarCredenciales(username, password) {
    const key = normalizarUsuario(username);
    const row = this.db.prepare('SELECT * FROM users WHERE username_key = ?').get(key);
    if (!row) return null;
    const hash = scryptSync(password, row.salt, 64);
    const expected = Buffer.from(row.hash, 'hex');
    if (hash.length !== expected.length || !timingSafeEqual(hash, expected)) return null;
    return this.publico(row);
  }

  usuarioPorId(id) {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return row ? this.publico(row) : null;
  }

  crearSesion(userId) {
    const token = randomBytes(32).toString('hex');
    const ahora = Date.now();
    this.db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .run(token, userId, ahora, ahora + SESSION_TTL_MS);
    return token;
  }

  usuarioPorToken(token) {
    if (!token) return null;
    const ahora = Date.now();
    this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(ahora);
    const row = this.db.prepare(`
      SELECT u.* FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ? AND s.expires_at > ?
    `).get(token, ahora);
    return row ? this.publico(row) : null;
  }

  revocarSesion(token) {
    if (!token) return;
    this.db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }

  registrarPartida(partida) {
    const {
      roomCode,
      roomType,
      winnerTeam,
      scoreA,
      scoreB,
      hands,
      startedAt,
      finishedAt,
      players
    } = partida;
    if (!Array.isArray(players) || players.length !== 4) {
      throw new Error('La partida debe tener 4 jugadores.');
    }

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const info = this.db.prepare(`
        INSERT INTO matches (room_code, room_type, winner_team, score_a, score_b, hands, started_at, finished_at, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        String(roomCode),
        String(roomType),
        Number(winnerTeam),
        Number(scoreA),
        Number(scoreB),
        Number(hands),
        Number(startedAt),
        Number(finishedAt),
        Math.max(0, Number(finishedAt) - Number(startedAt))
      );
      const matchId = Number(info.lastInsertRowid);
      const insertarJugador = this.db.prepare(`
        INSERT INTO match_players (match_id, user_id, seat, team, name, won, team_score, rival_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const jugador of players) {
        insertarJugador.run(
          matchId,
          Number(jugador.userId),
          Number(jugador.seat),
          Number(jugador.team),
          String(jugador.name),
          jugador.won ? 1 : 0,
          Number(jugador.teamScore),
          Number(jugador.rivalScore)
        );
      }
      this.db.exec('COMMIT');
      return matchId;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  ranking(limite = 20) {
    const tope = Math.max(1, Math.min(50, Number(limite) || 20));
    const filas = this.db.prepare(`
      SELECT u.id AS user_id,
             u.username,
             COUNT(*) AS games,
             SUM(mp.won) AS wins,
             SUM(CASE WHEN mp.won = 0 THEN 1 ELSE 0 END) AS losses,
             SUM(mp.team_score) AS points
      FROM match_players mp
      JOIN users u ON u.id = mp.user_id
      GROUP BY mp.user_id
      ORDER BY wins DESC, (1.0 * SUM(mp.won) / COUNT(*)) DESC, points DESC, games DESC, u.username ASC
      LIMIT ?
    `).all(tope);

    return filas.map((fila) => {
      const games = Number(fila.games);
      const wins = Number(fila.wins);
      return {
        userId: Number(fila.user_id),
        username: fila.username,
        games,
        wins,
        losses: Number(fila.losses),
        winRate: games > 0 ? Math.round((1000 * wins) / games) / 10 : 0,
        points: Number(fila.points)
      };
    });
  }

  historialUsuario(userId, limite = 20) {
    const tope = Math.max(1, Math.min(50, Number(limite) || 20));
    const filas = this.db.prepare(`
      SELECT m.id AS match_id,
             m.room_code,
             m.room_type,
             m.winner_team,
             m.score_a,
             m.score_b,
             m.started_at,
             m.finished_at,
             m.duration_ms,
             mp.seat,
             mp.team,
             mp.won,
             mp.team_score,
             mp.rival_score,
             (SELECT GROUP_CONCAT(p.name, ' · ')
                FROM match_players p
               WHERE p.match_id = m.id AND p.team = mp.team AND p.user_id <> mp.user_id) AS teammates,
             (SELECT GROUP_CONCAT(p.name, ' · ')
                FROM match_players p
               WHERE p.match_id = m.id AND p.team <> mp.team) AS rivals
      FROM matches m
      JOIN match_players mp ON mp.match_id = m.id
      WHERE mp.user_id = ?
      ORDER BY m.finished_at DESC
      LIMIT ?
    `).all(Number(userId), tope);

    return filas.map((fila) => ({
      matchId: Number(fila.match_id),
      roomCode: fila.room_code,
      roomType: fila.room_type,
      winnerTeam: Number(fila.winner_team),
      scoreA: Number(fila.score_a),
      scoreB: Number(fila.score_b),
      startedAt: Number(fila.started_at),
      finishedAt: Number(fila.finished_at),
      durationMs: Number(fila.duration_ms),
      seat: Number(fila.seat),
      team: Number(fila.team),
      won: Number(fila.won) === 1,
      teamScore: Number(fila.team_score),
      rivalScore: Number(fila.rival_score),
      teammates: fila.teammates || '',
      rivals: fila.rivals || ''
    }));
  }

  estadisticasUsuario(userId) {
    const fila = this.db.prepare(`
      SELECT COUNT(*) AS games,
             COALESCE(SUM(won), 0) AS wins,
             COALESCE(SUM(CASE WHEN won = 0 THEN 1 ELSE 0 END), 0) AS losses,
             COALESCE(SUM(team_score), 0) AS points
      FROM match_players
      WHERE user_id = ?
    `).get(Number(userId));
    const games = Number(fila?.games || 0);
    const wins = Number(fila?.wins || 0);
    return {
      games,
      wins,
      losses: Number(fila?.losses || 0),
      winRate: games > 0 ? Math.round((1000 * wins) / games) / 10 : 0,
      points: Number(fila?.points || 0)
    };
  }

  cerrar() {
    this.db.close();
  }

  publico(row) {
    return {
      id: Number(row.id),
      username: row.username,
      coins: Number(row.coins),
      email: row.email || null,
      verified: Number(row.verified) === 1,
      totpEnabled: Number(row.totp_enabled) === 1
    };
  }
}

export function normalizarUsuario(username) {
  return String(username).trim().normalize('NFKC').toLowerCase();
}

export function validarCredenciales(username, password) {
  const limpio = String(username ?? '').trim();
  if (limpio.length < 3 || limpio.length > 18) return 'El alias debe tener entre 3 y 18 caracteres.';
  if (!/^[\p{L}\p{N} _-]+$/u.test(limpio)) return 'Usa solo letras, números, espacio, guion o guion bajo.';
  if (String(password ?? '').length < 6) return 'La contraseña debe tener al menos 6 caracteres.';
  if (String(password ?? '').length > 72) return 'La contraseña es demasiado larga.';
  return null;
}
