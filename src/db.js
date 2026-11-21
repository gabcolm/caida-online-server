import pg from 'pg';
import { randomBytes, randomInt, scryptSync, timingSafeEqual } from 'node:crypto';
import { compararCodigo, generarCodigo, generarSalt, hashCodigo, normalizarEmail } from './security.js';

const { Pool } = pg;

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function urlPorDefecto() {
  const usuario = process.env.PGUSER || 'caida';
  const clave = process.env.PGPASSWORD || '';
  const host = process.env.PGHOST || 'localhost';
  const puerto = process.env.PGPORT || '5432';
  const base = process.env.PGDATABASE || 'caida_online';
  const auth = clave
    ? `${encodeURIComponent(usuario)}:${encodeURIComponent(clave)}`
    : encodeURIComponent(usuario);
  return `postgresql://${auth}@${host}:${puerto}/${base}`;
}

function normalizarUrl(valor) {
  const url = new URL(valor);
  // Neon añade channel_binding/sslmode; la conexión SSL se configura en el Pool.
  url.searchParams.delete('channel_binding');
  url.searchParams.delete('sslmode');
  return url;
}

function esLocal(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

const ESQUEMA = `
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  username_key TEXT NOT NULL UNIQUE,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  coins INTEGER NOT NULL DEFAULT 2000,
  email TEXT,
  email_key TEXT,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  verified_at BIGINT,
  totp_secret TEXT,
  totp_pending TEXT,
  totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  totp_enabled_at BIGINT,
  last_ip TEXT,
  last_login_at BIGINT,
  created_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_key ON users(email_key) WHERE email_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS account_codes (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  salt TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT
);
CREATE INDEX IF NOT EXISTS idx_account_codes_user ON account_codes(user_id, purpose, used_at);

CREATE TABLE IF NOT EXISTS recovery_codes (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  salt TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  used_at BIGINT,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id, used_at);

CREATE TABLE IF NOT EXISTS login_challenges (
  token TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_challenges_user ON login_challenges(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  created_at BIGINT NOT NULL,
  event TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  user_id BIGINT,
  username TEXT,
  ip TEXT,
  user_agent TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event, created_at DESC);

CREATE TABLE IF NOT EXISTS matches (
  id BIGSERIAL PRIMARY KEY,
  room_code TEXT NOT NULL,
  room_type TEXT NOT NULL,
  winner_team INTEGER NOT NULL,
  score_a INTEGER NOT NULL,
  score_b INTEGER NOT NULL,
  hands INTEGER NOT NULL,
  started_at BIGINT NOT NULL,
  finished_at BIGINT NOT NULL,
  duration_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_matches_finished ON matches(finished_at DESC);

CREATE TABLE IF NOT EXISTS match_players (
  match_id BIGINT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  seat INTEGER NOT NULL,
  team INTEGER NOT NULL,
  name TEXT NOT NULL,
  won BOOLEAN NOT NULL,
  team_score INTEGER NOT NULL,
  rival_score INTEGER NOT NULL,
  PRIMARY KEY (match_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_match_players_user ON match_players(user_id);
`;

export class BaseDatos {
  constructor(databaseUrl = process.env.DATABASE_URL || urlPorDefecto()) {
    this.url = normalizarUrl(databaseUrl);
    const local = esLocal(this.url.hostname);
    this.pool = new Pool({
      connectionString: this.url.toString(),
      max: Number(process.env.PG_POOL_MAX || 10),
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 15000,
      ssl: local ? false : { rejectUnauthorized: false }
    });

    this.pool.on('error', (error) => {
      console.error('[db] error en conexión inactiva:', error.message);
    });
  }

  /** Crea tablas e índices si no existen. */
  async iniciar() {
    await this.pool.query(ESQUEMA);
  }

  async crearUsuario(username, password, email = null) {
    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 64).toString('hex');
    const key = normalizarUsuario(username);
    const emailLimpio = email ? String(email).trim() : null;
    const emailKey = emailLimpio ? normalizarEmail(emailLimpio) : null;
    try {
      const { rows } = await this.pool.query(
        `INSERT INTO users (username, username_key, salt, hash, email, email_key, verified, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7)
         RETURNING id`,
        [username, key, salt, hash, emailLimpio, emailKey, Date.now()]
      );
      return this.usuarioPorId(rows[0].id);
    } catch (error) {
      if (error.code === '23505') {
        const porCorreo = String(error.constraint || '').includes('email_key')
          || String(error.detail || '').includes('email_key');
        const e = new Error(porCorreo ? 'Ese correo ya está registrado.' : 'Ese alias ya está registrado.');
        e.code = porCorreo ? 'EMAIL_EXISTS' : 'USER_EXISTS';
        throw e;
      }
      throw error;
    }
  }

  async actualizarEmail(userId, email) {
    const emailLimpio = String(email || '').trim();
    const emailKey = normalizarEmail(emailLimpio);
    try {
      await this.pool.query(
        'UPDATE users SET email = $1, email_key = $2, verified = FALSE, verified_at = NULL WHERE id = $3',
        [emailLimpio, emailKey, Number(userId)]
      );
    } catch (error) {
      if (error.code === '23505') {
        const e = new Error('Ese correo ya está registrado.');
        e.code = 'EMAIL_EXISTS';
        throw e;
      }
      throw error;
    }
    return this.usuarioPorId(userId);
  }

  async marcarVerificado(userId) {
    await this.pool.query('UPDATE users SET verified = TRUE, verified_at = $1 WHERE id = $2', [Date.now(), Number(userId)]);
    return this.usuarioPorId(userId);
  }

  async crearCodigo(userId, purpose, ttlMs = 15 * 60 * 1000) {
    const codigo = generarCodigo(6);
    const salt = generarSalt();
    const ahora = Date.now();

    await this.pool.query(
      'UPDATE account_codes SET used_at = $1 WHERE user_id = $2 AND purpose = $3 AND used_at IS NULL',
      [ahora, Number(userId), String(purpose)]
    );
    await this.pool.query(
      `INSERT INTO account_codes (user_id, purpose, salt, code_hash, attempts, created_at, expires_at)
       VALUES ($1, $2, $3, $4, 0, $5, $6)`,
      [Number(userId), String(purpose), salt, hashCodigo(codigo, salt), ahora, ahora + ttlMs]
    );

    return { codigo, expira: ahora + ttlMs };
  }

  async consumirCodigo(userId, purpose, codigo) {
    const ahora = Date.now();
    const { rows } = await this.pool.query(
      `SELECT * FROM account_codes
       WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3
       ORDER BY id DESC LIMIT 1`,
      [Number(userId), String(purpose), ahora]
    );
    const fila = rows[0];
    if (!fila) return { ok: false, error: 'El código expiró o ya se usó. Solicita otro.' };

    const intentos = Number(fila.attempts) + 1;
    if (compararCodigo(codigo, fila.salt, fila.code_hash)) {
      await this.pool.query('UPDATE account_codes SET used_at = $1 WHERE id = $2', [ahora, fila.id]);
      return { ok: true };
    }

    const bloquear = intentos >= 5;
    await this.pool.query(
      'UPDATE account_codes SET attempts = $1, used_at = $2 WHERE id = $3',
      [intentos, bloquear ? ahora : null, fila.id]
    );
    return {
      ok: false,
      error: bloquear ? 'Demasiados intentos. Solicita un código nuevo.' : 'Código incorrecto.'
    };
  }

  /**
   * Verifica un código sin consumirlo. El código sigue sirviendo para el
   * paso final de cambio de contraseña.
   */
  async verificarCodigo(userId, purpose, codigo) {
    const ahora = Date.now();
    const { rows } = await this.pool.query(
      `SELECT * FROM account_codes
       WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3
       ORDER BY id DESC LIMIT 1`,
      [Number(userId), String(purpose), ahora]
    );
    const fila = rows[0];
    if (!fila) return { ok: false, error: 'El código expiró o ya se usó. Solicita otro.' };

    const intentos = Number(fila.attempts) + 1;
    if (compararCodigo(codigo, fila.salt, fila.code_hash)) {
      await this.pool.query('UPDATE account_codes SET attempts = 0 WHERE id = $1', [fila.id]);
      return { ok: true };
    }

    const bloquear = intentos >= 5;
    await this.pool.query(
      'UPDATE account_codes SET attempts = $1, used_at = $2 WHERE id = $3',
      [intentos, bloquear ? ahora : null, fila.id]
    );
    return {
      ok: false,
      error: bloquear ? 'Demasiados intentos. Solicita un código nuevo.' : 'Código incorrecto.'
    };
  }

  async actualizarPassword(userId, password) {
    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 64).toString('hex');
    await this.pool.query('UPDATE users SET salt = $1, hash = $2 WHERE id = $3', [salt, hash, Number(userId)]);
    await this.pool.query('DELETE FROM sessions WHERE user_id = $1', [Number(userId)]);
    return this.usuarioPorId(userId);
  }

  async usuarioPorIdentificador(identificador) {
    const limpio = String(identificador || '').trim();
    if (!limpio) return null;

    let { rows } = await this.pool.query('SELECT * FROM users WHERE username_key = $1', [normalizarUsuario(limpio)]);
    if (!rows[0] && limpio.includes('@')) {
      ({ rows } = await this.pool.query('SELECT * FROM users WHERE email_key = $1', [normalizarEmail(limpio)]));
    }
    return rows[0] ? this.publico(rows[0]) : null;
  }

  async datosTotp(userId) {
    const { rows } = await this.pool.query(
      'SELECT totp_secret, totp_pending, totp_enabled FROM users WHERE id = $1',
      [Number(userId)]
    );
    const row = rows[0];
    if (!row) return null;
    return {
      secret: row.totp_secret || null,
      pending: row.totp_pending || null,
      enabled: row.totp_enabled === true
    };
  }

  async guardarTotpPendiente(userId, secreto) {
    await this.pool.query(
      'UPDATE users SET totp_pending = $1, totp_secret = NULL, totp_enabled = FALSE, totp_enabled_at = NULL WHERE id = $2',
      [String(secreto), Number(userId)]
    );
  }

  async activarTotp(userId, secreto) {
    await this.pool.query(
      'UPDATE users SET totp_secret = $1, totp_pending = NULL, totp_enabled = TRUE, totp_enabled_at = $2 WHERE id = $3',
      [String(secreto), Date.now(), Number(userId)]
    );
  }

  async desactivarTotp(userId) {
    await this.pool.query(
      'UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_enabled = FALSE, totp_enabled_at = NULL WHERE id = $1',
      [Number(userId)]
    );
    await this.pool.query('DELETE FROM recovery_codes WHERE user_id = $1', [Number(userId)]);
  }

  async crearCodigosRecuperacion(userId, cantidad = 8) {
    const alfabeto = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const codigos = [];
    const cliente = await this.pool.connect();

    try {
      await cliente.query('BEGIN');
      await cliente.query('DELETE FROM recovery_codes WHERE user_id = $1', [Number(userId)]);

      for (let i = 0; i < cantidad; i++) {
        let compacto = '';
        for (let j = 0; j < 8; j++) compacto += alfabeto[randomInt(0, alfabeto.length)];
        const salt = generarSalt();
        await cliente.query(
          'INSERT INTO recovery_codes (user_id, salt, code_hash, created_at) VALUES ($1, $2, $3, $4)',
          [Number(userId), salt, hashCodigo(compacto, salt), Date.now()]
        );
        codigos.push(`${compacto.slice(0, 4)}-${compacto.slice(4)}`);
      }

      await cliente.query('COMMIT');
      return codigos;
    } catch (error) {
      await cliente.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      cliente.release();
    }
  }

  async consumirCodigoRecuperacion(userId, codigo) {
    const limpio = String(codigo || '').toUpperCase().replace(/[^A-Z2-9]/g, '');
    if (limpio.length < 8) return false;

    const { rows } = await this.pool.query(
      'SELECT * FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL',
      [Number(userId)]
    );
    for (const fila of rows) {
      if (compararCodigo(limpio, fila.salt, fila.code_hash)) {
        await this.pool.query('UPDATE recovery_codes SET used_at = $1 WHERE id = $2', [Date.now(), fila.id]);
        return true;
      }
    }
    return false;
  }

  async crearDesafioLogin(userId) {
    const token = randomBytes(32).toString('hex');
    const ahora = Date.now();
    await this.pool.query('DELETE FROM login_challenges WHERE expires_at <= $1', [ahora]);
    await this.pool.query(
      'INSERT INTO login_challenges (token, user_id, attempts, created_at, expires_at) VALUES ($1, $2, 0, $3, $4)',
      [token, Number(userId), ahora, ahora + 5 * 60 * 1000]
    );
    return token;
  }

  async desafioLogin(token) {
    const { rows } = await this.pool.query(
      'SELECT * FROM login_challenges WHERE token = $1 AND expires_at > $2',
      [String(token || ''), Date.now()]
    );
    return rows[0] || null;
  }

  async fallarDesafio(token) {
    const row = await this.desafioLogin(token);
    if (!row) return 5;
    const intentos = Number(row.attempts) + 1;
    if (intentos >= 5) await this.pool.query('DELETE FROM login_challenges WHERE token = $1', [row.token]);
    else await this.pool.query('UPDATE login_challenges SET attempts = $1 WHERE token = $2', [intentos, row.token]);
    return intentos;
  }

  async borrarDesafio(token) {
    await this.pool.query('DELETE FROM login_challenges WHERE token = $1', [String(token || '')]);
  }

  async datosAcceso(userId) {
    const { rows } = await this.pool.query(
      'SELECT last_ip, last_login_at FROM users WHERE id = $1',
      [Number(userId)]
    );
    const row = rows[0];
    return row
      ? { lastIp: row.last_ip || null, lastLoginAt: row.last_login_at ? Number(row.last_login_at) : null }
      : null;
  }

  async actualizarUltimoAcceso(userId, ip) {
    await this.pool.query(
      'UPDATE users SET last_ip = $1, last_login_at = $2 WHERE id = $3',
      [ip || null, Date.now(), Number(userId)]
    );
  }

  async registrarAuditoria({ event, severity = 'info', userId = null, username = null, ip = null, userAgent = null, detail = null }) {
    await this.pool.query(
      `INSERT INTO audit_log (created_at, event, severity, user_id, username, ip, user_agent, detail)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        Date.now(),
        String(event),
        String(severity),
        userId === null ? null : Number(userId),
        username || null,
        ip || null,
        userAgent || null,
        detail == null ? null : (typeof detail === 'string' ? detail : JSON.stringify(detail))
      ]
    );
  }

  async listarAuditoria(limite = 100) {
    const tope = Math.max(1, Math.min(500, Number(limite) || 100));
    const { rows } = await this.pool.query('SELECT * FROM audit_log ORDER BY id DESC LIMIT $1', [tope]);

    return rows.map((fila) => {
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

  async limpiarAuditoria(dias = 90) {
    const corte = Date.now() - Math.max(1, Number(dias) || 90) * 24 * 60 * 60 * 1000;
    await this.pool.query('DELETE FROM audit_log WHERE created_at < $1', [corte]);
  }

  async limpiarCodigosExpirados() {
    const ahora = Date.now();
    await this.pool.query('DELETE FROM account_codes WHERE expires_at < $1', [ahora - 24 * 60 * 60 * 1000]);
    await this.pool.query('DELETE FROM login_challenges WHERE expires_at < $1', [ahora]);
  }

  async verificarCredenciales(username, password) {
    const key = normalizarUsuario(username);
    const { rows } = await this.pool.query('SELECT * FROM users WHERE username_key = $1', [key]);
    const row = rows[0];
    if (!row) return null;

    const hash = scryptSync(password, row.salt, 64);
    const expected = Buffer.from(row.hash, 'hex');
    if (hash.length !== expected.length || !timingSafeEqual(hash, expected)) return null;
    return this.publico(row);
  }

  async usuarioPorId(id) {
    const { rows } = await this.pool.query('SELECT * FROM users WHERE id = $1', [Number(id)]);
    return rows[0] ? this.publico(rows[0]) : null;
  }

  async crearSesion(userId) {
    const token = randomBytes(32).toString('hex');
    const ahora = Date.now();
    await this.pool.query(
      'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)',
      [token, Number(userId), ahora, ahora + SESSION_TTL_MS]
    );
    return token;
  }

  async usuarioPorToken(token) {
    if (!token) return null;
    const ahora = Date.now();
    await this.pool.query('DELETE FROM sessions WHERE expires_at <= $1', [ahora]);
    const { rows } = await this.pool.query(
      `SELECT u.* FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = $1 AND s.expires_at > $2`,
      [token, ahora]
    );
    return rows[0] ? this.publico(rows[0]) : null;
  }

  async revocarSesion(token) {
    if (!token) return;
    await this.pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  }

  async registrarPartida(partida) {
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

    const cliente = await this.pool.connect();
    try {
      await cliente.query('BEGIN');

      const { rows } = await cliente.query(
        `INSERT INTO matches (room_code, room_type, winner_team, score_a, score_b, hands, started_at, finished_at, duration_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id`,
        [
          String(roomCode),
          String(roomType),
          Number(winnerTeam),
          Number(scoreA),
          Number(scoreB),
          Number(hands),
          Number(startedAt),
          Number(finishedAt),
          Math.max(0, Number(finishedAt) - Number(startedAt))
        ]
      );
      const matchId = Number(rows[0].id);

      for (const jugador of players) {
        await cliente.query(
          `INSERT INTO match_players (match_id, user_id, seat, team, name, won, team_score, rival_score)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [
            matchId,
            Number(jugador.userId),
            Number(jugador.seat),
            Number(jugador.team),
            String(jugador.name),
            Boolean(jugador.won),
            Number(jugador.teamScore),
            Number(jugador.rivalScore)
          ]
        );
      }

      await cliente.query('COMMIT');
      return matchId;
    } catch (error) {
      await cliente.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      cliente.release();
    }
  }

  async ranking(limite = 20) {
    const tope = Math.max(1, Math.min(50, Number(limite) || 20));
    const { rows } = await this.pool.query(
      `SELECT u.id AS user_id,
              u.username,
              COUNT(*) AS games,
              SUM(CASE WHEN mp.won THEN 1 ELSE 0 END) AS wins,
              SUM(CASE WHEN mp.won THEN 0 ELSE 1 END) AS losses,
              SUM(mp.team_score) AS points
       FROM match_players mp
       JOIN users u ON u.id = mp.user_id
       GROUP BY mp.user_id, u.id, u.username
       ORDER BY wins DESC, (1.0 * SUM(CASE WHEN mp.won THEN 1 ELSE 0 END) / COUNT(*)) DESC,
                points DESC, games DESC, u.username ASC
       LIMIT $1`,
      [tope]
    );

    return rows.map((fila) => {
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

  async historialUsuario(userId, limite = 20) {
    const tope = Math.max(1, Math.min(50, Number(limite) || 20));
    const { rows } = await this.pool.query(
      `SELECT m.id AS match_id,
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
              (SELECT STRING_AGG(p.name, ' · ' ORDER BY p.seat)
                 FROM match_players p
                WHERE p.match_id = m.id AND p.team = mp.team AND p.user_id <> mp.user_id) AS teammates,
              (SELECT STRING_AGG(p.name, ' · ' ORDER BY p.seat)
                 FROM match_players p
                WHERE p.match_id = m.id AND p.team <> mp.team) AS rivals
       FROM matches m
       JOIN match_players mp ON mp.match_id = m.id
       WHERE mp.user_id = $1
       ORDER BY m.finished_at DESC
       LIMIT $2`,
      [Number(userId), tope]
    );

    return rows.map((fila) => ({
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
      won: fila.won === true,
      teamScore: Number(fila.team_score),
      rivalScore: Number(fila.rival_score),
      teammates: fila.teammates || '',
      rivals: fila.rivals || ''
    }));
  }

  async estadisticasUsuario(userId) {
    const { rows } = await this.pool.query(
      `SELECT COUNT(*) AS games,
              COALESCE(SUM(CASE WHEN won THEN 1 ELSE 0 END), 0) AS wins,
              COALESCE(SUM(CASE WHEN won THEN 0 ELSE 1 END), 0) AS losses,
              COALESCE(SUM(team_score), 0) AS points
       FROM match_players
       WHERE user_id = $1`,
      [Number(userId)]
    );
    const fila = rows[0];
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

  async cerrar() {
    await this.pool.end();
  }

  publico(row) {
    return {
      id: Number(row.id),
      username: row.username,
      coins: Number(row.coins),
      email: row.email || null,
      verified: row.verified === true || Number(row.verified) === 1,
      totpEnabled: row.totp_enabled === true || Number(row.totp_enabled) === 1
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
