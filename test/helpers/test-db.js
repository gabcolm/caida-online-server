import pg from 'pg';
import '../../src/env.js';

const { Pool } = pg;

export function urlPruebas() {
  return process.env.DATABASE_URL_TEST
    || process.env.DATABASE_URL
    || 'postgresql://caida@localhost:5432/caida_online_test';
}

function esLocal(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

/** Borra todo el esquema de la base de pruebas para empezar limpio. */
export async function reiniciarBaseDePruebas() {
  const url = new URL(urlPruebas());
  const pool = new Pool({
    connectionString: url.toString(),
    ssl: esLocal(url.hostname) ? false : { rejectUnauthorized: false }
  });

  try {
    await pool.query(`
      DROP TABLE IF EXISTS purchases, social_accounts, friendships, match_players, matches, audit_log, login_challenges,
        recovery_codes, account_codes, sessions, users CASCADE
    `);
  } finally {
    await pool.end();
  }
}
