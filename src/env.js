import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rutaEnv = process.env.ENV_FILE || path.join(__dirname, '..', '.env');

// dotenv no sobreescribe variables ya definidas por el sistema.
// ENV_FILE permite usar otro archivo (por ejemplo, en pruebas).
dotenv.config({ path: rutaEnv, quiet: true });

/**
 * Limpia espacios sobrantes y comillas envolventes que a veces quedan
 * pegadas al copiar valores en paneles como el de Render
 * (por ejemplo `"smtp.gmail.com"` o ` "clave" `).
 */
export function limpiarValor(valor) {
  let limpio = String(valor ?? '').trim();

  while (limpio.length >= 2) {
    const primero = limpio[0];
    const ultimo = limpio[limpio.length - 1];
    const envuelto = (primero === '"' && ultimo === '"')
      || (primero === "'" && ultimo === "'");

    if (!envuelto) break;
    limpio = limpio.slice(1, -1).trim();
  }

  return limpio;
}

// Variables que se leen en el arranque; se sanean una sola vez.
const CLAVES_SANEADAS = [
  'PORT',
  'DATABASE_URL',
  'DATABASE_URL_TEST',
  'PG_POOL_MAX',
  'CORS_ORIGIN',
  'TRUST_PROXY',
  'NODE_ENV',
  'TLS_CERT',
  'TLS_KEY',
  'ADMIN_TOKEN',
  'DEV_CODES',
  'REQUIRE_EMAIL',
  'REQUIRE_VERIFIED',
  'RECOVERY_CODE_TTL_MIN',
  'VERIFY_CODE_TTL_MIN',
  'SMTP_URL',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_SECURE',
  'SMTP_USER',
  'SMTP_PASS',
  'SMTP_FROM',
  'SMTP_REPLY_TO',
  'SMTP_REQUIRE_TLS',
  'SMTP_DEBUG',
  'MAIL_PROVIDER',
  'MAIL_FROM',
  'MAIL_HTTP_TIMEOUT_MS',
  'RESEND_API_KEY',
  'RESEND_API_URL',
  'BREVO_API_KEY',
  'BREVO_API_URL',
  'DKIM_DOMAIN',
  'DKIM_SELECTOR',
  'DKIM_PRIVATE_KEY',
  'ALERT_EMAIL',
  'ALERT_WEBHOOK_URL'
];

for (const clave of CLAVES_SANEADAS) {
  if (process.env[clave] !== undefined) {
    process.env[clave] = limpiarValor(process.env[clave]);
  }
}

export const ENV_PATH = rutaEnv;
