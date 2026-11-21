import nodemailer from 'nodemailer';
import { existsSync, readFileSync } from 'node:fs';
import { limpiarValor } from './env.js';

function parseBool(valor) {
  return ['1', 'true', 'yes', 'on'].includes(String(valor || '').trim().toLowerCase());
}

function extraerEmail(valor) {
  const texto = String(valor || '').trim();
  const coincidencia = texto.match(/<([^>]+)>/);
  return (coincidencia ? coincidencia[1] : texto).trim().toLowerCase();
}

function extraerNombre(valor) {
  const texto = String(valor || '').trim();
  const coincidencia = texto.match(/^"?([^"<]*?)"?\s*<[^>]+>$/);
  return (coincidencia && coincidencia[1].trim()) || 'Caída Online';
}

// Todos los valores vienen saneados de env.js; se vuelve a limpiar por si
// algún módulo de prueba importa mailer.js sin pasar por env.js.
const SMTP_URL = limpiarValor(process.env.SMTP_URL);
const SMTP_HOST = limpiarValor(process.env.SMTP_HOST);
const SMTP_PORT = Number(limpiarValor(process.env.SMTP_PORT) || 587) || 587;
const SMTP_SECURE = SMTP_PORT === 465 ? true : parseBool(limpiarValor(process.env.SMTP_SECURE));
const SMTP_USER = limpiarValor(process.env.SMTP_USER);
const SMTP_PASS = limpiarValor(process.env.SMTP_PASS);
const SMTP_FROM = limpiarValor(process.env.SMTP_FROM)
  || (SMTP_USER ? `Caída Online <${SMTP_USER}>` : 'Caída Online <no-reply@caida.local>');
const SMTP_REPLY_TO = limpiarValor(process.env.SMTP_REPLY_TO);
const SMTP_REQUIRE_TLS = parseBool(limpiarValor(process.env.SMTP_REQUIRE_TLS))
  || (!SMTP_SECURE && SMTP_HOST.toLowerCase().includes('gmail.com'));
const SMTP_DEBUG = parseBool(limpiarValor(process.env.SMTP_DEBUG));
const DKIM_DOMAIN = limpiarValor(process.env.DKIM_DOMAIN);
const DKIM_SELECTOR = limpiarValor(process.env.DKIM_SELECTOR) || 'caida';
const DKIM_KEY = limpiarValor(process.env.DKIM_PRIVATE_KEY);
const ALERT_EMAIL = limpiarValor(process.env.ALERT_EMAIL);
const PRODUCCION = limpiarValor(process.env.NODE_ENV) === 'production';

// --- Proveedores de correo por API HTTP (puerto 443) -----------------------
// Render Free bloquea los puertos SMTP 25/465/587; con Resend o Brevo el
// envío viaja por HTTPS y funciona en el plan gratuito.
const MAIL_PROVIDER = limpiarValor(process.env.MAIL_PROVIDER).toLowerCase();
const RESEND_API_KEY = limpiarValor(process.env.RESEND_API_KEY);
const RESEND_API_URL = limpiarValor(process.env.RESEND_API_URL) || 'https://api.resend.com/emails';
const BREVO_API_KEY = limpiarValor(process.env.BREVO_API_KEY);
const BREVO_API_URL = limpiarValor(process.env.BREVO_API_URL) || 'https://api.brevo.com/v3/smtp/email';
const MAIL_HTTP_TIMEOUT_MS = Number(limpiarValor(process.env.MAIL_HTTP_TIMEOUT_MS) || 15000) || 15000;

const MAIL_FROM = limpiarValor(process.env.MAIL_FROM) || SMTP_FROM;

let PROVEEDOR_HTTP = '';
if (MAIL_PROVIDER === 'resend') {
  PROVEEDOR_HTTP = RESEND_API_KEY ? 'resend' : '';
} else if (MAIL_PROVIDER === 'brevo') {
  PROVEEDOR_HTTP = BREVO_API_KEY ? 'brevo' : '';
} else if (!MAIL_PROVIDER && RESEND_API_KEY) {
  PROVEEDOR_HTTP = 'resend';
} else if (!MAIL_PROVIDER && BREVO_API_KEY) {
  PROVEEDOR_HTTP = 'brevo';
}

let transporte = null;

function construirDkim() {
  if (!DKIM_DOMAIN || !DKIM_KEY) return null;
  try {
    const privateKey = existsSync(DKIM_KEY) ? readFileSync(DKIM_KEY, 'utf8') : DKIM_KEY.replace(/\\n/g, '\n');
    return { domainName: DKIM_DOMAIN, keySelector: DKIM_SELECTOR, privateKey };
  } catch (error) {
    console.error('[MAIL_ERROR] no se pudo leer DKIM_PRIVATE_KEY:', error);
    return null;
  }
}

function advertirConfiguracion() {
  if (SMTP_USER && !SMTP_PASS) {
    console.warn('[seguridad] SMTP_USER está definido pero SMTP_PASS está vacío.');
  }
  if (/\s/.test(SMTP_PASS)) {
    console.warn('[seguridad] SMTP_PASS contiene espacios. Las contraseñas de aplicación de Gmail suelen tener 16 caracteres sin espacios.');
  }
  if (SMTP_USER && !SMTP_USER.includes('@')) {
    console.warn('[seguridad] SMTP_USER no parece un correo completo. Usa la dirección de Gmail completa.');
  }
  if (SMTP_HOST.toLowerCase().includes('gmail.com')) {
    const fromEmail = extraerEmail(SMTP_FROM);
    if (fromEmail && fromEmail !== SMTP_USER.toLowerCase()) {
      console.warn(`[seguridad] Gmail normalmente exige que el remitente (${fromEmail}) sea la misma cuenta autenticada (${SMTP_USER}).`);
    }
  }
  if (SMTP_PORT === 587 && SMTP_SECURE) {
    console.warn('[seguridad] El puerto 587 normalmente usa SMTP_SECURE=0 (STARTTLS).');
  }
  if (SMTP_PORT === 465 && !parseBool(limpiarValor(process.env.SMTP_SECURE))) {
    console.warn('[seguridad] El puerto 465 usa SSL directo; se forzó secure=true.');
  }
}

/**
 * Resumen del canal de correo sin secretos, útil para los logs de Render.
 */
export function diagnosticoMailer() {
  let hostHttp = null;
  if (PROVEEDOR_HTTP) {
    try {
      hostHttp = new URL(PROVEEDOR_HTTP === 'resend' ? RESEND_API_URL : BREVO_API_URL).host;
    } catch {
      hostHttp = PROVEEDOR_HTTP === 'resend' ? RESEND_API_URL : BREVO_API_URL;
    }
  }

  return {
    canal: PROVEEDOR_HTTP ? `http:${PROVEEDOR_HTTP}` : (transporte || SMTP_URL || SMTP_HOST ? 'smtp' : 'ninguno'),
    host: PROVEEDOR_HTTP ? hostHttp : (SMTP_HOST || null),
    puerto: PROVEEDOR_HTTP ? 443 : SMTP_PORT,
    secure: PROVEEDOR_HTTP ? true : SMTP_SECURE,
    usuario: SMTP_USER ? extraerEmail(SMTP_USER) : null,
    remitente: MAIL_FROM,
    passwordConfigurada: Boolean(SMTP_PASS),
    apiKeyConfigurada: Boolean(PROVEEDOR_HTTP === 'resend' ? RESEND_API_KEY : PROVEEDOR_HTTP === 'brevo' ? BREVO_API_KEY : '')
  };
}

export function configurarMailer({ verificar = true } = {}) {
  const proveedorPedido = (MAIL_PROVIDER === 'resend' || MAIL_PROVIDER === 'brevo')
    ? MAIL_PROVIDER
    : '';

  if (proveedorPedido && !PROVEEDOR_HTTP) {
    console.error(`[MAIL_ERROR] MAIL_PROVIDER=${proveedorPedido} pero falta ${proveedorPedido === 'resend' ? 'RESEND_API_KEY' : 'BREVO_API_KEY'}.`);
    return false;
  }

  if (PROVEEDOR_HTTP) {
    if (!MAIL_FROM || !MAIL_FROM.includes('@')) {
      console.warn('[seguridad] MAIL_FROM no parece un remitente válido:', MAIL_FROM);
    }

    console.log(`[seguridad] correo por API HTTP (${PROVEEDOR_HTTP}) sobre HTTPS; remitente=${MAIL_FROM}`);
    if (SMTP_HOST) {
      console.log('[seguridad] SMTP ignorado porque hay un proveedor HTTP configurado.');
    }
    console.log('[seguridad] diagnóstico correo:', diagnosticoMailer());
    return true;
  }

  if (!SMTP_URL && !SMTP_HOST) {
    if (PRODUCCION) {
      console.warn('[seguridad] correo no configurado: no se enviarán verificaciones, recuperaciones ni alertas.');
      console.warn('[seguridad] En Render Free configura RESEND_API_KEY (o BREVO_API_KEY): los puertos SMTP están bloqueados.');
    } else {
      console.log('[seguridad] SMTP no configurado: los códigos se mostrarán en la consola local.');
    }
    return false;
  }

  try {
    let opciones;

    if (SMTP_URL) {
      opciones = { url: SMTP_URL };
      console.log('[seguridad] SMTP usando SMTP_URL (host/port/secure se leen de la URL).');
    } else {
      opciones = {
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_SECURE,
        auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
        requireTLS: SMTP_REQUIRE_TLS,
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 20000,
        tls: { minVersion: 'TLSv1.2' }
      };

      console.log('[seguridad] SMTP explícito: '
        + `host=${SMTP_HOST} port=${SMTP_PORT} secure=${SMTP_SECURE} `
        + `auth=${SMTP_USER ? 'sí' : 'no'} from=${SMTP_FROM} requireTLS=${SMTP_REQUIRE_TLS}`);
    }

    advertirConfiguracion();

    if (SMTP_DEBUG) {
      opciones.logger = true;
      opciones.debug = true;
      console.warn('[seguridad] SMTP_DEBUG activo: el log puede incluir datos del protocolo SMTP. No usar en producción.');
    }

    const dkim = construirDkim();
    if (dkim) opciones.dkim = dkim;
    transporte = nodemailer.createTransport(opciones);
    console.log(`[seguridad] SMTP configurado${dkim ? ` con DKIM (${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN})` : ''}.`);
    console.log('[seguridad] diagnóstico correo:', diagnosticoMailer());

    // No basta con crear el transporte: verify comprueba conexión y login.
    if (verificar) verificarMailer();
    return true;
  } catch (error) {
    console.error('[MAIL_ERROR] configuración SMTP inválida:', error);
    transporte = null;
    return false;
  }
}

export async function verificarMailer() {
  if (PROVEEDOR_HTTP) {
    console.log(`[seguridad] API HTTP (${PROVEEDOR_HTTP}) configurada; no hay handshake SMTP que verificar.`);
    return true;
  }
  if (!transporte) return false;

  console.log('[seguridad] Verificando conexión y autenticación SMTP...');
  try {
    await transporte.verify();
    console.log('[seguridad] SMTP verify: conexión y autenticación OK.');
    return true;
  } catch (error) {
    console.error('[MAIL_ERROR]', error);
    console.error('[seguridad] SMTP verify falló:', {
      code: error.code,
      responseCode: error.responseCode,
      command: error.command,
      response: error.response,
      message: error.message
    });
    return false;
  }
}

export function mailerConfigurado() {
  return transporte !== null || Boolean(PROVEEDOR_HTTP);
}

export function construirCorreo({ purpose, code, username, expiresMinutes = 15 }) {
  const verificacion = purpose === 'verify';
  const asunto = verificacion
    ? 'Verifica tu cuenta — Caída Online'
    : 'Recupera tu contraseña — Caída Online';
  const accion = verificacion ? 'verificar tu cuenta' : 'cambiar tu contraseña';
  const titulo = verificacion ? 'Verifica tu cuenta' : 'Recupera tu clave';
  const intro = verificacion
    ? 'Estás a un paso de asegurar tu cuenta para las mesas online.'
    : 'Recibimos una solicitud para cambiar la contraseña de tu cuenta.';

  const texto = [
    `Hola ${username || 'jugador'},`,
    '',
    intro,
    '',
    `Tu código para ${accion}: ${code}`,
    '',
    `El código vence en ${expiresMinutes} minutos.`,
    'Si no solicitaste este mensaje, ignora el correo.',
    '',
    'Caída Online'
  ].join('\n');

  const html = `<!doctype html>
<html lang="es">
<body style="margin:0;background:#07100d;font-family:Arial,Helvetica,sans-serif;color:#f8f0de;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#07100d;padding:32px 12px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#0b2a21;border:1px solid #3d2a1c;border-radius:18px;overflow:hidden;">
        <tr><td style="padding:28px 32px 8px;">
          <div style="font-size:12px;letter-spacing:4px;color:#e8b04b;">CAÍDA ONLINE</div>
          <h1 style="margin:10px 0 0;font-size:30px;color:#fbf3e2;">${titulo}</h1>
          <p style="margin:12px 0 0;font-size:15px;line-height:1.5;color:#c9b99a;">${intro}</p>
        </td></tr>
        <tr><td align="center" style="padding:24px 32px;">
          <div style="display:inline-block;background:#f6e7c8;color:#25180f;border-radius:14px;padding:16px 28px;font-size:34px;letter-spacing:8px;font-weight:bold;">${code}</div>
        </td></tr>
        <tr><td style="padding:0 32px 28px;">
          <p style="margin:0;font-size:14px;line-height:1.5;color:#c9b99a;">Usa este código para ${accion}. Vence en <strong style="color:#fbf3e2;">${expiresMinutes} minutos</strong>.</p>
          <p style="margin:12px 0 0;font-size:13px;line-height:1.5;color:#8f9d92;">Si no solicitaste este mensaje, ignora el correo. Nadie de Caída Online te pedirá el código por chat.</p>
        </td></tr>
        <tr><td style="padding:18px 32px;background:#08271d;font-size:12px;color:#8f9d92;">
          Caída Online · 4 jugadores · 2 equipos · 24 puntos
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  return { subject: asunto, text: texto, html };
}

function errorHttp(mensaje, codigo, respuesta) {
  const error = new Error(mensaje);
  error.code = codigo;
  error.response = respuesta;
  return error;
}

async function enviarPorResend({ to, subject, text, html }) {
  const respuesta = await fetch(RESEND_API_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: MAIL_FROM,
      to: [to],
      subject,
      text,
      html,
      ...(SMTP_REPLY_TO ? { reply_to: SMTP_REPLY_TO } : {})
    }),
    signal: AbortSignal.timeout(MAIL_HTTP_TIMEOUT_MS)
  });

  const cuerpo = await respuesta.text();
  if (!respuesta.ok) {
    throw errorHttp(`Resend respondió HTTP ${respuesta.status}: ${cuerpo}`, `HTTP_${respuesta.status}`, cuerpo);
  }

  return { provider: 'resend', accepted: [to], response: cuerpo };
}

async function enviarPorBrevo({ to, subject, text, html }) {
  const respuesta = await fetch(BREVO_API_URL, {
    method: 'POST',
    headers: {
      'api-key': BREVO_API_KEY,
      'Content-Type': 'application/json',
      accept: 'application/json'
    },
    body: JSON.stringify({
      sender: { email: extraerEmail(MAIL_FROM), name: extraerNombre(MAIL_FROM) },
      to: [{ email: to }],
      subject,
      htmlContent: html,
      textContent: text,
      ...(SMTP_REPLY_TO ? { replyTo: { email: SMTP_REPLY_TO } } : {})
    }),
    signal: AbortSignal.timeout(MAIL_HTTP_TIMEOUT_MS)
  });

  const cuerpo = await respuesta.text();
  if (!respuesta.ok) {
    throw errorHttp(`Brevo respondió HTTP ${respuesta.status}: ${cuerpo}`, `HTTP_${respuesta.status}`, cuerpo);
  }

  return { provider: 'brevo', accepted: [to], response: cuerpo };
}

async function enviarCorreo({ to, subject, text, html }) {
  if (PROVEEDOR_HTTP === 'resend') return enviarPorResend({ to, subject, text, html });
  if (PROVEEDOR_HTTP === 'brevo') return enviarPorBrevo({ to, subject, text, html });

  if (!transporte) {
    throw new Error('No hay canal de correo configurado (SMTP o API HTTP).');
  }

  return transporte.sendMail({
    from: SMTP_FROM,
    to,
    replyTo: SMTP_REPLY_TO || undefined,
    subject,
    text,
    html
  });
}

export async function enviarCodigo({ to, code, purpose, username, expiresMinutes = 15 }) {
  if (!to) return { sent: false, dev: false, error: 'La cuenta no tiene correo.' };

  if (!mailerConfigurado()) {
    if (!PRODUCCION) {
      console.log(`[seguridad] código ${purpose} para ${username || to} (${to}): ${code}`);
      return { sent: false, dev: true };
    }
    console.error('[MAIL_ERROR] No hay canal de correo configurado (SMTP o API HTTP).');
    return { sent: false, dev: false, error: 'El envío de correos no está configurado.' };
  }

  const correo = construirCorreo({ purpose, code, username, expiresMinutes });

  try {
    const info = await enviarCorreo({
      to,
      subject: correo.subject,
      text: correo.text,
      html: correo.html
    });

    // Información devuelta por el proveedor (SMTP, Resend o Brevo).
    console.log('[seguridad] sendMail info:', info);
    console.log(`[MAIL_OK] correo ${purpose} aceptado por ${PROVEEDOR_HTTP || 'smtp'} para ${to}`);

    if (Array.isArray(info.rejected) && info.rejected.length > 0) {
      console.warn('[seguridad] sendMail destinatarios rechazados:', info.rejected);
    }
    if (Array.isArray(info.accepted) && info.accepted.length === 0) {
      console.warn('[seguridad] sendMail no aceptó ningún destinatario:', info.accepted);
    }

    return { sent: true, dev: false, info };
  } catch (error) {
    // Log completo con stack para diagnosticar en Render.
    console.error('[MAIL_ERROR]', error);
    console.error('[seguridad] sendMail falló:', {
      provider: PROVEEDOR_HTTP || 'smtp',
      code: error.code,
      responseCode: error.responseCode,
      command: error.command,
      response: error.response,
      message: error.message
    });
    return { sent: false, dev: false, error: 'No se pudo enviar el correo.' };
  }
}

export async function enviarAlerta({ subject, text }) {
  if (!ALERT_EMAIL || !mailerConfigurado()) return false;

  try {
    const info = await enviarCorreo({
      to: ALERT_EMAIL,
      subject: '[Caída Online] ' + subject,
      text,
      html: undefined
    });
    console.log('[seguridad] sendMail alerta info:', info);
    return true;
  } catch (error) {
    console.error('[MAIL_ERROR]', error);
    console.error('[seguridad] no se pudo enviar la alerta:', {
      provider: PROVEEDOR_HTTP || 'smtp',
      code: error.code,
      responseCode: error.responseCode,
      response: error.response,
      message: error.message
    });
    return false;
  }
}
