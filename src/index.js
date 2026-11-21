import './env.js';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
import { createClient } from 'redis';
import QRCode from 'qrcode';
import { BaseDatos, validarCredenciales, normalizarUsuario } from './db.js';
import { PartidaCaida } from './game.js';
import {
  RateLimiter,
  crearLimitador,
  generarSecretoTotp,
  ipDeRequest,
  politicaVerificacion,
  urlTotp,
  validarEmail,
  validarPassword,
  verificarTotp
} from './security.js';
import { configurarMailer, enviarCodigo } from './mailer.js';
import { configurarAuditoria, auditar } from './audit.js';
import { paginaAuditoria } from './admin.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUERTO = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'caida.db');
const ORIGENES_PERMITIDOS = String(process.env.CORS_ORIGIN || '*').split(',').map((o) => o.trim()).filter(Boolean);
const TURNO_MS = Number(process.env.TURN_MS || 30000);
const ESPERA_RECONEXION_MS = Number(process.env.RECONNECT_MS || 45000);
const TLS_CERT = process.env.TLS_CERT || '';
const TLS_KEY = process.env.TLS_KEY || '';
const TRUST_PROXY = process.env.TRUST_PROXY === '1' || process.env.RENDER === 'true';
const DEV_CODES = process.env.DEV_CODES === '1';
const REQUIRE_EMAIL = process.env.REQUIRE_EMAIL === '1';
const REQUIRE_VERIFIED = process.env.REQUIRE_VERIFIED === '1';
const API_POR_MINUTO = Number(process.env.API_RATE_MAX || 300);
const AUTH_POR_MINUTO = Number(process.env.AUTH_RATE_MAX || 30);
const FALLOS_LOGIN_MAX = Number(process.env.LOGIN_FAIL_MAX || 8);
const WS_POR_VENTANA = Number(process.env.WS_RATE_MAX || 60);
const WS_VENTANA_MS = Number(process.env.WS_RATE_WINDOW_MS || 10000);
const VERIFY_AFTER_MATCHES = Number(process.env.VERIFY_AFTER_MATCHES || 0);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const ALERT_FAIL_THRESHOLD = Number(process.env.ALERT_FAIL_THRESHOLD || 3);
const AUDIT_RETENTION_DAYS = Number(process.env.AUDIT_RETENTION_DAYS || 90);
const TOTP_EMISOR = process.env.TOTP_ISSUER || 'Caída Online';

function minutosCodigo(valor, defecto = 15) {
  const numero = Number(valor || defecto);
  if (!Number.isFinite(numero)) return defecto;
  // El código de recuperación/verificación nunca dura menos de 15 minutos.
  return Math.max(15, Math.floor(numero));
}

const RECOVERY_CODE_TTL_MIN = minutosCodigo(process.env.RECOVERY_CODE_TTL_MIN, 15);
const VERIFY_CODE_TTL_MIN = minutosCodigo(process.env.VERIFY_CODE_TTL_MIN, 15);
const RECOVERY_CODE_TTL_MS = RECOVERY_CODE_TTL_MIN * 60 * 1000;
const VERIFY_CODE_TTL_MS = VERIFY_CODE_TTL_MIN * 60 * 1000;
const MAX_CUERPO_BYTES = 32 * 1024;
const SEGURO = Boolean(TLS_CERT && TLS_KEY);

const db = new BaseDatos(DB_PATH);
configurarAuditoria(db);
const salas = new Map();
const salaPorUsuario = new Map();
const cola = [];
const socketsPorUsuario = new Map();

async function crearRedis() {
  const url = process.env.REDIS_URL || '';
  if (!url) return null;
  const cliente = createClient({
    url,
    socket: {
      connectTimeout: 3000,
      reconnectStrategy: (intentos) => (intentos > 5 ? false : Math.min(intentos * 250, 2000))
    }
  });
  cliente.on('error', (error) => console.warn('[redis]', error.message));
  try {
    await cliente.connect();
    console.log('[redis] conectado: rate limiting distribuido activo.');
    return cliente;
  } catch (error) {
    console.warn('[redis] no disponible, se usa rate limiting local:', error.message);
    try { await cliente.disconnect(); } catch { /* ignore */ }
    return null;
  }
}

const clienteRedis = await crearRedis();

const limitadorApi = crearLimitador({ clienteRedis, max: API_POR_MINUTO, windowMs: 60_000, nombre: 'api' });
const limitadorAuth = crearLimitador({ clienteRedis, max: AUTH_POR_MINUTO, windowMs: 60_000, nombre: 'auth' });
const limitadorFallosLogin = crearLimitador({ clienteRedis, max: FALLOS_LOGIN_MAX, windowMs: 15 * 60_000, nombre: 'login' });

const RUTAS_AUTH = new Set([
  '/api/register',
  '/api/login',
  '/api/login/2fa',
  '/api/account/email',
  '/api/verify/request',
  '/api/verify',
  '/api/recovery/request',
  '/api/recovery/reset',
  '/api/recover',
  '/api/recover/verify',
  '/api/2fa/setup',
  '/api/2fa/enable',
  '/api/2fa/disable',
  '/api/2fa/recovery'
]);

configurarMailer();

function iniciarSesionHttp(user, res, ip, userAgent, detalle = {}) {
  const acceso = db.datosAcceso(user.id);
  const token = db.crearSesion(user.id);
  db.actualizarUltimoAcceso(user.id, ip);
  auditar({
    event: 'login_ok',
    userId: user.id,
    username: user.username,
    ip,
    userAgent,
    detail: detalle
  });
  if (acceso?.lastLoginAt && acceso.lastIp && acceso.lastIp !== ip) {
    auditar({
      event: 'login_new_ip',
      severity: 'warn',
      userId: user.id,
      username: user.username,
      ip,
      userAgent,
      detail: { ipAnterior: acceso.lastIp, ipNueva: ip }
    });
  }
  return responder(res, 200, { token, user });
}

async function manejarHttp(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const seguro = SEGURO || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');
    aplicarCors(req, res);
    aplicarCabecerasSeguridad(res, seguro, url.pathname);
    if (req.method === 'OPTIONS') return responder(res, 204, null);

    const ip = ipDeRequest(req, TRUST_PROXY);
    const userAgent = req.headers['user-agent'] || null;
    if (req.method !== 'GET' || url.pathname.startsWith('/api/')) {
      if (url.pathname !== '/api/health' && url.pathname.startsWith('/api/')) {
        const limite = await limitadorApi.hit(ip);
        if (!limite.ok) {
          auditar({ event: 'rate_limited_api', severity: 'warn', ip, userAgent, detail: { path: url.pathname } });
          return responder(res, 429, {
            error: 'Demasiadas solicitudes. Espera un momento e inténtalo de nuevo.',
            code: 'RATE_LIMITED'
          }, { 'Retry-After': String(limite.retryAfter) });
        }
      }
      if (RUTAS_AUTH.has(url.pathname)) {
        const limite = await limitadorAuth.hit(ip);
        if (!limite.ok) {
          auditar({ event: 'auth_rate_limited', severity: 'critical', ip, userAgent, detail: { path: url.pathname } });
          return responder(res, 429, {
            error: 'Demasiados intentos. Espera un minuto antes de volver a probar.',
            code: 'AUTH_RATE_LIMITED'
          }, { 'Retry-After': String(limite.retryAfter) });
        }
      }
    }

    if (req.method === 'GET' && url.pathname === '/api/health') {
      return responder(res, 200, { ok: true, service: 'caida-online', version: '1.0.0', rooms: salas.size, queue: cola.length, secure: seguro });
    }

    if (req.method === 'POST' && url.pathname === '/api/register') {
      const body = await leerJson(req);
      const error = validarCredenciales(body.username, body.password);
      if (error) return responder(res, 400, { error });
      const email = body.email ? String(body.email).trim() : null;
      if (email) {
        const errorEmail = validarEmail(email);
        if (errorEmail) return responder(res, 400, { error: errorEmail });
      } else if (REQUIRE_EMAIL) {
        return responder(res, 400, { error: 'Escribe un correo electrónico para registrarte.' });
      }
      try {
        const user = db.crearUsuario(String(body.username).trim(), String(body.password), email);
        const token = db.crearSesion(user.id);
        const verification = user.email ? await enviarCodigoVerificacion(user) : { ok: true, sent: false };
        auditar({
          event: 'register',
          userId: user.id,
          username: user.username,
          ip,
          userAgent,
          detail: { email: !!user.email }
        });
        return responder(res, 201, { token, user, verification });
      } catch (e) {
        return responder(res, 409, { error: e.message, code: e.code || 'REGISTER_ERROR' });
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const body = await leerJson(req);
      const alias = String(body.username || '');
      const claveFallos = `${ip}:${normalizarUsuario(alias)}`;
      const user = db.verificarCredenciales(alias, body.password || '');
      if (!user) {
        const fallos = await limitadorFallosLogin.hit(claveFallos);
        const severidad = !fallos.ok ? 'critical' : (fallos.restantes <= ALERT_FAIL_THRESHOLD ? 'warn' : 'info');
        auditar({
          event: fallos.ok ? 'login_fail' : 'login_blocked',
          severity: severidad,
          username: alias,
          ip,
          userAgent,
          detail: { intentosRestantes: fallos.restantes }
        });
        if (!fallos.ok) {
          return responder(res, 429, {
            error: 'Demasiados intentos fallidos. Espera 15 minutos o recupera tu contraseña.',
            code: 'LOGIN_BLOCKED'
          }, { 'Retry-After': String(fallos.retryAfter) });
        }
        return responder(res, 401, { error: 'Alias o contraseña incorrectos.', code: 'BAD_CREDENTIALS' });
      }
      await limitadorFallosLogin.reset(claveFallos);

      if (user.totpEnabled) {
        const challengeToken = db.crearDesafioLogin(user.id);
        auditar({
          event: 'login_2fa_required',
          userId: user.id,
          username: user.username,
          ip,
          userAgent,
          detail: { challenge: true }
        });
        return responder(res, 200, {
          requires2fa: true,
          challengeToken,
          username: user.username
        });
      }

      return iniciarSesionHttp(user, res, ip, userAgent, { metodo: 'password' });
    }

    if (req.method === 'POST' && url.pathname === '/api/login/2fa') {
      const body = await leerJson(req);
      const desafio = db.desafioLogin(body.challengeToken);
      if (!desafio) {
        return responder(res, 401, { error: 'El desafío venció. Inicia sesión de nuevo.', code: 'BAD_2FA_CHALLENGE' });
      }
      const user = db.usuarioPorId(desafio.user_id);
      const datos = db.datosTotp(desafio.user_id);
      if (!user || !datos?.enabled || !datos.secret) {
        db.borrarDesafio(desafio.token);
        return responder(res, 401, { error: 'La verificación en dos pasos no está disponible.', code: 'BAD_2FA_CHALLENGE' });
      }

      const codigo = String(body.code || '').trim();
      const validoTotp = verificarTotp(datos.secret, codigo);
      const validoRecuperacion = !validoTotp && db.consumirCodigoRecuperacion(user.id, codigo);
      if (!validoTotp && !validoRecuperacion) {
        const intentos = db.fallarDesafio(desafio.token);
        auditar({
          event: 'login_2fa_fail',
          severity: intentos >= 3 ? 'critical' : 'warn',
          userId: user.id,
          username: user.username,
          ip,
          userAgent,
          detail: { intentos }
        });
        return responder(res, 401, {
          error: intentos >= 5
            ? 'Demasiados intentos. Inicia sesión de nuevo.'
            : 'Código de verificación incorrecto.',
          code: 'BAD_2FA_CODE'
        });
      }

      db.borrarDesafio(desafio.token);
      if (validoRecuperacion) {
        auditar({
          event: 'login_recovery_code',
          severity: 'warn',
          userId: user.id,
          username: user.username,
          ip,
          userAgent
        });
      }
      return iniciarSesionHttp(user, res, ip, userAgent, {
        metodo: validoRecuperacion ? 'recovery_code' : 'totp'
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/me') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      return responder(res, 200, { user, stats: db.estadisticasUsuario(user.id) });
    }

    if (req.method === 'POST' && url.pathname === '/api/account/email') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const errorEmail = validarEmail(body.email);
      if (errorEmail) return responder(res, 400, { error: errorEmail });
      if (!body.password) return responder(res, 400, { error: 'Confirma tu contraseña para cambiar el correo.' });
      const credenciales = db.verificarCredenciales(user.username, String(body.password));
      if (!credenciales) return responder(res, 401, { error: 'Contraseña incorrecta.', code: 'BAD_CREDENTIALS' });
      try {
        const actualizado = db.actualizarEmail(user.id, body.email);
        const verification = await enviarCodigoVerificacion(actualizado);
        auditar({
          event: 'email_changed',
          severity: 'warn',
          userId: user.id,
          username: user.username,
          ip,
          userAgent,
          detail: { email: actualizado.email }
        });
        return responder(res, 200, { user: actualizado, verification });
      } catch (e) {
        return responder(res, 409, { error: e.message, code: e.code || 'EMAIL_ERROR' });
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/verify/request') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      if (!user.email) return responder(res, 400, { error: 'Primero agrega un correo a tu cuenta.' });
      if (user.verified) return responder(res, 200, { ok: true, alreadyVerified: true });
      const verification = await enviarCodigoVerificacion(user);
      return responder(res, 200, { ok: true, verification });
    }

    if (req.method === 'POST' && url.pathname === '/api/verify') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const resultado = db.consumirCodigo(user.id, 'verify', body.code);
      if (!resultado.ok) return responder(res, 400, { error: resultado.error, code: 'BAD_CODE' });
      const verificado = db.marcarVerificado(user.id);
      auditar({ event: 'account_verified', userId: user.id, username: user.username, ip, userAgent });
      return responder(res, 200, { ok: true, user: verificado });
    }

    if (req.method === 'POST' && (url.pathname === '/api/recovery/request' || url.pathname === '/api/recover')) {
      const body = await leerJson(req);
      const user = db.usuarioPorIdentificador(body.identifier);
      let devCode;

      console.log('[recovery] solicitud recibida', {
        identificador: String(body.identifier || '').trim().slice(0, 3) + '***',
        cuentaEncontrada: !!user,
        tieneCorreo: !!user?.email
      });

      if (user && user.email) {
        const { codigo } = db.crearCodigo(user.id, 'reset', RECOVERY_CODE_TTL_MS);
        if (DEV_CODES) devCode = codigo;

        // Fire-and-forget: el correo sale por detrás y la respuesta HTTP no espera.
        console.log(`[recovery] correo encolado para ${user.username}`);
        enviarCodigo({
          to: user.email,
          code: codigo,
          purpose: 'reset',
          username: user.username,
          expiresMinutes: RECOVERY_CODE_TTL_MIN
        }).then((envio) => {
          auditar({
            event: envio.sent ? 'recovery_email_sent' : 'recovery_email_failed',
            severity: envio.sent ? 'info' : 'warn',
            userId: user.id,
            username: user.username,
            ip,
            userAgent,
            detail: { sent: !!envio.sent, dev: !!envio.dev, error: envio.error || null }
          });
        }).catch((error) => {
          console.error('[MAIL_ERROR]', error);
          auditar({
            event: 'recovery_email_failed',
            severity: 'warn',
            userId: user.id,
            username: user.username,
            ip,
            userAgent,
            detail: { error: error.message }
          });
        });
      }

      auditar({
        event: 'password_reset_requested',
        severity: 'warn',
        userId: user?.id ?? null,
        username: user?.username ?? null,
        ip,
        userAgent,
        detail: { cuentaEncontrada: !!user, conCorreo: !!user?.email }
      });

      return responder(res, 200, {
        ok: true,
        success: true,
        queued: true,
        sent: true,
        message: 'Código enviado. Revisa tu correo (puede tardar un minuto en llegar).',
        expiresInMinutes: RECOVERY_CODE_TTL_MIN,
        ...(devCode ? { devCode } : {})
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/recovery/reset') {
      const body = await leerJson(req);
      const errorPassword = validarPassword(body.password);
      if (errorPassword) return responder(res, 400, { error: errorPassword });
      const user = db.usuarioPorIdentificador(body.identifier);
      if (!user) return responder(res, 400, { error: 'Código inválido o expirado.', code: 'BAD_CODE' });
      const resultado = db.consumirCodigo(user.id, 'reset', body.code);
      if (!resultado.ok) return responder(res, 400, { error: resultado.error, code: 'BAD_CODE' });
      db.actualizarPassword(user.id, String(body.password));
      auditar({
        event: 'password_reset_ok',
        severity: 'warn',
        userId: user.id,
        username: user.username,
        ip,
        userAgent
      });
      return responder(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/recover/verify') {
      const body = await leerJson(req);
      const user = db.usuarioPorIdentificador(body.identifier);
      if (!user) return responder(res, 400, { error: 'Código inválido o expirado.', code: 'BAD_CODE' });
      const resultado = db.verificarCodigo(user.id, 'reset', body.code);
      if (!resultado.ok) {
        auditar({
          event: 'recover_verify_fail',
          severity: 'warn',
          userId: user.id,
          username: user.username,
          ip,
          userAgent
        });
        return responder(res, 400, { error: resultado.error, code: 'BAD_CODE' });
      }
      auditar({ event: 'recover_verify_ok', userId: user.id, username: user.username, ip, userAgent });
      return responder(res, 200, { ok: true, valid: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/2fa/setup') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const datos = db.datosTotp(user.id);
      if (datos?.enabled) return responder(res, 409, { error: 'La verificación en dos pasos ya está activa.', code: '2FA_ALREADY_ENABLED' });
      const secreto = generarSecretoTotp();
      db.guardarTotpPendiente(user.id, secreto);
      const otpauth = urlTotp(secreto, user.username, TOTP_EMISOR);
      let qr = null;
      try {
        qr = await QRCode.toDataURL(otpauth, {
          margin: 1,
          width: 260,
          errorCorrectionLevel: 'M',
          color: { dark: '#0B2A21', light: '#F6E7C8' }
        });
      } catch (error) {
        console.warn('[2fa] no se pudo generar el QR:', error.message);
      }
      auditar({ event: '2fa_setup_started', userId: user.id, username: user.username, ip, userAgent });
      return responder(res, 200, {
        ok: true,
        secret: secreto,
        otpauth,
        qr
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/2fa/enable') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const datos = db.datosTotp(user.id);
      if (datos?.enabled) return responder(res, 409, { error: 'La verificación en dos pasos ya está activa.', code: '2FA_ALREADY_ENABLED' });
      if (!datos?.pending) return responder(res, 400, { error: 'Primero inicia la configuración de 2FA.', code: '2FA_NOT_STARTED' });
      if (!verificarTotp(datos.pending, body.code)) {
        auditar({ event: '2fa_enable_fail', severity: 'warn', userId: user.id, username: user.username, ip, userAgent });
        return responder(res, 400, { error: 'El código de 6 dígitos no es válido.', code: 'BAD_2FA_CODE' });
      }
      db.activarTotp(user.id, datos.pending);
      const recoveryCodes = db.crearCodigosRecuperacion(user.id);
      const actualizado = db.usuarioPorId(user.id);
      auditar({ event: '2fa_enabled', userId: user.id, username: user.username, ip, userAgent });
      return responder(res, 200, { ok: true, user: actualizado, recoveryCodes });
    }

    if (req.method === 'POST' && url.pathname === '/api/2fa/disable') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const datos = db.datosTotp(user.id);
      if (!datos?.enabled || !datos.secret) {
        return responder(res, 409, { error: 'La verificación en dos pasos no está activa.', code: '2FA_NOT_ENABLED' });
      }
      const clave = String(body.code || '').trim();
      const porTotp = verificarTotp(datos.secret, clave);
      const porRecuperacion = !porTotp && db.consumirCodigoRecuperacion(user.id, clave);
      if (!porTotp && !porRecuperacion) {
        auditar({ event: '2fa_disable_fail', severity: 'warn', userId: user.id, username: user.username, ip, userAgent });
        return responder(res, 400, { error: 'El código no es válido.', code: 'BAD_2FA_CODE' });
      }
      db.desactivarTotp(user.id);
      const actualizado = db.usuarioPorId(user.id);
      auditar({
        event: porRecuperacion ? '2fa_disabled_recovery' : '2fa_disabled',
        severity: 'warn',
        userId: user.id,
        username: user.username,
        ip,
        userAgent
      });
      return responder(res, 200, { ok: true, user: actualizado });
    }

    if (req.method === 'POST' && url.pathname === '/api/2fa/recovery') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const datos = db.datosTotp(user.id);
      if (!datos?.enabled || !datos.secret) {
        return responder(res, 409, { error: 'La verificación en dos pasos no está activa.', code: '2FA_NOT_ENABLED' });
      }
      const clave = String(body.code || '').trim();
      const porTotp = verificarTotp(datos.secret, clave);
      const porRecuperacion = !porTotp && db.consumirCodigoRecuperacion(user.id, clave);
      if (!porTotp && !porRecuperacion) {
        auditar({ event: '2fa_recovery_fail', severity: 'warn', userId: user.id, username: user.username, ip, userAgent });
        return responder(res, 400, { error: 'El código no es válido.', code: 'BAD_2FA_CODE' });
      }
      const recoveryCodes = db.crearCodigosRecuperacion(user.id);
      auditar({
        event: porRecuperacion ? '2fa_recovery_regenerated_with_code' : '2fa_recovery_regenerated',
        severity: 'warn',
        userId: user.id,
        username: user.username,
        ip,
        userAgent
      });
      return responder(res, 200, { ok: true, recoveryCodes });
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/audit') {
      if (!ADMIN_TOKEN) return responder(res, 404, { error: 'Ruta no encontrada.' });
      const recibido = String(req.headers['x-admin-token'] || '');
      const a = Buffer.from(recibido);
      const b = Buffer.from(ADMIN_TOKEN);
      const valido = a.length === b.length && timingSafeEqual(a, b);
      if (!valido) return responder(res, 401, { error: 'Token de administración inválido.', code: 'UNAUTHORIZED' });
      const limite = Number(url.searchParams.get('limit') || 100);
      auditar({ event: 'admin_audit_read', ip, userAgent, detail: { limite } });
      return responder(res, 200, { audit: db.listarAuditoria(limite) });
    }

    if (req.method === 'GET' && url.pathname === '/api/ranking') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const limite = Number(url.searchParams.get('limit') || 20);
      return responder(res, 200, { ranking: db.ranking(limite) });
    }

    if (req.method === 'GET' && url.pathname === '/api/history') {
      const user = usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const limite = Number(url.searchParams.get('limit') || 20);
      return responder(res, 200, { history: db.historialUsuario(user.id, limite) });
    }

    if (req.method === 'POST' && url.pathname === '/api/logout') {
      const auth = leerBearer(req);
      db.revocarSesion(auth);
      return responder(res, 200, { ok: true });
    }

    if (req.method === 'GET' && url.pathname === '/admin/auditoria') {
      if (!ADMIN_TOKEN) return responder(res, 404, { error: 'Ruta no encontrada.' });
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
      res.setHeader('Cache-Control', 'no-store');
      res.end(paginaAuditoria());
      return;
    }

    return responder(res, 404, { error: 'Ruta no encontrada.' });
  } catch (error) {
    if (error && error.code === 'BODY_TOO_LARGE') {
      return responder(res, 413, { error: 'La solicitud es demasiado grande.', code: 'BODY_TOO_LARGE' });
    }
    if (error && error.code === 'INVALID_JSON') {
      return responder(res, 400, { error: 'JSON inválido.', code: 'INVALID_JSON' });
    }
    console.error('[http]', error);
    return responder(res, 500, { error: 'Error interno del servidor.' });
  }
}

const servidor = SEGURO
  ? https.createServer({ key: readFileSync(TLS_KEY), cert: readFileSync(TLS_CERT) }, manejarHttp)
  : http.createServer(manejarHttp);

const wss = new WebSocketServer({ noServer: true });

servidor.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (url.pathname !== '/ws') {
    socket.destroy();
    return;
  }
  const token = url.searchParams.get('token') || '';
  const user = db.usuarioPorToken(token);
  if (!user) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.usuario = user;
    ws.token = token;
    ws.ip = ipDeRequest(req, TRUST_PROXY);
    ws.userAgent = req.headers['user-agent'] || null;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws) => {
  const user = ws.usuario;
  ws.estaVivo = true;
  ws.on('pong', () => { ws.estaVivo = true; });

  const anteriores = socketsPorUsuario.get(user.id) || new Set();
  for (const anterior of anteriores) {
    if (anterior !== ws) anterior.close(4000, 'Sesión abierta en otro dispositivo');
  }
  anteriores.add(ws);
  socketsPorUsuario.set(user.id, anteriores);

  enviar(ws, 'hello', { user });
  console.log(`[ws] conectado #${user.id} ${user.username}`);

  const sala = salaDeUsuario(user.id);
  if (sala) {
    const jugador = sala.players.find((p) => p && p.userId === user.id);
    if (jugador) {
      jugador.socket = ws;
      jugador.connected = true;
      jugador.reconnectedAt = Date.now();
      enviarSala(sala, 'roomState');
      enviarEstado(sala);
    }
  }

  const enCola = cola.find((q) => q.userId === user.id);
  if (enCola) {
    enCola.socket = ws;
    enviar(ws, 'queue', { count: cola.length, position: cola.indexOf(enCola) + 1 });
  }

  const limiteWs = new RateLimiter({ max: WS_POR_VENTANA, windowMs: WS_VENTANA_MS, nombre: 'ws' });
  ws.on('message', (data) => {
    const limite = limiteWs.hit('ws');
    if (!limite.ok) {
      enviarError(ws, 'Demasiados mensajes. La conexión se cerrará.');
      ws.close(4008, 'Demasiados mensajes');
      return;
    }
    manejarMensaje(ws, data);
  });
  ws.on('close', () => desconectar(ws));
  ws.on('error', (error) => console.warn('[ws] error', error.message));
});

function manejarMensaje(ws, data) {
  let mensaje;
  try {
    mensaje = JSON.parse(String(data));
  } catch {
    return enviarError(ws, 'Mensaje inválido.');
  }
  if (!mensaje || typeof mensaje.type !== 'string') return enviarError(ws, 'Falta el tipo de mensaje.');

  const user = ws.usuario;
  switch (mensaje.type) {
    case 'ping':
      return enviar(ws, 'pong', { t: Date.now() });
    case 'quickMatch':
      return buscarPartida(ws);
    case 'cancelQueue':
      return salirDeCola(user.id, ws);
    case 'createRoom':
      return crearSalaPrivada(ws);
    case 'joinRoom':
      return unirseSala(ws, mensaje.code);
    case 'startRoom':
      return iniciarSala(ws);
    case 'leaveRoom':
      return salirDeSala(ws);
    case 'playCard':
      return jugarCarta(ws, mensaje.cardId);
    case 'voteTribilin':
      return votarTribilin(ws, mensaje.vote);
    case 'sync':
      return sincronizar(ws);
    default:
      return enviarError(ws, 'Tipo de mensaje desconocido.');
  }
}

function verificarCuentaParaJugar(ws) {
  if (!REQUIRE_VERIFIED && VERIFY_AFTER_MATCHES <= 0) return true;
  const actual = db.usuarioPorId(ws.usuario.id);
  if (!actual) {
    enviarError(ws, 'Sesión inválida.', 'UNAUTHORIZED');
    return false;
  }
  const stats = db.estadisticasUsuario(actual.id);
  const politica = politicaVerificacion({
    verified: actual.verified,
    games: stats.games,
    requireVerified: REQUIRE_VERIFIED,
    afterMatches: VERIFY_AFTER_MATCHES
  });
  if (!politica.ok) {
    auditar({
      event: 'play_blocked_unverified',
      severity: 'warn',
      userId: actual.id,
      username: actual.username,
      ip: ws.ip,
      userAgent: ws.userAgent,
      detail: { games: stats.games, requireVerified: REQUIRE_VERIFIED, afterMatches: VERIFY_AFTER_MATCHES }
    });
    enviarError(ws, politica.motivo, 'VERIFY_REQUIRED');
    return false;
  }
  return true;
}

function buscarPartida(ws) {
  const user = ws.usuario;
  if (!verificarCuentaParaJugar(ws)) return;
  const actual = salaDeUsuario(user.id);
  if (actual) return enviarError(ws, 'Ya estás en una sala.');
  if (cola.some((q) => q.userId === user.id)) {
    const pos = cola.findIndex((q) => q.userId === user.id);
    return enviar(ws, 'queue', { count: cola.length, position: pos + 1 });
  }

  cola.push({ userId: user.id, name: user.username, socket: ws });
  difundirCola();

  for (let i = cola.length - 1; i >= 0; i--) {
    const q = cola[i];
    if (!q.socket || q.socket.readyState !== WebSocket.OPEN) cola.splice(i, 1);
  }

  if (cola.length >= 4) {
    const listos = cola.splice(0, 4);
    const sala = crearSala('quick');
    for (let i = 0; i < 4; i++) {
      const jugador = listos[i];
      const existente = socketsPorUsuario.get(jugador.userId)?.values().next().value;
      if (!existente || existente.readyState !== WebSocket.OPEN) continue;
      sala.players[i] = {
        seat: i,
        userId: jugador.userId,
        name: jugador.name,
        socket: existente,
        connected: true,
        reconnectedAt: null
      };
      salaPorUsuario.set(jugador.userId, sala.code);
    }
    iniciarPartida(sala);
  }
}

function salirDeCola(userId, ws = null) {
  const indice = cola.findIndex((q) => q.userId === userId);
  if (indice >= 0) cola.splice(indice, 1);
  if (ws) enviar(ws, 'queue', { count: cola.length, position: 0, cancelled: true });
  difundirCola();
}

function crearSalaPrivada(ws) {
  const user = ws.usuario;
  if (!verificarCuentaParaJugar(ws)) return;
  if (salaDeUsuario(user.id)) return enviarError(ws, 'Ya estás en una sala.');
  salirDeCola(user.id, ws);
  const sala = crearSala('private');
  sala.hostUserId = user.id;
  sala.players[0] = {
    seat: 0,
    userId: user.id,
    name: user.username,
    socket: ws,
    connected: true,
    reconnectedAt: null
  };
  salaPorUsuario.set(user.id, sala.code);
  console.log(`[sala] ${sala.code} creada por ${user.username}`);
  difundirSala(sala);
}

function unirseSala(ws, codigo) {
  const code = String(codigo || '').trim().toUpperCase();
  if (!code) return enviarError(ws, 'Escribe un código de sala.');
  if (!verificarCuentaParaJugar(ws)) return;
  if (salaDeUsuario(ws.usuario.id)) return enviarError(ws, 'Ya estás en una sala.');
  const sala = salas.get(code);
  if (!sala) return enviarError(ws, 'La sala no existe o ya terminó.');
  if (sala.status !== 'waiting') return enviarError(ws, 'La partida ya comenzó.');
  const libre = sala.players.findIndex((p) => !p);
  if (libre < 0) return enviarError(ws, 'La sala está llena.');
  salirDeCola(ws.usuario.id, ws);
  sala.players[libre] = {
    seat: libre,
    userId: ws.usuario.id,
    name: ws.usuario.username,
    socket: ws,
    connected: true,
    reconnectedAt: null
  };
  salaPorUsuario.set(ws.usuario.id, sala.code);
  console.log(`[sala] ${code} + ${ws.usuario.username}`);
  difundirSala(sala);
}

function iniciarSala(ws) {
  const sala = salaDeUsuario(ws.usuario.id);
  if (!sala) return enviarError(ws, 'No estás en una sala.');
  if (sala.hostUserId !== ws.usuario.id) return enviarError(ws, 'Solo el anfitrión puede iniciar.');
  if (sala.status !== 'waiting') return enviarError(ws, 'La partida ya comenzó.');
  const ocupados = sala.players.filter(Boolean);
  if (ocupados.length !== 4) return enviarError(ws, 'Faltan jugadores: ' + ocupados.length + '/4.');
  if (ocupados.some((p) => !p.connected)) return enviarError(ws, 'Hay jugadores desconectados.');
  iniciarPartida(sala);
}

function jugarCarta(ws, cardId) {
  const sala = salaDeUsuario(ws.usuario.id);
  if (!sala || !sala.game) return enviarError(ws, 'No hay una partida activa.');
  const jugador = sala.players.find((p) => p && p.userId === ws.usuario.id);
  if (!jugador) return enviarError(ws, 'No estás sentado en esta mesa.');
  const resultado = sala.game.jugar(jugador.seat, String(cardId || ''));
  if (!resultado.ok) return enviarError(ws, resultado.error);
  sala.deadline = Date.now() + TURNO_MS;
  difundirEstado(sala);
}

function votarTribilin(ws, voto) {
  const sala = salaDeUsuario(ws.usuario.id);
  if (!sala || !sala.game) return enviarError(ws, 'No hay una partida activa.');
  const jugador = sala.players.find((p) => p && p.userId === ws.usuario.id);
  if (!jugador) return enviarError(ws, 'No estás sentado en esta mesa.');
  const resultado = sala.game.votar(jugador.seat, Number(voto));
  if (!resultado.ok) return enviarError(ws, resultado.error);
  if (sala.game.phase === 'playing') sala.deadline = Date.now() + TURNO_MS;
  difundirEstado(sala);
}

function sincronizar(ws) {
  const sala = salaDeUsuario(ws.usuario.id);
  if (sala) {
    enviarSala(sala, 'roomState');
    enviarEstado(sala);
  } else {
    enviar(ws, 'noRoom', {});
  }
}

function salirDeSala(ws) {
  const user = ws.usuario;
  const sala = salaDeUsuario(user.id);
  if (!sala) return enviar(ws, 'noRoom', {});

  if (sala.status === 'waiting') {
    const jugador = sala.players.find((p) => p && p.userId === user.id);
    if (jugador) sala.players[jugador.seat] = null;
    salaPorUsuario.delete(user.id);
    if (sala.hostUserId === user.id) {
      const siguiente = sala.players.find(Boolean);
      sala.hostUserId = siguiente ? siguiente.userId : null;
    }
    if (!sala.players.some(Boolean)) {
      salas.delete(sala.code);
    } else {
      difundirSala(sala);
    }
  } else {
    const jugador = sala.players.find((p) => p && p.userId === user.id);
    if (jugador) {
      jugador.connected = false;
      jugador.leftAt = Date.now();
      jugador.socket = null;
    }
    salaPorUsuario.delete(user.id);
    difundirSala(sala);
    enviar(ws, 'leftRoom', {});
  }
}

function desconectar(ws) {
  const user = ws.usuario;
  const sets = socketsPorUsuario.get(user.id);
  if (sets) {
    sets.delete(ws);
    if (!sets.size) socketsPorUsuario.delete(user.id);
  }

  salirDeCola(user.id);

  const sala = salaDeUsuario(user.id);
  if (!sala) return;
  const jugador = sala.players.find((p) => p && p.userId === user.id);
  if (!jugador || jugador.socket !== ws) return;

  jugador.connected = false;
  jugador.disconnectedAt = Date.now();
  jugador.socket = null;
  difundirSala(sala);

  if (sala.status === 'waiting') {
    setTimeout(() => {
      const actual = salas.get(sala.code);
      if (!actual || actual.status !== 'waiting') return;
      const p = actual.players.find((x) => x && x.userId === user.id);
      if (p && !p.connected) {
        actual.players[p.seat] = null;
        salaPorUsuario.delete(user.id);
        if (actual.hostUserId === user.id) {
          const siguiente = actual.players.find(Boolean);
          actual.hostUserId = siguiente ? siguiente.userId : null;
        }
        if (!actual.players.some(Boolean)) salas.delete(actual.code);
        else difundirSala(actual);
      }
    }, ESPERA_RECONEXION_MS);
  }
}

function crearSala(tipo) {
  let code;
  do code = generarCodigo(); while (salas.has(code));
  const sala = {
    code,
    id: randomUUID(),
    tipo,
    status: 'waiting',
    hostUserId: null,
    players: [null, null, null, null],
    createdAt: Date.now(),
    startedAt: null,
    finishedAt: null,
    game: null,
    deadline: 0,
    voteDeadline: 0
  };
  salas.set(code, sala);
  return sala;
}

function iniciarPartida(sala) {
  const jugadores = sala.players.filter(Boolean);
  if (jugadores.length !== 4) return;
  sala.status = 'playing';
  sala.startedAt = Date.now();
  sala.hostUserId = sala.hostUserId || jugadores[0].userId;
  sala.game = new PartidaCaida(jugadores.map((p) => p.name));
  sala.deadline = 0;
  sala.voteDeadline = Date.now() + TURNO_MS;
  console.log(`[partida] ${sala.code} iniciada: ${jugadores.map((p) => p.name).join(', ')}`);
  difundirSala(sala);
  difundirEstado(sala);
}

function salaDeUsuario(userId) {
  const code = salaPorUsuario.get(userId);
  return code ? salas.get(code) : null;
}

function difundirSala(sala) {
  for (const jugador of sala.players) {
    if (!jugador || !jugador.socket) continue;
    enviar(jugador.socket, 'roomState', { room: estadoSala(sala, jugador.userId) });
  }
}

function enviarSala(sala, tipo) {
  for (const jugador of sala.players) {
    if (!jugador || !jugador.socket) continue;
    enviar(jugador.socket, tipo, { room: estadoSala(sala, jugador.userId) });
  }
}

function difundirEstado(sala) {
  if (!sala.game) return;
  for (const jugador of sala.players) {
    if (!jugador || !jugador.socket) continue;
    enviar(jugador.socket, 'gameState', {
      room: estadoSala(sala, jugador.userId),
      state: sala.game.estadoPara(jugador.seat)
    });
  }
  if (sala.game.phase === 'finished' && sala.status !== 'finished') {
    sala.status = 'finished';
    sala.finishedAt = Date.now();
    guardarResultado(sala);
    setTimeout(() => {
      const actual = salas.get(sala.code);
      if (actual && actual.status === 'finished') {
        for (const p of actual.players) if (p) salaPorUsuario.delete(p.userId);
        salas.delete(actual.code);
      }
    }, 10 * 60 * 1000);
  }
}

function guardarResultado(sala) {
  try {
    const juego = sala.game;
    if (!juego || juego.phase !== 'finished' || juego.winnerTeam === null) return;
    const scores = juego.scores;
    const winnerTeam = juego.winnerTeam;
    const jugadores = sala.players.filter(Boolean).map((jugador) => {
      const equipo = jugador.seat % 2;
      return {
        userId: jugador.userId,
        seat: jugador.seat,
        name: jugador.name,
        team: equipo,
        won: equipo === winnerTeam,
        teamScore: scores[equipo],
        rivalScore: scores[1 - equipo]
      };
    });
    if (jugadores.length !== 4) return;

    const id = db.registrarPartida({
      roomCode: sala.code,
      roomType: sala.tipo,
      winnerTeam,
      scoreA: scores[0],
      scoreB: scores[1],
      hands: juego.handNumber,
      startedAt: sala.startedAt || juego.startedAt,
      finishedAt: sala.finishedAt,
      players: jugadores
    });
    console.log(`[historial] ${sala.code} #${id} guardada (${scores[0]}-${scores[1]})`);
    auditar({
      event: 'match_finished',
      userId: null,
      detail: {
        sala: sala.code,
        tipo: sala.tipo,
        scoreA: scores[0],
        scoreB: scores[1],
        winnerTeam,
        hands: juego.handNumber
      }
    });
  } catch (error) {
    console.error('[historial] no se pudo guardar el resultado:', error);
  }
}

function estadoSala(sala, userId) {
  return {
    roomId: sala.id,
    code: sala.code,
    tipo: sala.tipo,
    status: sala.status,
    hostSeat: (() => {
      const host = sala.players.find((p) => p && p.userId === sala.hostUserId);
      return host ? host.seat : -1;
    })(),
    yourSeat: (() => {
      const jugador = sala.players.find((p) => p && p.userId === userId);
      return jugador ? jugador.seat : -1;
    })(),
    players: sala.players.map((p, seatIndex) => p ? {
      seat: p.seat,
      userId: p.userId,
      name: p.name,
      connected: p.connected
    } : {
      seat: seatIndex,
      userId: 0,
      name: '',
      connected: false
    })
  };
}

function enviarEstado(sala) {
  if (sala.game) difundirEstado(sala);
}

function difundirCola() {
  for (const q of cola) {
    if (!q.socket || q.socket.readyState !== WebSocket.OPEN) continue;
    const pos = cola.findIndex((x) => x.userId === q.userId) + 1;
    enviar(q.socket, 'queue', { count: cola.length, position: pos });
  }
}

function enviar(ws, type, payload = {}) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ type, ...payload }));
}

function enviarError(ws, message, code = null) {
  enviar(ws, 'error', code ? { message, code } : { message });
}

function generarCodigo() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

async function enviarCodigoVerificacion(user) {
  if (!user || !user.email) {
    return { ok: false, sent: false, error: 'La cuenta no tiene correo.' };
  }
  const { codigo, expira } = db.crearCodigo(user.id, 'verify', VERIFY_CODE_TTL_MS);

  // Fire-and-forget: el registro/verificación no espera a Gmail.
  enviarCodigo({
    to: user.email,
    code: codigo,
    purpose: 'verify',
    username: user.username,
    expiresMinutes: VERIFY_CODE_TTL_MIN
  }).then((envio) => {
    auditar({
      event: envio.sent ? 'verification_email_sent' : 'verification_email_failed',
      severity: envio.sent ? 'info' : 'warn',
      userId: user.id,
      username: user.username,
      detail: { sent: !!envio.sent, dev: !!envio.dev, error: envio.error || null }
    });
  }).catch((error) => {
    console.error('[MAIL_ERROR]', error);
    auditar({
      event: 'verification_email_failed',
      severity: 'warn',
      userId: user.id,
      username: user.username,
      detail: { error: error.message }
    });
  });

  return {
    ok: true,
    sent: true,
    queued: true,
    expiresAt: expira,
    expiresInMinutes: VERIFY_CODE_TTL_MIN,
    ...(DEV_CODES ? { devCode: codigo } : {})
  };
}

function aplicarCabecerasSeguridad(res, seguro, pathname) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (pathname.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  if (seguro) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

function aplicarCors(req, res) {
  const origen = req.headers.origin;
  if (ORIGENES_PERMITIDOS.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origen && ORIGENES_PERMITIDOS.includes(origen)) {
    res.setHeader('Access-Control-Allow-Origin', origen);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Max-Age', '600');
}

function responder(res, status, body, cabeceras = {}) {
  res.statusCode = status;
  for (const [clave, valor] of Object.entries(cabeceras)) res.setHeader(clave, valor);
  if (body === null) return res.end();
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function leerJson(req) {
  return new Promise((resolve, reject) => {
    const declarado = Number(req.headers['content-length'] || 0);
    if (declarado > MAX_CUERPO_BYTES) {
      const e = new Error('Cuerpo demasiado grande.');
      e.code = 'BODY_TOO_LARGE';
      req.pause();
      reject(e);
      return;
    }

    let data = '';
    let total = 0;
    let terminado = false;
    req.on('data', (chunk) => {
      if (terminado) return;
      total += chunk.length;
      if (total > MAX_CUERPO_BYTES) {
        terminado = true;
        const e = new Error('Cuerpo demasiado grande.');
        e.code = 'BODY_TOO_LARGE';
        req.pause();
        reject(e);
        return;
      }
      data += chunk;
    });
    req.on('end', () => {
      if (terminado) return;
      terminado = true;
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        const e = new Error('JSON inválido.');
        e.code = 'INVALID_JSON';
        reject(e);
      }
    });
    req.on('error', (error) => {
      if (!terminado) {
        terminado = true;
        reject(error);
      }
    });
  });
}

function leerBearer(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return '';
  return header.slice(7).trim();
}

function usuarioDeRequest(req) {
  return db.usuarioPorToken(leerBearer(req));
}

setInterval(() => {
  const ahora = Date.now();
  for (const sala of salas.values()) {
    if (!sala.game) continue;
    if (sala.game.phase === 'voting') {
      if (ahora >= sala.voteDeadline) {
        for (let seat = 0; seat < 4; seat++) {
          if (sala.game.votos[seat] === null) sala.game.votar(seat, Math.random() > 0.5 ? 1 : 2);
        }
        sala.deadline = ahora + TURNO_MS;
        difundirEstado(sala);
      }
      continue;
    }
    if (sala.status !== 'playing' || sala.game.phase !== 'playing') continue;
    if (ahora >= sala.deadline) {
      const asiento = sala.game.turnSeat;
      const r = sala.game.jugadaAutomatica(asiento);
      if (r.ok) {
        console.log(`[turno] ${sala.code}: jugada automática del asiento ${asiento}`);
        sala.deadline = ahora + TURNO_MS;
        difundirEstado(sala);
      } else {
        sala.deadline = ahora + TURNO_MS;
      }
    }
  }
}, 1000).unref();

setInterval(() => {
  limitadorApi.limpiar();
  limitadorAuth.limpiar();
  limitadorFallosLogin.limpiar();
}, 60_000).unref();

setInterval(() => {
  db.limpiarAuditoria(AUDIT_RETENTION_DAYS);
  db.limpiarCodigosExpirados();
}, 60 * 60_000).unref();

setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.estaVivo === false) { ws.terminate(); continue; }
    ws.estaVivo = false;
    try { ws.ping(); } catch { /* ignore */ }
  }
}, 30000).unref();

servidor.listen(PUERTO, '0.0.0.0', () => {
  const protocolo = SEGURO ? 'https' : 'http';
  const protocoloWs = SEGURO ? 'wss' : 'ws';
  console.log('==============================================');
  console.log('  CAÍDA ONLINE — backend');
  console.log(`  ${protocolo.toUpperCase()}  ${protocolo}://localhost:${PUERTO}/api`);
  console.log(`  WS    ${protocoloWs}://localhost:${PUERTO}/ws?token=...`);
  console.log(`  DB    ${DB_PATH}`);
  console.log(`  TLS   ${SEGURO ? 'activo' : 'desactivado (usa TLS_CERT/TLS_KEY o un proxy HTTPS)'}`);
  console.log('==============================================');
});

function cerrar() {
  console.log('Cerrando servidor...');
  for (const ws of wss.clients) ws.close(1001, 'Servidor detenido');
  db.cerrar();
  servidor.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}

process.on('SIGINT', cerrar);
process.on('SIGTERM', cerrar);
