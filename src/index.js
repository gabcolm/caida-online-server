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

const PUERTO = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL || '';
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

const AD_REWARD_COINS = Math.max(1, Number(process.env.AD_REWARD_COINS || 100));
const AD_REWARD_COOLDOWN_MS = Math.max(1000, Number(process.env.AD_REWARD_COOLDOWN_MS || 60000));
const PRODUCTOS_MONEDAS = Object.freeze({
  monedas_1000: { coins: 1000, precio: 1.99 },
  monedas_5000: { coins: 5500, precio: 7.99 },
  monedas_15000: { coins: 17000, precio: 19.99 },
  monedas_50000: { coins: 50000, precio: 49.99 }
});
const ultimoAnuncio = new Map();
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

const db = new BaseDatos(DATABASE_URL || undefined);
await db.iniciar();
configurarAuditoria(db);
const salas = new Map();
const salaPorUsuario = new Map();
const salasPrivadas = new Map();
const salaPrivadaPorUsuario = new Map();
const cola = [];
const socketsPorUsuario = new Map();

function enviarAUsuario(userId, tipo, datos = {}) {
  const set = socketsPorUsuario.get(Number(userId));
  if (!set) return false;
  let enviado = false;
  for (const ws of set) {
    if (ws.readyState === WebSocket.OPEN) {
      enviar(ws, tipo, datos);
      enviado = true;
    }
  }
  return enviado;
}

function usuarioEnLinea(userId) {
  const set = socketsPorUsuario.get(Number(userId));
  if (!set) return false;
  for (const ws of set) if (ws.readyState === WebSocket.OPEN) return true;
  return false;
}

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
  '/api/auth/social',
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

async function iniciarSesionHttp(user, res, ip, userAgent, detalle = {}) {
  const acceso = await await db.datosAcceso(user.id);
  const token = await await db.crearSesion(user.id);
  await db.actualizarUltimoAcceso(user.id, ip);
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

    if (req.method === 'POST' && url.pathname === '/api/auth/social') {
      const body = await leerJson(req);
      const provider = String(body.provider || '').trim().toLowerCase();
      if (provider !== 'google' && provider !== 'facebook') {
        return responder(res, 400, { error: 'Proveedor social no soportado.', code: 'BAD_PROVIDER' });
      }
      const providerId = String(body.providerUserId || '').trim();
      if (providerId.length < 3) {
        return responder(res, 400, { error: 'Falta el identificador del proveedor.', code: 'BAD_SOCIAL_ID' });
      }
      const email = body.email ? String(body.email).trim() : null;
      if (email) {
        const errorEmail = validarEmail(email);
        if (errorEmail) return responder(res, 400, { error: errorEmail });
      }
      const nombre = body.name ? String(body.name).slice(0, 40) : null;
      const { user, created } = await db.crearUsuarioSocial({ provider, providerId, email, name: nombre });
      const token = await db.crearSesion(user.id);
      await db.actualizarUltimoAcceso(user.id, ip);
      auditar({
        event: created ? 'social_register' : 'social_login',
        userId: user.id,
        username: user.username,
        ip,
        userAgent,
        detail: { provider }
      });
      return responder(res, created ? 201 : 200, {
        token,
        user: { ...user, facebookLinked: provider === 'facebook' || await db.tieneFacebook(user.id) },
        provider
      });
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
        const user = await db.crearUsuario(String(body.username).trim(), String(body.password), email);
        const token = await db.crearSesion(user.id);
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
      const user = await db.verificarCredenciales(alias, body.password || '');
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
        const challengeToken = await db.crearDesafioLogin(user.id);
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

      return await iniciarSesionHttp(user, res, ip, userAgent, { metodo: 'password' });
    }

    if (req.method === 'POST' && url.pathname === '/api/login/2fa') {
      const body = await leerJson(req);
      const desafio = await db.desafioLogin(body.challengeToken);
      if (!desafio) {
        return responder(res, 401, { error: 'El desafío venció. Inicia sesión de nuevo.', code: 'BAD_2FA_CHALLENGE' });
      }
      const user = await db.usuarioPorId(desafio.user_id);
      const datos = await db.datosTotp(desafio.user_id);
      if (!user || !datos?.enabled || !datos.secret) {
        await db.borrarDesafio(desafio.token);
        return responder(res, 401, { error: 'La verificación en dos pasos no está disponible.', code: 'BAD_2FA_CHALLENGE' });
      }

      const codigo = String(body.code || '').trim();
      const validoTotp = verificarTotp(datos.secret, codigo);
      const validoRecuperacion = !validoTotp && await db.consumirCodigoRecuperacion(user.id, codigo);
      if (!validoTotp && !validoRecuperacion) {
        const intentos = await db.fallarDesafio(desafio.token);
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

      await db.borrarDesafio(desafio.token);
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
      return await iniciarSesionHttp(user, res, ip, userAgent, {
        metodo: validoRecuperacion ? 'recovery_code' : 'totp'
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/me') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      return responder(res, 200, {
        user: { ...user, facebookLinked: await db.tieneFacebook(user.id) },
        stats: await db.estadisticasUsuario(user.id)
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/wallet/ad-reward') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });

      const ahora = Date.now();
      const anterior = ultimoAnuncio.get(user.id) || 0;
      if (ahora - anterior < AD_REWARD_COOLDOWN_MS) {
        const espera = Math.ceil((AD_REWARD_COOLDOWN_MS - (ahora - anterior)) / 1000);
        return responder(res, 429, {
          error: `Espera ${espera} s antes de otro anuncio.`,
          code: 'AD_COOLDOWN',
          retryAfter: espera
        });
      }
      ultimoAnuncio.set(user.id, ahora);

      const coins = await db.sumarMonedas(user.id, AD_REWARD_COINS);
      auditar({
        event: 'wallet_ad_reward',
        userId: user.id,
        username: user.username,
        ip,
        userAgent,
        detail: { reward: AD_REWARD_COINS, saldo: coins }
      });
      return responder(res, 200, { ok: true, coins, reward: AD_REWARD_COINS });
    }

    if (req.method === 'POST' && url.pathname === '/api/wallet/purchase') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });

      const body = await leerJson(req);
      const productId = String(body.productId || '').trim();
      const producto = PRODUCTOS_MONEDAS[productId];
      if (!producto) {
        return responder(res, 400, { error: 'Producto de monedas desconocido.', code: 'BAD_PRODUCT' });
      }

      // TODO producción: validar el recibo con Google Play antes de acreditar.
      const receiptId = String(body.receiptId || '').trim();
      if (receiptId.length < 4) {
        return responder(res, 400, { error: 'Falta el recibo de compra.', code: 'BAD_RECEIPT' });
      }

      const nuevo = await db.registrarCompra({
        receiptId,
        userId: user.id,
        productId,
        coins: producto.coins
      });

      if (!nuevo) {
        const actual = await db.usuarioPorId(user.id);
        return responder(res, 200, { ok: true, duplicate: true, coins: actual?.coins ?? user.coins });
      }

      const coins = await db.sumarMonedas(user.id, producto.coins);
      auditar({
        event: 'wallet_purchase',
        userId: user.id,
        username: user.username,
        ip,
        userAgent,
        detail: { productId, coins: producto.coins, saldo: coins }
      });
      return responder(res, 200, { ok: true, coins, added: producto.coins, productId });
    }

    if (req.method === 'POST' && url.pathname === '/api/account/email') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const errorEmail = validarEmail(body.email);
      if (errorEmail) return responder(res, 400, { error: errorEmail });
      if (!body.password) return responder(res, 400, { error: 'Confirma tu contraseña para cambiar el correo.' });
      const credenciales = await db.verificarCredenciales(user.username, String(body.password));
      if (!credenciales) return responder(res, 401, { error: 'Contraseña incorrecta.', code: 'BAD_CREDENTIALS' });
      try {
        const actualizado = await db.actualizarEmail(user.id, body.email);
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
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      if (!user.email) return responder(res, 400, { error: 'Primero agrega un correo a tu cuenta.' });
      if (user.verified) return responder(res, 200, { ok: true, alreadyVerified: true });
      const verification = await enviarCodigoVerificacion(user);
      return responder(res, 200, { ok: true, verification });
    }

    if (req.method === 'POST' && url.pathname === '/api/verify') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const resultado = await db.consumirCodigo(user.id, 'verify', body.code);
      if (!resultado.ok) return responder(res, 400, { error: resultado.error, code: 'BAD_CODE' });
      const verificado = await db.marcarVerificado(user.id);
      auditar({ event: 'account_verified', userId: user.id, username: user.username, ip, userAgent });
      return responder(res, 200, { ok: true, user: verificado });
    }

    if (req.method === 'POST' && (url.pathname === '/api/recovery/request' || url.pathname === '/api/recover')) {
      const body = await leerJson(req);
      const user = await db.usuarioPorIdentificador(body.identifier);
      let devCode;

      console.log('[recovery] solicitud recibida', {
        identificador: String(body.identifier || '').trim().slice(0, 3) + '***',
        cuentaEncontrada: !!user,
        tieneCorreo: !!user?.email
      });

      if (user && user.email) {
        const { codigo } = await db.crearCodigo(user.id, 'reset', RECOVERY_CODE_TTL_MS);
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
      const user = await db.usuarioPorIdentificador(body.identifier);
      if (!user) return responder(res, 400, { error: 'Código inválido o expirado.', code: 'BAD_CODE' });
      const resultado = await db.consumirCodigo(user.id, 'reset', body.code);
      if (!resultado.ok) return responder(res, 400, { error: resultado.error, code: 'BAD_CODE' });
      await db.actualizarPassword(user.id, String(body.password));
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
      const user = await db.usuarioPorIdentificador(body.identifier);
      if (!user) return responder(res, 400, { error: 'Código inválido o expirado.', code: 'BAD_CODE' });
      const resultado = await db.verificarCodigo(user.id, 'reset', body.code);
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
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const datos = await db.datosTotp(user.id);
      if (datos?.enabled) return responder(res, 409, { error: 'La verificación en dos pasos ya está activa.', code: '2FA_ALREADY_ENABLED' });
      const secreto = generarSecretoTotp();
      await db.guardarTotpPendiente(user.id, secreto);
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
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const datos = await db.datosTotp(user.id);
      if (datos?.enabled) return responder(res, 409, { error: 'La verificación en dos pasos ya está activa.', code: '2FA_ALREADY_ENABLED' });
      if (!datos?.pending) return responder(res, 400, { error: 'Primero inicia la configuración de 2FA.', code: '2FA_NOT_STARTED' });
      if (!verificarTotp(datos.pending, body.code)) {
        auditar({ event: '2fa_enable_fail', severity: 'warn', userId: user.id, username: user.username, ip, userAgent });
        return responder(res, 400, { error: 'El código de 6 dígitos no es válido.', code: 'BAD_2FA_CODE' });
      }
      await db.activarTotp(user.id, datos.pending);
      const recoveryCodes = await db.crearCodigosRecuperacion(user.id);
      const actualizado = await db.usuarioPorId(user.id);
      auditar({ event: '2fa_enabled', userId: user.id, username: user.username, ip, userAgent });
      return responder(res, 200, { ok: true, user: actualizado, recoveryCodes });
    }

    if (req.method === 'POST' && url.pathname === '/api/2fa/disable') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const datos = await db.datosTotp(user.id);
      if (!datos?.enabled || !datos.secret) {
        return responder(res, 409, { error: 'La verificación en dos pasos no está activa.', code: '2FA_NOT_ENABLED' });
      }
      const clave = String(body.code || '').trim();
      const porTotp = verificarTotp(datos.secret, clave);
      const porRecuperacion = !porTotp && await db.consumirCodigoRecuperacion(user.id, clave);
      if (!porTotp && !porRecuperacion) {
        auditar({ event: '2fa_disable_fail', severity: 'warn', userId: user.id, username: user.username, ip, userAgent });
        return responder(res, 400, { error: 'El código no es válido.', code: 'BAD_2FA_CODE' });
      }
      await db.desactivarTotp(user.id);
      const actualizado = await db.usuarioPorId(user.id);
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
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const body = await leerJson(req);
      const datos = await db.datosTotp(user.id);
      if (!datos?.enabled || !datos.secret) {
        return responder(res, 409, { error: 'La verificación en dos pasos no está activa.', code: '2FA_NOT_ENABLED' });
      }
      const clave = String(body.code || '').trim();
      const porTotp = verificarTotp(datos.secret, clave);
      const porRecuperacion = !porTotp && await db.consumirCodigoRecuperacion(user.id, clave);
      if (!porTotp && !porRecuperacion) {
        auditar({ event: '2fa_recovery_fail', severity: 'warn', userId: user.id, username: user.username, ip, userAgent });
        return responder(res, 400, { error: 'El código no es válido.', code: 'BAD_2FA_CODE' });
      }
      const recoveryCodes = await db.crearCodigosRecuperacion(user.id);
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
      return responder(res, 200, { audit: await db.listarAuditoria(limite) });
    }

    if (req.method === 'GET' && url.pathname === '/api/ranking') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const limite = Number(url.searchParams.get('limit') || 20);
      return responder(res, 200, { ranking: await db.ranking(limite) });
    }

    if (req.method === 'GET' && url.pathname === '/api/history') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });
      const limite = Number(url.searchParams.get('limit') || 20);
      return responder(res, 200, { history: await db.historialUsuario(user.id, limite) });
    }

    if (req.method === 'GET' && url.pathname === '/api/friends') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });

      const [amigos, solicitudes] = await Promise.all([
        db.listarAmigos(user.id),
        db.solicitudesAmistad(user.id)
      ]);

      return responder(res, 200, {
        myFriendCode: user.friendCode,
        friends: amigos.map((amigo) => ({ ...amigo, online: usuarioEnLinea(amigo.id) })),
        incomingRequests: solicitudes.incoming,
        outgoingRequests: solicitudes.outgoing
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/friends/request') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });

      const body = await leerJson(req);
      const consulta = String(body.query || '').trim();
      if (consulta.length < 3) {
        return responder(res, 400, { error: 'Escribe un código de amigo o un alias.', code: 'BAD_QUERY' });
      }

      let destino = await db.usuarioPorFriendCode(consulta);
      if (!destino) destino = await db.usuarioPorIdentificador(consulta);
      if (!destino) {
        return responder(res, 404, { error: 'No encontramos ese código o alias.', code: 'NOT_FOUND' });
      }
      if (destino.id === user.id) {
        return responder(res, 400, { error: 'No puedes agregarte a ti mismo.', code: 'SELF_FRIEND' });
      }

      try {
        const resultado = await db.crearSolicitudAmistad(user.id, destino.id);
        if (resultado.autoAccepted) {
          enviarAUsuario(destino.id, 'friend_accepted', { userId: user.id, username: user.username });
        } else {
          enviarAUsuario(destino.id, 'friend_request', {
            fromUserId: user.id,
            username: user.username,
            friendCode: user.friendCode
          });
        }
        auditar({
          event: resultado.autoAccepted ? 'friend_accepted' : 'friend_request',
          userId: user.id,
          username: user.username,
          ip,
          userAgent,
          detail: { friendId: destino.id, username: destino.username }
        });
        return responder(res, 200, { ok: true, autoAccepted: resultado.autoAccepted, friendId: destino.id });
      } catch (error) {
        return responder(res, 400, { error: error.message, code: 'FRIEND_ERROR' });
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/friends/respond') {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });

      const body = await leerJson(req);
      const action = body.action === 'accept' ? 'accept' : body.action === 'reject' ? 'reject' : null;
      if (!action) return responder(res, 400, { error: 'Acción inválida.', code: 'BAD_ACTION' });

      const fila = await db.responderSolicitud(body.requestId, user.id, action);
      if (!fila) return responder(res, 404, { error: 'La solicitud ya no existe.', code: 'NOT_FOUND' });

      if (action === 'accept') {
        enviarAUsuario(fila.requester_id, 'friend_accepted', { userId: user.id, username: user.username });
      } else {
        enviarAUsuario(fila.requester_id, 'friend_rejected', { userId: user.id, username: user.username });
      }

      auditar({
        event: action === 'accept' ? 'friend_accept' : 'friend_reject',
        userId: user.id,
        username: user.username,
        ip,
        userAgent,
        detail: { requesterId: Number(fila.requester_id) }
      });

      return responder(res, 200, { ok: true });
    }

    const amigoEliminar = url.pathname.match(/^\/api\/friends\/(\d+)$/);
    if (req.method === 'DELETE' && amigoEliminar) {
      const user = await usuarioDeRequest(req);
      if (!user) return responder(res, 401, { error: 'Sesión inválida o expirada.', code: 'UNAUTHORIZED' });

      const eliminado = await db.eliminarAmistad(user.id, Number(amigoEliminar[1]));
      if (!eliminado) return responder(res, 404, { error: 'Ese amigo no existe.', code: 'NOT_FOUND' });

      auditar({
        event: 'friend_removed',
        userId: user.id,
        username: user.username,
        ip,
        userAgent,
        detail: { friendId: Number(amigoEliminar[1]) }
      });

      return responder(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/logout') {
      const auth = leerBearer(req);
      await db.revocarSesion(auth);
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

servidor.on('upgrade', async (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (url.pathname !== '/ws') {
    socket.destroy();
    return;
  }
  const token = url.searchParams.get('token') || '';
  const user = await db.usuarioPorToken(token);
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
    manejarMensaje(ws, data).catch((error) => console.error('[ws] mensaje:', error.message));
  });
  ws.on('close', () => desconectar(ws));
  ws.on('error', (error) => console.warn('[ws] error', error.message));
});

async function manejarMensaje(ws, data) {
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
    case 'create_private_room':
      return crearLobbyPrivado(ws);
    case 'join_private_room':
      return unirseLobbyPrivado(ws, mensaje.roomCode, mensaje.seat);
    case 'select_seat':
      return seleccionarAsientoPrivado(ws, mensaje.seat);
    case 'swap_seat':
      return intercambiarAsientosPrivados(ws, mensaje.seatA, mensaje.seatB);
    case 'update_private_room_settings':
      return actualizarAjustesLobbyPrivado(ws, mensaje);
    case 'invite_friend':
      return invitarAmigoLobbyPrivado(ws, mensaje.friendId);
    case 'leave_private_room':
      return salirLobbyPrivado(ws);
    case 'start_private_match':
      return iniciarPartidaPrivada(ws);
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

async function verificarCuentaParaJugar(ws) {
  if (!REQUIRE_VERIFIED && VERIFY_AFTER_MATCHES <= 0) return true;
  const actual = await db.usuarioPorId(ws.usuario.id);
  if (!actual) {
    enviarError(ws, 'Sesión inválida.', 'UNAUTHORIZED');
    return false;
  }
  const stats = await db.estadisticasUsuario(actual.id);
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

async function buscarPartida(ws) {
  const user = ws.usuario;
  if (!(await verificarCuentaParaJugar(ws))) return;
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

async function crearSalaPrivada(ws) {
  const user = ws.usuario;
  if (!(await verificarCuentaParaJugar(ws))) return;
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

async function unirseSala(ws, codigo) {
  const code = String(codigo || '').trim().toUpperCase();
  if (!code) return enviarError(ws, 'Escribe un código de sala.');
  if (!(await verificarCuentaParaJugar(ws))) return;
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

  const lobbyPrivado = quitarDeLobbyPrivado(user.id);
  if (lobbyPrivado) difundirLobbyPrivado(lobbyPrivado);

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

function socketDeUsuario(userId) {
  const set = socketsPorUsuario.get(Number(userId));
  if (!set) return null;
  for (const ws of set) {
    if (ws.readyState === WebSocket.OPEN) return ws;
  }
  return null;
}

function lobbyPrivadoDeUsuario(userId) {
  const code = salaPrivadaPorUsuario.get(Number(userId));
  return code ? salasPrivadas.get(code) : null;
}

function vistaLobbyPrivado(sala) {
  return {
    code: sala.code,
    hostId: sala.hostId,
    betAmount: sala.betAmount,
    allowBots: sala.allowBots,
    status: sala.status,
    seats: sala.seats.map((s, i) => (s
      ? { seat: i, userId: s.userId, username: s.username, friendCode: s.friendCode || null, isBot: !!s.isBot }
      : { seat: i, userId: null }))
  };
}

function difundirLobbyPrivado(sala) {
  for (const s of sala.seats) {
    if (s && s.userId) enviarAUsuario(s.userId, 'private_room_state', { room: vistaLobbyPrivado(sala) });
  }
}

function quitarDeLobbyPrivado(userId) {
  const id = Number(userId);
  const code = salaPrivadaPorUsuario.get(id);
  if (!code) return null;

  const sala = salasPrivadas.get(code);
  if (!sala) {
    salaPrivadaPorUsuario.delete(id);
    return null;
  }

  const indice = sala.seats.findIndex((s) => s && s.userId === id);
  if (indice >= 0) sala.seats[indice] = null;
  salaPrivadaPorUsuario.delete(id);

  const humanos = sala.seats.filter((s) => s && s.userId);
  if (!humanos.length) {
    salasPrivadas.delete(code);
    return null;
  }

  if (sala.hostId === id) sala.hostId = humanos[0].userId;
  return sala;
}

function crearLobbyPrivado(ws) {
  const user = ws.usuario;
  if (salaDeUsuario(user.id) || lobbyPrivadoDeUsuario(user.id)) {
    return enviarError(ws, 'Ya estás en una sala.');
  }

  let code;
  do code = generarCodigo(); while (salasPrivadas.has(code) || salas.has(code));

  const sala = {
    code,
    hostId: user.id,
    betAmount: 0,
    allowBots: false,
    status: 'waiting',
    createdAt: Date.now(),
    seats: [
      { userId: user.id, username: user.username, friendCode: user.friendCode || null },
      null,
      null,
      null
    ]
  };

  salasPrivadas.set(code, sala);
  salaPrivadaPorUsuario.set(user.id, code);
  auditar({ event: 'private_room_create', userId: user.id, username: user.username, ip: ws.ip, userAgent: ws.userAgent, detail: { code } });
  difundirLobbyPrivado(sala);
}

function unirseLobbyPrivado(ws, roomCode, asientoPreferido = null) {
  const user = ws.usuario;
  const code = String(roomCode || '').trim().toUpperCase();
  const sala = salasPrivadas.get(code);
  if (!sala || sala.status !== 'waiting') return enviarError(ws, 'La sala privada no existe o ya empezó.');

  if (salaPrivadaPorUsuario.get(user.id) === code) {
    difundirLobbyPrivado(sala);
    return;
  }
  if (salaDeUsuario(user.id) || lobbyPrivadoDeUsuario(user.id)) {
    return enviarError(ws, 'Ya estás en otra sala.');
  }
  if (sala.seats.every(Boolean)) return enviarError(ws, 'La sala privada está llena.');

  let asiento = Number.isInteger(Number(asientoPreferido)) ? Number(asientoPreferido) : -1;
  if (asiento < 0 || asiento > 3 || sala.seats[asiento]) {
    asiento = sala.seats[2] ? sala.seats.findIndex((s) => !s) : 2;
    if (asiento < 0 || sala.seats[asiento]) asiento = sala.seats.findIndex((s) => !s);
  }
  if (asiento < 0) return enviarError(ws, 'La sala privada está llena.');

  sala.seats[asiento] = { userId: user.id, username: user.username, friendCode: user.friendCode || null };
  salaPrivadaPorUsuario.set(user.id, code);
  auditar({ event: 'private_room_join', userId: user.id, username: user.username, ip: ws.ip, userAgent: ws.userAgent, detail: { code, seat: asiento } });
  difundirLobbyPrivado(sala);
}

function seleccionarAsientoPrivado(ws, asiento) {
  const user = ws.usuario;
  const sala = lobbyPrivadoDeUsuario(user.id);
  if (!sala) return enviarError(ws, 'No estás en una sala privada.');

  const destino = Number(asiento);
  if (!Number.isInteger(destino) || destino < 0 || destino > 3) return enviarError(ws, 'Asiento inválido.');
  if (sala.seats[destino]) return enviarError(ws, 'Ese asiento está ocupado.');

  const actual = sala.seats.findIndex((s) => s && s.userId === user.id);
  if (actual < 0) return enviarError(ws, 'No estás sentado en esta sala.');
  if (actual === destino) return;

  const jugador = sala.seats[actual];
  sala.seats[actual] = null;
  sala.seats[destino] = jugador;
  difundirLobbyPrivado(sala);
}

function intercambiarAsientosPrivados(ws, seatA, seatB) {
  const user = ws.usuario;
  const sala = lobbyPrivadoDeUsuario(user.id);
  if (!sala) return enviarError(ws, 'No estás en una sala privada.');
  if (sala.hostId !== user.id) return enviarError(ws, 'Solo el anfitrión puede intercambiar asientos.');

  const a = Number(seatA);
  const b = Number(seatB);
  if (!Number.isInteger(a) || !Number.isInteger(b) || a < 0 || a > 3 || b < 0 || b > 3 || a === b) {
    return enviarError(ws, 'Asientos inválidos.');
  }

  [sala.seats[a], sala.seats[b]] = [sala.seats[b], sala.seats[a]];
  difundirLobbyPrivado(sala);
}

function actualizarAjustesLobbyPrivado(ws, mensaje = {}) {
  const user = ws.usuario;
  const sala = lobbyPrivadoDeUsuario(user.id);
  if (!sala) return enviarError(ws, 'No estás en una sala privada.');
  if (sala.hostId !== user.id) return enviarError(ws, 'Solo el anfitrión cambia la apuesta.');

  if (mensaje.betAmount !== undefined) {
    const apuesta = Number(mensaje.betAmount);
    if (![0, 500, 2500, 10000].includes(apuesta)) return enviarError(ws, 'Apuesta no válida.');
    sala.betAmount = apuesta;
    if (apuesta !== 0) sala.allowBots = false;
  }

  if (mensaje.allowBots !== undefined) {
    if (sala.betAmount !== 0) return enviarError(ws, 'Los bots solo se permiten en salas gratis.');
    sala.allowBots = !!mensaje.allowBots;
  }

  difundirLobbyPrivado(sala);
}

async function invitarAmigoLobbyPrivado(ws, friendId) {
  const user = ws.usuario;
  const sala = lobbyPrivadoDeUsuario(user.id);
  if (!sala) return enviarError(ws, 'Crea o únete a una sala privada primero.');

  const amigo = Number(friendId);
  if (!Number.isInteger(amigo) || amigo === user.id) return enviarError(ws, 'Amigo inválido.');
  if (!(await db.sonAmigos(user.id, amigo))) return enviarError(ws, 'Ese jugador no está en tu lista de amigos.');
  if (!usuarioEnLinea(amigo)) return enviarError(ws, 'Tu amigo no está conectado ahora.');

  enviarAUsuario(amigo, 'private_room_invite', {
    fromUserId: user.id,
    fromUsername: user.username,
    roomCode: sala.code,
    betAmount: sala.betAmount
  });
  enviar(ws, 'private_room_invite_sent', { friendId: amigo, roomCode: sala.code });
}

function salirLobbyPrivado(ws) {
  const user = ws.usuario;
  const sala = quitarDeLobbyPrivado(user.id);
  if (sala) difundirLobbyPrivado(sala);
  enviar(ws, 'private_room_left', {});
}

async function iniciarPartidaPrivada(ws) {
  const user = ws.usuario;
  const sala = lobbyPrivadoDeUsuario(user.id);
  if (!sala) return enviarError(ws, 'No estás en una sala privada.');
  if (sala.hostId !== user.id) return enviarError(ws, 'Solo el anfitrión puede iniciar.');

  const humanos = sala.seats
    .map((s, seat) => (s && s.userId ? { ...s, seat } : null))
    .filter(Boolean);

  if (humanos.length < 2) return enviarError(ws, 'Necesitas al menos 2 jugadores para iniciar.');
  if (sala.betAmount > 0 && humanos.length !== 4) {
    return enviarError(ws, 'Para apostar monedas deben estar los 4 jugadores (2v2).', 'INSUFFICIENT_PLAYERS');
  }

  if (sala.betAmount > 0) {
    const cobro = await db.cobrarApuestas(humanos.map((h) => h.userId), sala.betAmount);
    if (!cobro.ok) {
      const afectado = humanos.find((h) => h.userId === cobro.userId);
      return enviarError(
        ws,
        `A ${afectado ? afectado.username : 'un jugador'} le faltan monedas para la apuesta de ${sala.betAmount}.`,
        'INSUFFICIENT_COINS'
      );
    }
  }

  const juego = crearSala('private');
  juego.hostUserId = sala.hostId;
  juego.apuesta = sala.betAmount;
  juego.pozo = sala.betAmount * humanos.length;
  juego.codigoPrivado = sala.code;

  for (let seat = 0; seat < 4; seat++) {
    const s = sala.seats[seat];
    if (s && s.userId) {
      juego.players[seat] = {
        seat,
        userId: s.userId,
        name: s.username,
        socket: socketDeUsuario(s.userId),
        connected: true,
        reconnectedAt: null
      };
      salaPorUsuario.set(s.userId, juego.code);
    } else {
      juego.players[seat] = {
        seat,
        userId: null,
        name: `Bot ${seat + 1}`,
        socket: null,
        connected: true,
        reconnectedAt: null,
        isBot: true
      };
    }
  }

  salasPrivadas.delete(sala.code);
  for (const h of humanos) salaPrivadaPorUsuario.delete(h.userId);

  auditar({
    event: 'private_match_start',
    userId: user.id,
    username: user.username,
    ip: ws.ip,
    userAgent: ws.userAgent,
    detail: { code: sala.code, bet: sala.betAmount, humans: humanos.length }
  });

  iniciarPartida(juego);
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
  return guardarResultadoAsync(sala).catch((error) => {
    console.error('[historial] no se pudo guardar el resultado:', error);
  });
}

async function guardarResultadoAsync(sala) {
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
    if (jugadores.length !== 4 || jugadores.some((j) => !j.userId)) {
      console.log(`[historial] ${sala.code}: partida con bots o incompleta; no se guarda en ranking.`);
      return;
    }

    const id = await db.registrarPartida({
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

    if (sala.apuesta > 0 && sala.pozo > 0) {
      const ganadores = jugadores.filter((j) => j.userId && j.won);
      if (ganadores.length) {
        const premio = Math.floor(sala.pozo / ganadores.length);
        for (const ganador of ganadores) {
          await db.sumarMonedas(ganador.userId, premio);
        }
        auditar({
          event: 'private_bet_settled',
          userId: null,
          detail: {
            sala: sala.codigoPrivado || sala.code,
            pozo: sala.pozo,
            premio,
            ganadores: ganadores.map((g) => g.userId)
          }
        });
        console.log(`[apuesta] ${sala.code}: pozo ${sala.pozo}, premio ${premio} a ${ganadores.length} ganador(es).`);
      }
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
  const { codigo, expira } = await db.crearCodigo(user.id, 'verify', VERIFY_CODE_TTL_MS);

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

async function usuarioDeRequest(req) {
  return await db.usuarioPorToken(leerBearer(req));
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
  db.limpiarAuditoria(AUDIT_RETENTION_DAYS).catch((error) => console.error('[db] limpieza auditoría:', error.message));
  db.limpiarCodigosExpirados().catch((error) => console.error('[db] limpieza códigos:', error.message));
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
  console.log(`  DB    PostgreSQL ${db.url.hostname}${db.url.pathname}`);
  console.log(`  TLS   ${SEGURO ? 'activo' : 'desactivado (usa TLS_CERT/TLS_KEY o un proxy HTTPS)'}`);
  console.log('==============================================');
});

function cerrar() {
  console.log('Cerrando servidor...');
  for (const ws of wss.clients) ws.close(1001, 'Servidor detenido');
  db.cerrar().catch((error) => console.warn('[db] cierre:', error.message));
  servidor.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}

process.on('SIGINT', cerrar);
process.on('SIGTERM', cerrar);
