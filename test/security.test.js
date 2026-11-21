import test from 'node:test';
import assert from 'node:assert/strict';
import {
  RateLimiter,
  RedisRateLimiter,
  AsyncRateLimiter,
  base32Codificar,
  base32Decodificar,
  codigoTotp,
  compararCodigo,
  crearLimitador,
  generarCodigo,
  generarSalt,
  generarSecretoTotp,
  hashCodigo,
  normalizarEmail,
  politicaVerificacion,
  urlTotp,
  validarEmail,
  validarPassword,
  verificarTotp
} from '../src/security.js';
import { construirCorreo } from '../src/mailer.js';

test('limitador de ventana fija', () => {
  let ahora = 1000;
  const limite = new RateLimiter({ max: 3, windowMs: 60000 });
  assert.equal(limite.hit('ip', ahora).ok, true);
  assert.equal(limite.hit('ip', ahora).ok, true);
  assert.equal(limite.hit('ip', ahora).ok, true);
  const bloqueado = limite.hit('ip', ahora);
  assert.equal(bloqueado.ok, false);
  assert.equal(bloqueado.retryAfter, 60);

  assert.equal(limite.hit('otra', ahora).ok, true);
  ahora += 60001;
  assert.equal(limite.hit('ip', ahora).ok, true);

  limite.hit('temporal', ahora);
  limite.limpiar(ahora + 120000);
  assert.equal(limite.buckets.size, 0);
});

test('códigos de seguridad y validaciones', () => {
  const codigo = generarCodigo();
  assert.match(codigo, /^\d{6}$/);
  const salt = generarSalt();
  const hash = hashCodigo(codigo, salt);
  assert.equal(compararCodigo(codigo, salt, hash), true);
  assert.equal(compararCodigo('000000', salt, hash), codigo === '000000');

  assert.equal(validarEmail('ana@example.com'), null);
  assert.equal(validarEmail('ana@example'), 'El correo no tiene un formato válido.');
  assert.equal(validarEmail(''), 'Escribe un correo electrónico.');
  assert.equal(normalizarEmail('  Ana@Example.COM '), 'ana@example.com');

  assert.equal(validarPassword('123456'), null);
  assert.equal(validarPassword('123'), 'La contraseña debe tener al menos 6 caracteres.');
});

test('TOTP, secreto base32 y política de verificación', () => {
  const secreto = generarSecretoTotp();
  assert.ok(secreto.length >= 32);
  assert.equal(base32Codificar(base32Decodificar(secreto)), secreto);

  const ahora = 1700000000000;
  const codigo = codigoTotp(secreto, ahora);
  assert.match(codigo, /^\d{6}$/);
  assert.equal(verificarTotp(secreto, codigo, 1, ahora), true);
  assert.equal(verificarTotp(secreto, codigo, 1, ahora + 90000), false);
  assert.equal(verificarTotp(secreto, '000000', 1, ahora), codigo === '000000');
  assert.match(urlTotp(secreto, 'Ana', 'Caída Online'), /^otpauth:\/\/totp\//);

  assert.equal(politicaVerificacion({ verified: true, games: 99 }).ok, true);
  assert.equal(politicaVerificacion({ verified: false, games: 1, requireVerified: true }).ok, false);
  assert.equal(politicaVerificacion({ verified: false, games: 2, afterMatches: 3 }).ok, true);
  assert.equal(politicaVerificacion({ verified: false, games: 3, afterMatches: 3 }).ok, false);
});

test('rate limiting con Redis simulado y plantilla de correo', async () => {
  const memoria = new Map();
  const fake = {
    async eval(_script, { keys, arguments: args }) {
      const clave = keys[0];
      const actual = (memoria.get(clave) || 0) + 1;
      memoria.set(clave, actual);
      return [actual, Number(args[0])];
    },
    async del(clave) { memoria.delete(clave); }
  };

  const limitador = new RedisRateLimiter({ cliente: fake, max: 2, windowMs: 60000, nombre: 'test' });
  assert.equal((await limitador.hit('ip')).ok, true);
  assert.equal((await limitador.hit('ip')).ok, true);
  assert.equal((await limitador.hit('ip')).ok, false);
  await limitador.reset('ip');
  assert.equal((await limitador.hit('ip')).ok, true);

  const local = crearLimitador({ max: 1, windowMs: 60000, nombre: 'local' });
  assert.ok(local instanceof AsyncRateLimiter);
  assert.equal((await local.hit('x')).ok, true);
  assert.equal((await local.hit('x')).ok, false);

  const correo = construirCorreo({ purpose: 'verify', code: '123456', username: 'Ana' });
  assert.match(correo.subject, /Verifica/);
  assert.match(correo.text, /123456/);
  assert.match(correo.html, /123456/);
  assert.match(correo.html, /15 minutos/);
});
