import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

const ALFABETO_BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Limitador de ventana fija por clave (IP, usuario, socket...). */
export class RateLimiter {
  constructor({ max, windowMs, nombre = 'limite' }) {
    this.max = Math.max(1, Number(max) || 1);
    this.windowMs = Math.max(1000, Number(windowMs) || 60000);
    this.nombre = nombre;
    this.buckets = new Map();
  }

  hit(clave, ahora = Date.now()) {
    const key = String(clave || 'anon');
    let bucket = this.buckets.get(key);
    if (!bucket || bucket.reset <= ahora) {
      bucket = { count: 0, reset: ahora + this.windowMs };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;
    const restantes = Math.max(0, this.max - bucket.count);
    return {
      ok: bucket.count <= this.max,
      restantes,
      retryAfter: Math.max(1, Math.ceil((bucket.reset - ahora) / 1000)),
      reset: bucket.reset
    };
  }

  reset(clave) {
    this.buckets.delete(String(clave || 'anon'));
  }

  limpiar(ahora = Date.now()) {
    for (const [clave, bucket] of this.buckets) {
      if (bucket.reset <= ahora) this.buckets.delete(clave);
    }
  }
}

export function ipDeRequest(req, trustProxy = false) {
  if (trustProxy) {
    const reenviada = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (reenviada) return reenviada;
  }
  return req.socket?.remoteAddress || 'desconocido';
}

export function generarCodigo(digitos = 6) {
  const max = 10 ** digitos;
  return String(randomInt(0, max)).padStart(digitos, '0');
}

export function generarSalt() {
  return randomBytes(16).toString('hex');
}

export function hashCodigo(codigo, salt) {
  return createHash('sha256').update(`${salt}:${String(codigo).trim()}`).digest('hex');
}

export function compararCodigo(codigo, salt, hashEsperado) {
  const calculado = Buffer.from(hashCodigo(codigo, salt), 'hex');
  const esperado = Buffer.from(String(hashEsperado || ''), 'hex');
  if (calculado.length !== esperado.length) return false;
  return timingSafeEqual(calculado, esperado);
}

export function normalizarEmail(email) {
  return String(email ?? '').trim().toLowerCase();
}

export function validarEmail(email) {
  const limpio = String(email ?? '').trim();
  if (!limpio) return 'Escribe un correo electrónico.';
  if (limpio.length > 254) return 'El correo es demasiado largo.';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/u.test(limpio)) return 'El correo no tiene un formato válido.';
  return null;
}

export function validarPassword(password) {
  const texto = String(password ?? '');
  if (texto.length < 6) return 'La contraseña debe tener al menos 6 caracteres.';
  if (texto.length > 72) return 'La contraseña es demasiado larga.';
  return null;
}

export function base32Codificar(buffer) {
  let bits = 0;
  let valor = 0;
  let salida = '';
  for (const byte of buffer) {
    valor = (valor << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      salida += ALFABETO_BASE32[(valor >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) salida += ALFABETO_BASE32[(valor << (5 - bits)) & 31];
  return salida;
}

export function base32Decodificar(texto) {
  const limpio = String(texto || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let valor = 0;
  const bytes = [];
  for (const caracter of limpio) {
    const indice = ALFABETO_BASE32.indexOf(caracter);
    if (indice < 0) continue;
    valor = (valor << 5) | indice;
    bits += 5;
    if (bits >= 8) {
      bytes.push((valor >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function generarSecretoTotp() {
  return base32Codificar(randomBytes(20));
}

function hotp(secretoBuffer, contador, digitos = 6) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(contador));
  const hash = createHmac('sha1', secretoBuffer).update(buffer).digest();
  const offset = hash[hash.length - 1] & 0x0f;
  const codigo = ((hash[offset] & 0x7f) << 24)
    | ((hash[offset + 1] & 0xff) << 16)
    | ((hash[offset + 2] & 0xff) << 8)
    | (hash[offset + 3] & 0xff);
  return String(codigo % (10 ** digitos)).padStart(digitos, '0');
}

export function codigoTotp(secreto, ahora = Date.now(), pasoMs = 30000) {
  return hotp(base32Decodificar(secreto), Math.floor(ahora / pasoMs));
}

export function verificarTotp(secreto, codigo, ventana = 1, ahora = Date.now(), pasoMs = 30000) {
  const limpio = String(codigo ?? '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(limpio)) return false;
  const secretoBuffer = base32Decodificar(secreto);
  if (secretoBuffer.length === 0) return false;
  const contador = Math.floor(ahora / pasoMs);
  const esperado = Buffer.from(limpio);
  for (let delta = -ventana; delta <= ventana; delta++) {
    const calculado = Buffer.from(hotp(secretoBuffer, contador + delta));
    if (calculado.length === esperado.length && timingSafeEqual(calculado, esperado)) return true;
  }
  return false;
}

export function urlTotp(secreto, usuario, emisor = 'Caída Online') {
  const etiqueta = encodeURIComponent(`${emisor}:${usuario || 'jugador'}`);
  return `otpauth://totp/${etiqueta}?secret=${encodeURIComponent(secreto)}&issuer=${encodeURIComponent(emisor)}&algorithm=SHA1&digits=6&period=30`;
}

export function politicaVerificacion({ verified, games, requireVerified = false, afterMatches = 0 }) {
  if (verified) return { ok: true, motivo: null };
  if (requireVerified) {
    return { ok: false, motivo: 'Verifica tu correo en Mi Cuenta antes de jugar online.' };
  }
  const limite = Number(afterMatches) || 0;
  if (limite > 0 && Number(games) >= limite) {
    return {
      ok: false,
      motivo: `Ya jugaste ${games} partidas. Verifica tu correo en Mi Cuenta para seguir jugando online.`
    };
  }
  return { ok: true, motivo: null };
}

const LUA_RATE_LIMIT = `
local actual = redis.call('INCR', KEYS[1])
if actual == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return { actual, ttl }
`;

export class RedisRateLimiter {
  constructor({ cliente, max, windowMs, nombre = 'limite' }) {
    this.cliente = cliente;
    this.max = Math.max(1, Number(max) || 1);
    this.windowMs = Math.max(1000, Number(windowMs) || 60000);
    this.nombre = nombre;
  }

  clave(clave) {
    return `caida:rl:${this.nombre}:${String(clave || 'anon')}`;
  }

  async hit(clave) {
    const respuesta = await this.cliente.eval(LUA_RATE_LIMIT, {
      keys: [this.clave(clave)],
      arguments: [String(this.windowMs)]
    });
    const conteo = Number(respuesta[0]);
    const ttl = Number(respuesta[1]);
    return {
      ok: conteo <= this.max,
      restantes: Math.max(0, this.max - conteo),
      retryAfter: Math.max(1, Math.ceil(ttl / 1000)),
      reset: Date.now() + Math.max(0, ttl)
    };
  }

  async reset(clave) {
    await this.cliente.del(this.clave(clave));
  }

  limpiar() { /* Redis expira las claves solo. */ }
}

export class AsyncRateLimiter {
  constructor(opciones) {
    this.local = new RateLimiter(opciones);
  }

  async hit(clave) {
    return this.local.hit(clave);
  }

  async reset(clave) {
    this.local.reset(clave);
  }

  limpiar() {
    this.local.limpiar();
  }
}

export function crearLimitador({ clienteRedis, ...opciones }) {
  return clienteRedis
    ? new RedisRateLimiter({ cliente: clienteRedis, ...opciones })
    : new AsyncRateLimiter(opciones);
}

