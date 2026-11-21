import { enviarAlerta } from './mailer.js';

const WEBHOOK_URL = process.env.ALERT_WEBHOOK_URL || '';
const ALERT_THROTTLE_MS = Number(process.env.ALERT_THROTTLE_MS || 60_000);

let baseDatos = null;
const ultimasAlertas = new Map();

export function configurarAuditoria(db) {
  baseDatos = db;
}

export function auditar({ event, severity = 'info', userId = null, username = null, ip = null, userAgent = null, detail = null }) {
  const evento = {
    event: String(event),
    severity,
    userId,
    username,
    ip,
    userAgent,
    detail
  };

  if (baseDatos) {
    baseDatos.registrarAuditoria(evento).catch((error) => {
      console.error('[auditoria] no se pudo guardar el evento:', error.message);
    });
  }

  if (severity === 'warn' || severity === 'critical') {
    alertar(evento).catch((error) => console.error('[auditoria] alerta fallida:', error.message));
  }
  return evento;
}

async function alertar(evento) {
  const clave = `${evento.event}:${evento.ip || ''}:${evento.userId || ''}`;
  const ahora = Date.now();
  const anterior = ultimasAlertas.get(clave) || 0;
  if (ahora - anterior < ALERT_THROTTLE_MS) return;
  ultimasAlertas.set(clave, ahora);

  const detalle = evento.detail ? ` · ${JSON.stringify(evento.detail)}` : '';
  const texto = `[${evento.severity.toUpperCase()}] ${evento.event}`
    + `\nUsuario: ${evento.username || evento.userId || 'desconocido'}`
    + `\nIP: ${evento.ip || 'desconocida'}`
    + detalle;

  if (WEBHOOK_URL) {
    try {
      await fetch(WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: texto,
          event: evento.event,
          severity: evento.severity,
          username: evento.username,
          userId: evento.userId,
          ip: evento.ip,
          detail: evento.detail,
          timestamp: new Date().toISOString()
        })
      });
    } catch (error) {
      console.error('[auditoria] webhook falló:', error.message);
    }
  }

  await enviarAlerta({ subject: evento.event, text: texto });
}
