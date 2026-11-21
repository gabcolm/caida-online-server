# Caída Online — Backend

Servidor de autenticación, salas, matchmaking y partidas en tiempo real.

## Requisitos

- Node.js **24+** (PostgreSQL mediante `pg`).
- `npm install`.

## Arrancar

```bash
cd Server
npm install
cp .env.example .env
# edita .env con tus credenciales
npm start
```

- HTTP: `http://localhost:3000/api`
- WebSocket: `ws://localhost:3000/ws?token=...`
- Base de datos: PostgreSQL (`DATABASE_URL`). El esquema y los índices se crean solos al arrancar.

### Archivo `.env`

`src/env.js` se importa como **primera línea** de `src/index.js`, antes de
cualquier módulo que lea `process.env`, y carga `Server/.env` con `dotenv`.
Las variables ya definidas por el sistema tienen prioridad y no se
sobreescriben.

- Copia `.env.example` a `.env` y rellena tus valores.
- No subas `.env` al repositorio (ya está en `.gitignore`).
- Si usas otro archivo, define `ENV_FILE=/ruta/al/archivo`.
- Los tests usan `ENV_FILE` apuntando a un archivo temporal para no depender
  de tu `.env`.
- Asegúrate de que el archivo se llame exactamente `.env`, no `.env.txt`.

Variables de entorno:

| Variable | Default | Descripción |
|---|---|---|
| `PORT` | `3000` | Puerto HTTP/WS |
| `DATABASE_URL` | `postgresql://caida@localhost:5432/caida_online` | Cadena de conexión PostgreSQL (Neon en producción) |
| `TURN_MS` | `30000` | Tiempo máximo por turno |
| `RECONNECT_MS` | `45000` | Gracia de reconexión en sala de espera |
| `CORS_ORIGIN` | `*` | Origen permitido (separa varios con coma) |
| `TLS_CERT` / `TLS_KEY` | vacío | Rutas al certificado y clave PEM para HTTPS/WSS |
| `TRUST_PROXY` | `0` | Usa `X-Forwarded-For` y `X-Forwarded-Proto` detrás de un proxy |
| `REDIS_URL` | vacío | Redis para rate limiting distribuido (`redis://...`) |
| `API_RATE_MAX` | `300` | Solicitudes API por IP y minuto |
| `AUTH_RATE_MAX` | `30` | Solicitudes de autenticación por IP y minuto |
| `LOGIN_FAIL_MAX` | `8` | Fallos de login por usuario/IP antes de bloquear 15 min |
| `WS_RATE_MAX` | `60` | Mensajes WebSocket por ventana |
| `WS_RATE_WINDOW_MS` | `10000` | Ventana del límite WebSocket |
| `DEV_CODES` | `0` | Devuelve `devCode` en las respuestas (solo desarrollo) |
| `REQUIRE_EMAIL` | `0` | Exige correo al registrarse |
| `REQUIRE_VERIFIED` | `0` | Bloquea el juego online hasta verificar el correo |
| `VERIFY_AFTER_MATCHES` | `0` | Partidas de gracia antes de exigir verificación (0 = desactivado) |
| `RECOVERY_CODE_TTL_MIN` | `15` | Minutos de validez del código de recuperación (mínimo 15) |
| `VERIFY_CODE_TTL_MIN` | `15` | Minutos de validez del código de verificación (mínimo 15) |
| `TOTP_ISSUER` | `Caída Online` | Nombre que aparece en la app autenticadora |
| `SMTP_URL` | vacío | URL SMTP (`smtps://usuario:clave@smtp.ejemplo.com:465`) |
| `SMTP_HOST` / `SMTP_PORT` | vacío / `587` | Alternativa a `SMTP_URL` |
| `SMTP_SECURE` | `0` | `1` para SSL directo (puerto 465) |
| `SMTP_USER` / `SMTP_PASS` | vacío | Credenciales SMTP |
| `SMTP_FROM` | `Caída Online <no-reply@caida.local>` | Remitente de los correos |
| `SMTP_REPLY_TO` | vacío | Reply-To opcional |
| `DKIM_DOMAIN` | vacío | Dominio firmado con DKIM |
| `DKIM_SELECTOR` | `caida` | Selector DKIM |
| `DKIM_PRIVATE_KEY` | vacío | Ruta o PEM de la clave privada DKIM |
| `ALERT_WEBHOOK_URL` | vacío | Webhook para alertas (Slack/Discord) |
| `ALERT_EMAIL` | vacío | Correo alternativo para alertas |
| `ALERT_FAIL_THRESHOLD` | `3` | Intentos antes de marcar un login como sospechoso |
| `ALERT_THROTTLE_MS` | `60000` | Anti-spam de alertas por evento/IP |
| `ADMIN_TOKEN` | vacío | Token para `GET /api/admin/audit` |
| `AUDIT_RETENTION_DAYS` | `90` | Días de retención de la auditoría |
| `NODE_ENV` | vacío | En `production` no se registran códigos en consola |

## HTTPS/WSS

Para TLS directo:

```bash
TLS_CERT=/ruta/cert.pem TLS_KEY=/ruta/key.pem npm start
```

El mismo puerto sirve `https://` y `wss://`. En producción también puedes
terminar TLS en un proxy (Caddy, Nginx, Traefik) y arrancar el backend en HTTP
con `TRUST_PROXY=1`; el cliente ya convierte `https://` en `wss://`.

## API HTTP

- `GET /api/health`
- `POST /api/register` `{ "username": "...", "password": "...", "email": "..." }`
- `POST /api/login`
- `GET /api/me` con `Authorization: Bearer <token>` (incluye `stats`)
- `POST /api/logout`
- `GET /api/ranking?limit=20` (requiere sesión)
- `GET /api/history?limit=20` (requiere sesión)
- `POST /api/account/email` `{ "email": "...", "password": "..." }` (sesión)
- `POST /api/verify/request` (sesión)
- `POST /api/verify` `{ "code": "123456" }` (sesión)
- `POST /api/recovery/request` `{ "identifier": "alias o correo" }`
- `POST /api/recovery/reset` `{ "identifier": "...", "code": "123456", "password": "..." }`
- `POST /api/recover` (alias de `recovery/request` para el flujo plug-and-play)
- `POST /api/recover/verify` `{ "identifier": "...", "code": "123456" }` (valida sin consumir el código)
- `POST /api/2fa/setup` (sesión) → `secret`, `otpauth` y `qr` (data URL PNG)
- `POST /api/2fa/enable` `{ "code": "123456" }` (sesión) → códigos de recuperación
- `POST /api/2fa/disable` `{ "code": "123456" }` (sesión)
- `POST /api/2fa/recovery` `{ "code": "123456" }` (sesión, regenera códigos)
- `POST /api/login/2fa` `{ "challengeToken": "...", "code": "123456" }`
- `GET /api/admin/audit?limit=100` con cabecera `x-admin-token`
- `GET /admin/auditoria` panel web para consultar la auditoría

Flujo de login con 2FA:

1. `POST /api/login` responde `{ "requires2fa": true, "challengeToken": "..." }`.
2. La app pide el código TOTP o un código de recuperación.
3. `POST /api/login/2fa` devuelve el token de sesión definitivo.

Los códigos de recuperación se muestran una sola vez al activar/regenerar 2FA.
El desafío de login vence en 5 minutos y admite 5 intentos.

Las contraseñas se guardan con `scrypt` + sal. Los tokens son opacos, aleatorios
y viven 30 días en PostgreSQL. Al cambiar la contraseña se revocan todas las
sesiones de esa cuenta.

Los códigos de verificación/recuperación son de 6 dígitos, vencen en 15 minutos
(configurable con `RECOVERY_CODE_TTL_MIN` y `VERIFY_CODE_TTL_MIN`; el mínimo es
15), admiten 5 intentos y se guardan con sal + SHA-256. Si `SMTP_URL` no está
configurado, en desarrollo el código se imprime en la consola y, con
`DEV_CODES=1`, también se devuelve en la respuesta para probar la UI. En
producción configura SMTP y deja `DEV_CODES=0`.

`POST /api/recover` responde de inmediato con `{ "success": true }` y deja el
envío de Nodemailer en segundo plano (fire-and-forget). El correo puede tardar
un minuto en llegar; el código ya está creado y sigue siendo válido durante su
TTL.

Las partidas terminadas se guardan en `matches` y `match_players` con el
código/tipo de sala, marcador, manos, duración, asiento, equipo y resultado de
cada jugador. El ranking se calcula con esas tablas (victorias, derrotas,
efectividad y puntos) y el historial devuelve las últimas mesas del jugador con
compañeros y rivales.

## Verificación progresiva

- `REQUIRE_VERIFIED=1` bloquea el matchmaking y las salas hasta verificar.
- `VERIFY_AFTER_MATCHES=N` deja jugar N partidas y después exige verificación.
  Se puede combinar con `REQUIRE_VERIFIED`: el bloqueo inmediato tiene prioridad.
- Al bloquear se registra `play_blocked_unverified` y se envía el código
  `VERIFY_REQUIRED` por WebSocket; el cliente abre **Mi Cuenta**.

## 2FA (TOTP)

- Se genera un secreto base32 de 20 bytes y se muestra para agregarlo
  manualmente a Google Authenticator, Authy, 1Password, etc.
- El setup devuelve también un QR en data URL (`qr`) que Unity muestra en un
  popup; el secreto sigue disponible con el botón **COPIAR SECRETO**.
- Códigos de 6 dígitos, ventana ±30 s.
- 8 códigos de recuperación de un solo uso, guardados con sal + SHA-256.
- El desafío de login vence en 5 minutos y admite 5 intentos.
- Desactivar 2FA exige un código TOTP actual.

## Rate limiting distribuido

Con `REDIS_URL` configurado, los límites de API/autenticación/fallos de login
se guardan en Redis y se comparten entre instancias. La clave es
`caida:rl:<nombre>:<ip>` y usa un script Lua atómico con `INCR` + `PEXPIRE`.
Si Redis no responde, el servidor cae a límites locales y lo advierte en el
log. El límite por conexión WebSocket sigue siendo local.

## Auditoría y alertas

La tabla `audit_log` guarda registro, login, fallos, bloqueos, cambios de
correo/clave, verificación, 2FA, partidas terminadas y lecturas del panel de
administración, con IP y user-agent.

- `GET /api/admin/audit?limit=100` (cabecera `x-admin-token`) devuelve los
  últimos eventos; sin `ADMIN_TOKEN` la ruta responde 404.
- `GET /admin/auditoria` sirve una página web autocontenida para consultar los
  eventos con el token (no se guarda en navegador ni URL).
- Los eventos `warn`/`critical` se envían a `ALERT_WEBHOOK_URL` (JSON con
  `text`) y/o a `ALERT_EMAIL`.
- Los fallos de login se marcan sospechosos al acercarse al límite; un login
  desde una IP distinta a la última genera `login_new_ip`.
- Las alertas tienen throttling por evento/IP (`ALERT_THROTTLE_MS`).

## Correo, SPF/DKIM/DMARC

Se envían plantillas HTML + texto para verificación y recuperación, con código
destacado y aviso de vencimiento. Para entrega real:

- Configura `SMTP_URL` o `SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/`SMTP_PASS`.
- Configura `SMTP_FROM` con un dominio propio.
- Publica registros DNS:
  - **SPF**: `v=spf1 include:<proveedor> ~all`
  - **DKIM**: `<selector>._domainkey` con la clave pública del proveedor.
    Si firmas tú, define `DKIM_DOMAIN`, `DKIM_SELECTOR` y `DKIM_PRIVATE_KEY`.
  - **DMARC**: `_dmarc` con `v=DMARC1; p=quarantine; rua=mailto:...`
- Verifica el dominio en el proveedor y evita enviar desde `no-reply@caida.local`
  en producción.

### Diagnóstico de correo

Si el servidor dice “SMTP configurado” pero el correo no llega:

```bash
cd Server
npm run mail:test -- tu@correo.com
```

El comando:

1. carga `.env`,
2. ejecuta `transporter.verify()` (conexión + login),
3. envía un correo de prueba,
4. imprime el objeto `info` de Nodemailer:
   - `messageId`
   - `accepted`
   - `rejected`
   - `pending`
   - `response`

Revisa también los logs `[seguridad] SMTP verify...` y
`[seguridad] sendMail info:`.

Para Gmail:

- Usa una **contraseña de aplicación** de 16 caracteres (requiere 2FA),
  no la contraseña normal.
- `SMTP_HOST=smtp.gmail.com`
- `SMTP_PORT=587`, `SMTP_SECURE=0` (STARTTLS)
  o `SMTP_PORT=465`, `SMTP_SECURE=1` (SSL directo)
- `SMTP_USER` debe ser el correo completo de Gmail.
- `SMTP_FROM` debe usar la misma cuenta (o un alias verificado).
- Si `info.rejected` contiene el destinatario, Gmail rechazó la entrega.
- Si `verify()` falla con `EAUTH`, la contraseña de aplicación es incorrecta
  o fue revocada.

`SMTP_DEBUG=1` muestra el protocolo SMTP completo, pero puede incluir datos
sensibles; úsalo solo en local y nunca en producción.

## WebSocket

Mensajes cliente → servidor:

```json
{ "type": "quickMatch" }
{ "type": "cancelQueue" }
{ "type": "createRoom" }
{ "type": "joinRoom", "code": "ABC123" }
{ "type": "startRoom" }
{ "type": "leaveRoom" }
{ "type": "playCard", "cardId": "Oro_1" }
{ "type": "voteTribilin", "vote": 1 }
{ "type": "sync" }
```

`vote` usa `1` = sí (mata partida, 24 pts) y `2` = no (5 pts).

Mensajes servidor → cliente:

- `hello`
- `queue` (`count`, `position`)
- `roomState` (`room`)
- `gameState` (`room`, `state`)
- `leftRoom`, `noRoom`
- `error` (`message`)
- `pong`

`gameState.state` incluye `ownHand` solo para el jugador destinatario,
`handCounts`, `table`, `scores`, `captured`, `turnSeat`, `dealerSeat`,
`phase`, `winnerTeam`, `lastEvent`, `sorteo`, `tribilinMata`, `votosEmitidos`,
`tuVoto`, `dealNumber`, `cantos` (los cantos visibles de la mesa) y
`cantoHistorial` (últimos 14 movimientos de cantos de la partida). La Ronda
oculta solo se envía a su dueño, tanto en `cantos` como en el historial.

## Reglas implementadas

- Baraja española de 40 cartas.
- Votación del Tribilín antes de repartir; el empate se resuelve al azar y los
  votos faltantes se completan al vencer el tiempo.
- Sorteo de mano con una carta por jugador y desempate automático.
- Mesa inicial de 4 valores distintos.
- Reparto de 3 cartas, tres repartos por mano (40 cartas).
- Turnos de 4 jugadores; equipos por paridad de asiento (0/2 vs 1/3).
- Captura por coincidencia y valores consecutivos (1→…→7→10→11→12).
- Cantos con la mano inicial: Ronda, Vigía, Patrulla, Tribilín y Registro.
  Se comparan por rango, valor alto y distancia a la mano; el ganador cobra
  una sola vez al final de la mano. La Ronda queda oculta hasta que su dueño
  juega las dos cartas del par ("Ronda Vista") y no cobra si nunca se vio.
- Canto "pa' viaje": si el canto ganador alcanza los 24 puntos, se cobra de
  inmediato y cierra la partida.
- Caída, mesa limpia, mayoría de cartas y carrera a 24 puntos.
- Turno automático a los 30 s para evitar bloqueos.
- Reconexión con snapshot personalizado.

Pendiente para la siguiente fase: apuestas online, torneos, espectadores,
paginación/ranking por temporadas y passkeys.

## Pruebas

```bash
npm test
```

Incluye pruebas del motor (cantos, Ronda oculta, votación, sorteo, turnos),
autenticación, matchmaking, reconexión, salas privadas, códigos inválidos,
partida completa, persistencia de ranking/historial, rate limiting local y
Redis simulado, verificación de correo, recuperación de contraseña, 2FA TOTP,
códigos de recuperación y auditoría.

## Herramientas

`node tools/bots.js` registra 3 bots, entra al matchmaking y juega
automáticamente. Sirve para probar la mesa desde Unity.

## Producción

- Poner el servidor detrás de **HTTPS/WSS** (TLS directo o proxy inverso).
- Configurar `SMTP_URL`/credenciales, `SMTP_FROM` propio, DKIM y DNS
  (SPF/DMARC), `NODE_ENV=production` y `DEV_CODES=0`.
- Configurar `REDIS_URL` para rate limiting compartido entre instancias.
- Revisar `CORS_ORIGIN` con el dominio real y mantener `TRUST_PROXY=1` solo si
  hay un proxy de confianza delante.
- Definir `ADMIN_TOKEN`, `ALERT_WEBHOOK_URL`/`ALERT_EMAIL` y revisar
  `GET /api/admin/audit`.
- Migrar a PostgreSQL/Redis si se espera más de una instancia.
- No subir `node_modules/`, `data/`, `.env` ni logs al repositorio.

## Despliegue en Render

Configuración del Web Service:

| Campo | Valor |
|---|---|
| Runtime | Node |
| Build Command | `npm ci` |
| Start Command | `npm start` (`node src/index.js`) |
| Health Check Path | `/api/health` |
| Root Directory | `Server` (si el repo incluye el proyecto Unity) |

El backend escucha en `process.env.PORT` (lo asigna Render) sobre `0.0.0.0`,
y `GET /api/health` responde `200` con `{"ok":true,...}` sin tocar la base.

**Versión de Node:** el backend usa PostgreSQL mediante `pg` y `DATABASE_URL`.
`package.json` exige **Node 24+** para igualar el entorno probado.

Variables de entorno en el panel de Render (nunca en el repositorio):

```text
NODE_ENV=production
DEV_CODES=0
TRUST_PROXY=1
CORS_ORIGIN=*
ADMIN_TOKEN=un-token-largo
DATABASE_URL=postgresql://usuario:clave@ep-xxxx.region.aws.neon.tech/neondb?sslmode=require

# Correo por API HTTP (Render Free bloquea los puertos SMTP)
MAIL_PROVIDER=resend
RESEND_API_KEY=re_...
MAIL_FROM="Caída Online <no-reply@tudominio.com>"
```

Las variables `SMTP_*` solo sirven en local o en instancias de pago: Render Free
bloquea la salida a los puertos 25, 465 y 587.

No definas `PORT`: Render lo inyecta. Si `RENDER=true` (lo pone Render), el
servidor activa `TRUST_PROXY` automáticamente para leer `X-Forwarded-For` y
`X-Forwarded-Proto`. El WebSocket viaja por el mismo puerto y Render lo expone
como `wss://`; en Unity usa `https://<servicio>.onrender.com`.

### Correo en Render

Render **Free** bloquea el tráfico saliente a los puertos SMTP `25`, `465` y
`587`; con Gmail verás `ETIMEDOUT` en los logs y el correo nunca sale. Para el
plan gratuito usa un proveedor por HTTPS (443):

- **Resend** (recomendado, 100 correos/día):
  1. Crea una cuenta y una API key (`re_...`).
  2. Verifica tu dominio, o usa `onboarding@resend.dev` para pruebas.
  3. En Render define `MAIL_PROVIDER=resend`, `RESEND_API_KEY` y `MAIL_FROM`.
- **Brevo** (300 correos/día): `MAIL_PROVIDER=brevo`, `BREVO_API_KEY` y
  `MAIL_FROM`.
- `MAIL_PROVIDER=smtp` fuerza el envío por SMTP (local o instancia de pago).

El servidor acepta `SMTP_*`, `MAIL_*`, `RESEND_*` y `BREVO_*` con o sin comillas
y con espacios sobrantes: `env.js` los limpia al arrancar.

En los logs de Render busca:

- `[seguridad] correo por API HTTP (resend)` y `[seguridad] diagnóstico correo`
  al arrancar.
- `[MAIL_OK] correo ... aceptado por ...` cuando el proveedor acepta el envío.
- `[MAIL_ERROR]` con el error completo si falla: `ETIMEDOUT`/`ECONNREFUSED`
  (puerto bloqueado), `EAUTH` (credenciales SMTP) o `HTTP_401`/`HTTP_403`
  (API key incorrecta o dominio sin verificar).
- `[recovery] solicitud recibida { cuentaEncontrada, tieneCorreo }` para saber si
  la cuenta existe en la base de datos de Render.

> `POST /api/recover` responde siempre `200 {"sent":true}` aunque el usuario o
> su correo no existan (evita enumerar cuentas). Si la base de Render está
> vacía o la cuenta no tiene correo, no se envía nada: revisa el log
> `[recovery] solicitud recibida`.

### Persistencia de datos (PostgreSQL / Neon)

- Usuarios, monedas, ranking, historial, códigos y auditoría viven en PostgreSQL
  (`DATABASE_URL`, por ejemplo la cadena de Neon).
- La base **no** depende del disco efímero de Render: sobrevive a deploys,
  reinicios y spin-down.
- Al arrancar se ejecutan `CREATE TABLE IF NOT EXISTS` e índices; no hay que
  crear el esquema a mano.
- En local usa `DATABASE_URL=postgresql://caida:...@localhost:5432/caida_online`
  y `DATABASE_URL_TEST=...caida_online_test` para `npm test`.
- Neon Free incluye 0.5 GB y escala a cero; la primera consulta tras
  inactividad puede tardar alrededor de un segundo.
- El plan free de Render suspende el servicio tras ~15 minutos sin tráfico: la
  primera petición puede tardar ~50 s y los WebSocket se cortan en cada deploy.

