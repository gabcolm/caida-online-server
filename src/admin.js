export function paginaAuditoria() {
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditoría · Caída Online</title>
<style>
  :root { --fieltro:#0e3b2c; --oscuro:#07100d; --crema:#fbf3e2; --sec:#c9b99a; --oro:#e8b04b; --rojo:#c0453b; --verde:#5fbf7a; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--oscuro); color:var(--crema); font-family:system-ui,Segoe UI,Roboto,sans-serif; }
  header { background:linear-gradient(135deg,#0e3b2c,#08271d); border-bottom:1px solid #3b2416; padding:22px 24px; }
  h1 { margin:0; font-size:24px; letter-spacing:1px; }
  .sub { color:var(--sec); font-size:13px; margin-top:6px; }
  main { padding:24px; max-width:1400px; margin:0 auto; }
  .barra { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:18px; }
  input { flex:1; min-width:260px; background:#0b2a21; color:var(--crema); border:1px solid #3b2416; border-radius:10px; padding:12px 14px; font-size:14px; }
  button { background:var(--oro); color:#25180f; border:0; border-radius:10px; padding:12px 20px; font-weight:700; cursor:pointer; }
  button:hover { filter:brightness(1.08); }
  #estado { color:var(--sec); font-size:13px; }
  .tabla { overflow:auto; border:1px solid #3b2416; border-radius:14px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { text-align:left; background:#0b2a21; color:var(--sec); font-size:11px; letter-spacing:1px; padding:12px; position:sticky; top:0; }
  td { padding:10px 12px; border-top:1px solid rgba(255,255,255,.06); vertical-align:top; }
  tr:hover td { background:rgba(255,255,255,.03); }
  .sev { display:inline-block; border-radius:999px; padding:3px 9px; font-size:11px; font-weight:700; text-transform:uppercase; }
  .info { background:rgba(95,191,122,.15); color:var(--verde); }
  .warn { background:rgba(232,176,75,.15); color:var(--oro); }
  .critical { background:rgba(192,69,59,.18); color:#ff8a7d; }
  .detalle { color:var(--sec); font-family:ui-monospace,Consolas,monospace; font-size:11px; max-width:420px; word-break:break-word; }
  .vacio { text-align:center; color:var(--sec); padding:40px; }
  .nota { color:var(--sec); font-size:12px; margin-top:14px; line-height:1.5; }
</style>
</head>
<body>
<header>
  <h1>Auditoría · Caída Online</h1>
  <div class="sub">Accesos, 2FA, correo, bloqueos y partidas. Requiere el token de administración.</div>
</header>
<main>
  <div class="barra">
    <input id="token" type="password" placeholder="ADMIN_TOKEN" autocomplete="off">
    <button id="cargar">CARGAR EVENTOS</button>
    <span id="estado"></span>
  </div>
  <div class="tabla">
    <table>
      <thead><tr><th>Fecha</th><th>Evento</th><th>Severidad</th><th>Usuario</th><th>IP</th><th>Detalle</th></tr></thead>
      <tbody id="filas"><tr><td colspan="6" class="vacio">Introduce el token y pulsa CARGAR EVENTOS.</td></tr></tbody>
    </table>
  </div>
  <div class="nota">El token no se guarda en el navegador ni en la URL. Si la ruta responde 404, falta configurar <code>ADMIN_TOKEN</code> en el servidor.</div>
</main>
<script>
  const input = document.getElementById('token');
  const boton = document.getElementById('cargar');
  const estado = document.getElementById('estado');
  const filas = document.getElementById('filas');

  function esc(valor) {
    return String(valor == null ? '' : valor)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fecha(ms) {
    try { return new Date(ms).toLocaleString('es-VE'); } catch (e) { return String(ms); }
  }

  function render(lista) {
    if (!lista || lista.length === 0) {
      filas.innerHTML = '<tr><td colspan="6" class="vacio">No hay eventos.</td></tr>';
      return;
    }
    filas.innerHTML = lista.map(function (e) {
      const sev = ['info', 'warn', 'critical'].indexOf(e.severity) >= 0 ? e.severity : 'info';
      const detalle = e.detail ? JSON.stringify(e.detail) : '';
      return '<tr>'
        + '<td>' + esc(fecha(e.createdAt)) + '</td>'
        + '<td><strong>' + esc(e.event) + '</strong></td>'
        + '<td><span class="sev ' + sev + '">' + esc(e.severity) + '</span></td>'
        + '<td>' + esc(e.username || (e.userId == null ? '' : '#' + e.userId)) + '</td>'
        + '<td>' + esc(e.ip || '') + '</td>'
        + '<td class="detalle">' + esc(detalle) + '</td>'
        + '</tr>';
    }).join('');
  }

  async function cargar() {
    const token = input.value.trim();
    if (!token) { estado.textContent = 'Escribe el ADMIN_TOKEN.'; estado.style.color = 'var(--rojo)'; return; }
    estado.textContent = 'Cargando...'; estado.style.color = 'var(--sec)';
    try {
      const r = await fetch('/api/admin/audit?limit=200', { headers: { 'x-admin-token': token } });
      const texto = await r.text();
      if (!r.ok) {
        estado.textContent = 'Error ' + r.status + ': ' + texto;
        estado.style.color = 'var(--rojo)';
        return;
      }
      const data = JSON.parse(texto);
      render(data.audit || []);
      estado.textContent = 'Eventos cargados: ' + (data.audit ? data.audit.length : 0);
      estado.style.color = 'var(--verde)';
    } catch (e) {
      estado.textContent = 'No se pudo conectar: ' + e.message;
      estado.style.color = 'var(--rojo)';
    }
  }

  boton.addEventListener('click', cargar);
  input.addEventListener('keydown', function (e) { if (e.key === 'Enter') cargar(); });
</script>
</body>
</html>`;
}
