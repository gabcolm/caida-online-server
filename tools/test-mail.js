import '../src/env.js';
import { configurarMailer, enviarCodigo, verificarMailer } from '../src/mailer.js';

const destino = process.argv[2];

if (!destino) {
  console.error('Uso: npm run mail:test -- tu@correo.com');
  process.exit(1);
}

if (!configurarMailer({ verificar: false })) {
  console.error('SMTP no está configurado. Revisa Server/.env');
  process.exit(1);
}

const verificado = await verificarMailer();
if (!verificado) {
  console.error('La conexión/autenticación SMTP falló. Revisa host, puerto, usuario y contraseña de aplicación.');
  process.exit(1);
}

console.log(`[mail:test] Enviando correo de prueba a ${destino}...`);
const resultado = await enviarCodigo({
  to: destino,
  code: '123456',
  purpose: 'verify',
  username: 'prueba'
});

console.log('[mail:test] Resultado:', resultado);
process.exit(resultado.sent ? 0 : 1);
