import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

async function importarMailer(caso) {
  return import(new URL(`../src/mailer.js?caso=${caso}`, import.meta.url).href);
}

function servidorDePrueba(respuesta) {
  let recibido = null;

  const servidor = http.createServer((req, res) => {
    let cuerpo = '';
    req.on('data', (trozo) => { cuerpo += trozo; });
    req.on('end', () => {
      recibido = {
        url: req.url,
        headers: req.headers,
        body: cuerpo ? JSON.parse(cuerpo) : null
      };
      res.writeHead(respuesta.status, { 'Content-Type': 'application/json' });
      res.end(respuesta.body);
    });
  });

  return new Promise((resolver) => {
    servidor.listen(0, '127.0.0.1', () => {
      resolver({ servidor, puerto: servidor.address().port, recibido: () => recibido });
    });
  });
}

test('sanea comillas y espacios en las variables de correo', async () => {
  process.env.NODE_ENV = 'production';
  process.env.MAIL_PROVIDER = 'smtp';
  process.env.SMTP_HOST = '  "smtp.gmail.com"  ';
  process.env.SMTP_PORT = ' 587 ';
  process.env.SMTP_SECURE = ' 0 ';
  process.env.SMTP_USER = " 'Cuenta@Gmail.com' ";
  process.env.SMTP_PASS = ' "clave de prueba" ';
  process.env.SMTP_FROM = '"Caída Online <cuenta@gmail.com>"';
  process.env.SMTP_REPLY_TO = ' "soporte@gmail.com" ';

  const { diagnosticoMailer } = await importarMailer('saneado');
  const diagnostico = diagnosticoMailer();

  assert.equal(diagnostico.canal, 'smtp');
  assert.equal(diagnostico.host, 'smtp.gmail.com');
  assert.equal(diagnostico.puerto, 587);
  assert.equal(diagnostico.usuario, 'cuenta@gmail.com');
  assert.equal(diagnostico.remitente, 'Caída Online <cuenta@gmail.com>');
  assert.equal(diagnostico.passwordConfigurada, true);
});

test('envía por Resend usando HTTPS y limpia la API key', async () => {
  const { servidor, puerto, recibido } = await servidorDePrueba({
    status: 200,
    body: '{"id":"correo-de-prueba"}'
  });

  try {
    process.env.NODE_ENV = 'production';
    process.env.MAIL_PROVIDER = 'resend';
    process.env.RESEND_API_KEY = ' "clave-test" ';
    process.env.MAIL_FROM = '"Caída Online <no-reply@caida.test>"';
    process.env.RESEND_API_URL = `http://127.0.0.1:${puerto}/emails`;

    const { configurarMailer, enviarCodigo } = await importarMailer('resend');

    assert.equal(configurarMailer({ verificar: false }), true);

    const resultado = await enviarCodigo({
      to: 'destino@test.com',
      code: '123456',
      purpose: 'reset',
      username: 'jugador'
    });

    assert.equal(resultado.sent, true);

    const peticion = recibido();
    assert.ok(peticion, 'el servidor local debe recibir la petición');
    assert.equal(peticion.headers.authorization, 'Bearer clave-test');
    assert.equal(peticion.body.from, 'Caída Online <no-reply@caida.test>');
    assert.deepEqual(peticion.body.to, ['destino@test.com']);
    assert.match(peticion.body.subject, /Recupera tu contraseña/);
  } finally {
    servidor.close();
  }
});

test('registra [MAIL_ERROR] con el error completo si el proveedor responde 401', async () => {
  const { servidor, puerto } = await servidorDePrueba({
    status: 401,
    body: '{"message":"API key inválida"}'
  });

  const original = console.error;
  const registros = [];
  console.error = (...args) => { registros.push(args); };

  try {
    process.env.NODE_ENV = 'production';
    process.env.MAIL_PROVIDER = 'resend';
    process.env.RESEND_API_KEY = 'clave-mala';
    process.env.MAIL_FROM = 'Caída Online <no-reply@caida.test>';
    process.env.RESEND_API_URL = `http://127.0.0.1:${puerto}/emails`;

    const { configurarMailer, enviarCodigo } = await importarMailer('error401');
    configurarMailer({ verificar: false });

    const resultado = await enviarCodigo({
      to: 'destino@test.com',
      code: '654321',
      purpose: 'verify',
      username: 'jugador'
    });

    assert.equal(resultado.sent, false);

    const conEtiqueta = registros.find((args) => args[0] === '[MAIL_ERROR]');
    assert.ok(conEtiqueta, 'debe registrar [MAIL_ERROR]');

    const error = conEtiqueta.find((valor) => valor instanceof Error);
    assert.ok(error, 'debe incluir el objeto Error completo');
    assert.equal(error.code, 'HTTP_401');
    assert.match(error.message, /401/);
  } finally {
    console.error = original;
    servidor.close();
  }
});
