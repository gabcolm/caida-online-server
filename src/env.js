import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rutaEnv = process.env.ENV_FILE || path.join(__dirname, '..', '.env');

// dotenv no sobreescribe variables ya definidas por el sistema.
// ENV_FILE permite usar otro archivo (por ejemplo, en pruebas).
dotenv.config({ path: rutaEnv, quiet: true });

export const ENV_PATH = rutaEnv;
