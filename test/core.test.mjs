import { spawnSync } from 'node:child_process';

const script = new URL('../core.test.mjs', import.meta.url);
const result = spawnSync(process.execPath, [script.pathname], {
  stdio: 'inherit',
  env: process.env,
});

if (result.error) {
  throw result.error;
}

process.exit(result.status ?? 1);
