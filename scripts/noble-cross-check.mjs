import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const seed = new Uint8Array(32).fill(0x42);
const message = new TextEncoder().encode('message');
const variants = [
  { name: 'ML-DSA-44', noble: ml_dsa44 },
  { name: 'ML-DSA-65', noble: ml_dsa65 },
  { name: 'ML-DSA-87', noble: ml_dsa87 },
];
const outputDir = mkdtempSync(join(tmpdir(), 'mldsa-noble-cross-check-'));

try {
  const rust = spawnSync(
    'cargo',
    ['test', '--features', 'mldsa', '--test', 'mldsa', 'noble_cross_check_exports', '--', '--exact', '--nocapture'],
    { encoding: 'utf8' }
  );
  if (rust.status !== 0) {
    process.stderr.write(rust.stdout);
    process.stderr.write(rust.stderr);
    throw new Error('Rust export test failed');
  }
  const resultLine = rust.stdout.split('\n').find((line) => line.startsWith('NOBLE_CROSS_CHECK='));
  if (!resultLine) throw new Error('Rust test did not emit cross-check data');
  const rustResults = JSON.parse(resultLine.slice('NOBLE_CROSS_CHECK='.length));

  for (const { name, noble } of variants) {
    const rustResult = rustResults[name];
    if (!rustResult) throw new Error(`Rust result missing ${name}`);
    const keys = noble.keygen(seed);
    const publicKey = Buffer.from(keys.publicKey).toString('base64');
    if (publicKey !== rustResult.publicKey) throw new Error(`${name}: public key derived from seed differs`);

    const rustSignature = new Uint8Array(Buffer.from(rustResult.signature, 'base64'));
    if (!noble.verify(rustSignature, message, keys.publicKey)) throw new Error(`${name}: noble rejected Rust signature`);

    const nobleSignature = noble.sign(message, keys.secretKey, { extraEntropy: false });
    writeFileSync(join(outputDir, `${name}.signature`), nobleSignature);
    const checked = spawnSync(
      'cargo',
      ['test', '--features', 'mldsa', '--test', 'mldsa', `noble_cross_check_imports_${name.replaceAll('-', '_').toLowerCase()}`, '--', '--exact'],
      { encoding: 'utf8', env: { ...process.env, NOBLE_SIGNATURE_PATH: join(outputDir, `${name}.signature`) } }
    );
    if (checked.status !== 0) {
      process.stderr.write(checked.stdout);
      process.stderr.write(checked.stderr);
      throw new Error(`Rust rejected noble ${name} signature`);
    }

    console.log(`${name}: seed-derived public key matches; signatures verify in both directions`);
  }
} finally {
  rmSync(outputDir, { recursive: true, force: true });
}
