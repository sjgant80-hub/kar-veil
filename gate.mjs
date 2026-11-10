// gate.mjs — the mutation-gate receipt for Kar-Veil's two kernels.
//
//   node gate.mjs            run witness v0.6 (from .witness/, every mutant, no cap) on each kernel against its tests,
//                            and write receipts/gate.json: per kernel the SHA-256 of the kernel and its tests (as git
//                            stores them, LF), mutants, killed, survivors and reviewed exemptions
//   node gate.mjs --verify   exit 1 unless the committed receipt is clean, uncapped, and names THESE kernels and tests
//
// CI runs --verify, and runs the same witness gate itself on GitHub's runner; the page reads its counts from the receipt.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const RECEIPT = 'receipts/gate.json';
const WITNESS = '.witness/witness.mjs';
const WITNESS_V06_SHA256 = '9918297aa5f8fc4e1d26d9e6b25226f56102fdc04f0c634155bfcba1c086ef48';
export const KERNELS = [
  { file: 'veil.mjs', tests: ['veil.test.mjs'], what: 'commit, prove and verify: the logic the page runs' },
  { file: 'veilcase.mjs', tests: ['veilcase.test.mjs'], what: 'the cost case, from the sourced basis' },
];
const shaLF = (p) => createHash('sha256').update(fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n')).digest('hex');

function run() {
  if (shaLF(WITNESS) !== WITNESS_V06_SHA256) { console.error(WITNESS + ' is not witness v0.6: git clone --depth 1 --branch v0.6 https://github.com/sjgant80-hub/witness .witness'); process.exit(2); }
  const kernels = [];
  for (const k of KERNELS) {
    const r = spawnSync(process.execPath, [WITNESS, 'mutate', k.file, '--timeout', '60000', '--cap', '100000', '--test', 'node', '--test', ...k.tests], { encoding: 'utf8', maxBuffer: 1 << 26 });
    const out = r.stdout;
    const j = JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
    kernels.push({
      file: k.file, what: k.what, sha256: shaLF(k.file),
      tests: 'node --test ' + k.tests.join(' '), testsSha256: k.tests.map(shaLF).join(','),
      total: j.total, killed: j.killed, survived: j.survived, ignored: j.ignored, capped: j.capped, clean: j.clean,
    });
    console.log((j.clean ? '✓ ' : '✗ ') + k.file + ': ' + j.killed + ' of ' + j.total + ' killed, ' + j.survived.length + ' survived, ' + j.ignored.length + ' reviewed-equivalent');
  }
  const receipt = { kind: 'kar-veil.gate', v: 1, witness: { tag: 'v0.6', sha256: WITNESS_V06_SHA256 }, kernels, clean: kernels.every((k) => k.clean && !k.capped) };
  fs.mkdirSync('receipts', { recursive: true });
  fs.writeFileSync(RECEIPT, JSON.stringify(receipt, null, 1) + '\n');
  console.log('wrote ' + RECEIPT + (receipt.clean ? ' · clean' : ' · NOT clean'));
  if (!receipt.clean) process.exit(1);
}

function verify() {
  const r = JSON.parse(fs.readFileSync(RECEIPT, 'utf8'));
  const problems = [];
  if (r.witness?.sha256 !== WITNESS_V06_SHA256) problems.push('the receipt does not name witness v0.6');
  for (const k of KERNELS) {
    const g = (r.kernels || []).find((x) => x.file === k.file);
    if (!g) { problems.push(k.file + ' is not in the receipt'); continue; }
    if (g.sha256 !== shaLF(k.file)) problems.push(k.file + ' changed since the gate ran: run node gate.mjs');
    if (g.testsSha256 !== k.tests.map(shaLF).join(',')) problems.push(k.tests.join(' ') + ' changed since the gate ran: run node gate.mjs');
    if (!g.clean || g.capped || g.survived.length) problems.push(k.file + ' is not clean and uncapped in the receipt');
  }
  if (problems.length) { for (const p of problems) console.error('✗ ' + p); process.exit(1); }
  console.log('✓ ' + RECEIPT + ': every kernel clean, uncapped, and these exact kernels and tests');
}

if (process.argv.includes('--verify')) verify(); else run();
