// measure.mjs — measures CLAIMS-2026-11-05-veil-v2.md exactly as it was sealed, and writes receipts/measure.json.
//
//   node measure.mjs            run it and write the receipt
//   node measure.mjs --check    run it and exit 1 if the committed receipt differs by one byte (CI)
//
// Deterministic: one seeded PRNG stream (mulberry32, seed 20261105) drawn in a fixed order, no clock, no network, no
// timings in the output. The hostile-input battery is witness v0.6's own (hostileInputs), read from a pinned copy of
// witness.mjs whose SHA-256 is checked before it is used. Every "held" below is computed here from the counts; no
// number is typed into the receipt or the page.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { KIND_V2, WARN_F1, WARN_F2, commit, commitV1, prove, verify } from './veil.mjs';
import { rng, hex64, documentText, line, tamper, guessConfirms, mutateField, CLASSES } from './attacks.mjs';

const CLAIMS_FILE = 'CLAIMS-2026-11-05-veil-v2.md';
const RECEIPT = 'receipts/measure.json';
const SEED = 20261105, DOCS = 400, HIDE_P = 0.4, DECOYS = 9, MUTATIONS = 2000;
const WITNESS_PATH = process.env.WITNESS || '.witness/witness.mjs';
const WITNESS_V06_SHA256 = '9918297aa5f8fc4e1d26d9e6b25226f56102fdc04f0c634155bfcba1c086ef48';
const shaLF = (path) => createHash('sha256').update(fs.readFileSync(path, 'utf8').replace(/\r\n/g, '\n')).digest('hex');

export async function measure(hostileInputs) {
  const r = rng(SEED);

  // ── the corpus: 400 documents, each committed under v2 (a PRNG secret) and under v1, each line hidden with p = 0.4
  const docs = [];
  for (let d = 0; d < DOCS; d++) {
    const text = documentText(r);
    const secret = hex64(r);
    const c2 = await commit(text, secret);
    const c1 = await commitV1(text);
    if (!c2.ok || !c1.ok) throw new Error('document ' + d + ' could not be committed: ' + (c2.why || c1.why));
    const hidden = c2.lines.map((_, i) => i).filter(() => r() < HIDE_P);
    docs.push({ text, c2, c1, p2: prove(c2, hidden).proof, p1: prove(c1, hidden).proof });
  }
  const lines = docs.reduce((s, x) => s + x.c2.lineCount, 0);
  const hiddenLines = docs.reduce((s, x) => s + x.p2.hidden.length, 0);

  // C1 honest v2 proofs verify against the root they were committed to
  let c1 = 0;
  for (const x of docs) if ((await verify(x.p2, x.c2.root)).status === 'VERIFIED') c1++;

  // C2 every tamper class on every honest v2 proof, against the trusted root; C3 needs the T7 proofs; C4 needs T6
  const classes = {};
  const t7 = [];
  for (const cls of Object.keys(CLASSES)) classes[cls] = { what: CLASSES[cls], cases: 0, BREACHED: 0, MALFORMED: 0, CONSISTENT: 0, VERIFIED: 0 };
  for (const x of docs) {
    for (const cls of Object.keys(CLASSES)) {
      for (const t of await tamper(cls, r, x.p2)) {
        const v = await verify(t, x.c2.root);
        classes[cls].cases++;
        classes[cls][v.status]++;
        if (cls === 'T7') t7.push(t);
      }
    }
  }

  // C3 no trusted root, no VERIFIED: every honest v2 proof and every T7 proof alone is CONSISTENT
  let c3Consistent = 0, c3Verified = 0;
  for (const p of [...docs.map((x) => x.p2), ...t7]) {
    const v = await verify(p);
    if (v.status === 'CONSISTENT') c3Consistent++;
    if (v.status === 'VERIFIED') c3Verified++;
  }

  // C4 fault F1: T6 on v1 proofs, against their v1 roots (predicted VERIFIED everywhere it applies)
  let t6v1 = 0, t6v1Verified = 0;
  for (const x of docs) {
    for (const t of await tamper('T6', r, x.p1)) {
      t6v1++;
      if ((await verify(t, x.c1.root)).status === 'VERIFIED') t6v1Verified++;
    }
  }

  // C5 fault F2: for every hidden line, the true text and 9 decoys (each different from it), hashed at that index
  let v1Confirmed = 0, v2Confirmed = 0, v1Hashes = 0, v2Hashes = 0;
  for (const x of docs) {
    for (const e of x.p2.hidden) {
      const truth = x.c2.lines[e.index];
      const candidates = [truth];
      while (candidates.length < 1 + DECOYS) { const d = line(r); if (d !== truth) candidates.push(d); }
      const e1 = x.p1.redactedHashes.find((h) => h.index === e.index);
      const g1 = await guessConfirms(x.p1, e1, candidates);
      const g2 = await guessConfirms(x.p2, e, candidates);
      v1Hashes += g1.hashes; v2Hashes += g2.hashes;
      if (g1.confirmed) v1Confirmed++;
      if (g2.confirmed) v2Confirmed++;
    }
  }

  // C6 v1 proofs stay checkable, and every v1 result names both faults
  let c6Verified = 0, c6Warned = 0;
  for (const x of docs) {
    const v = await verify(x.p1, x.c1.root);
    if (v.status === 'VERIFIED') c6Verified++;
    if (v.warnings.includes(WARN_F1) && v.warnings.includes(WARN_F2)) c6Warned++;
  }

  // C7 the verifier never throws: witness v0.6's battery as the proof (alone, with a trusted root, with a received
  // document too), then 2,000 one-field mutations of honest v2 proofs, each against that document's trusted root
  const isVerdict = (v) => v !== null && typeof v === 'object' && typeof v.status === 'string';
  let batteryCalls = 0, batteryThrows = 0, batteryNoVerdict = 0;
  const x0 = docs[0];
  for (const [, value] of hostileInputs()) {
    for (const args of [[value], [value, x0.c2.root], [value, x0.c2.root, x0.text]]) {
      batteryCalls++;
      try { if (!isVerdict(await verify(...args))) batteryNoVerdict++; } catch { batteryThrows++; }
    }
  }
  let mutThrows = 0, mutVerified = 0, mutNoVerdict = 0;
  const mutStatus = { BREACHED: 0, MALFORMED: 0, CONSISTENT: 0, VERIFIED: 0 };
  for (let k = 0; k < MUTATIONS; k++) {
    const x = docs[k % DOCS];
    const m = mutateField(r, x.p2);
    try {
      const v = await verify(m.proof, x.c2.root);
      if (!isVerdict(v)) mutNoVerdict++;
      else { mutStatus[v.status] = (mutStatus[v.status] || 0) + 1; if (v.status === 'VERIFIED') mutVerified++; }
    } catch { mutThrows++; }
  }

  // ── the claims, each held or failed from the counts above against the bar the seal set
  const everyClassCaught = Object.values(classes).every((c) => c.cases > 0 && c.BREACHED + c.MALFORMED === c.cases);
  const claims = {
    C1: { claim: 'honest v2 proofs verify', bar: '400 of 400 VERIFIED', got: c1 + ' of ' + DOCS, held: c1 === DOCS },
    C2: { claim: 'every tamper is caught (v2)', bar: 'every applicable case in T1-T9 BREACHED or MALFORMED', got: Object.entries(classes).map(([k, c]) => k + ' ' + (c.BREACHED + c.MALFORMED) + '/' + c.cases).join(', '), held: everyClassCaught },
    C3: { claim: 'no trusted root, no VERIFIED', bar: 'every honest v2 proof and every T7 proof CONSISTENT without a trusted root', got: c3Consistent + ' of ' + (DOCS + t7.length) + ' CONSISTENT, ' + c3Verified + ' VERIFIED', held: c3Consistent === DOCS + t7.length && c3Verified === 0 },
    C4: { claim: 'F1 reproduced on v1 and closed on v2', bar: 'v2: 0 of the T6 forgeries VERIFIED', got: 'v1 ' + t6v1Verified + ' of ' + t6v1 + ' VERIFIED (the fault, as predicted); v2 ' + classes.T6.VERIFIED + ' of ' + classes.T6.cases, held: classes.T6.cases > 0 && classes.T6.VERIFIED === 0, v1Reproduced: t6v1 > 0 && t6v1Verified === t6v1 },
    C5: { claim: 'F2 reproduced on v1 and closed on v2', bar: 'v2: 0 hidden lines confirmed without the secret', got: 'v1 ' + v1Confirmed + ' of ' + hiddenLines + ' confirmed (the fault, as predicted); v2 ' + v2Confirmed + ' of ' + hiddenLines, held: hiddenLines > 0 && v2Confirmed === 0, v1Reproduced: v1Confirmed === hiddenLines },
    C6: { claim: 'v1 proofs stay checkable', bar: '400 of 400 VERIFIED, both fault warnings on all', got: c6Verified + ' VERIFIED, ' + c6Warned + ' warned, of ' + DOCS, held: c6Verified === DOCS && c6Warned === DOCS },
    C7: { claim: 'the verifier never throws', bar: '0 throws; 0 of 2,000 mutations VERIFIED', got: batteryThrows + ' throws in ' + batteryCalls + ' battery calls, ' + mutThrows + ' throws and ' + mutVerified + ' VERIFIED in ' + MUTATIONS + ' mutations', held: batteryThrows === 0 && batteryNoVerdict === 0 && mutThrows === 0 && mutNoVerdict === 0 && mutVerified === 0 },
  };
  return {
    corpus: { documents: DOCS, lines, hiddenLines, hideProbability: HIDE_P, proofKind: KIND_V2 },
    classes,
    guessing: { decoysPerLine: DECOYS, v1: { confirmed: v1Confirmed, hashes: v1Hashes }, v2: { confirmed: v2Confirmed, hashes: v2Hashes } },
    battery: { calls: batteryCalls, throws: batteryThrows, noVerdict: batteryNoVerdict },
    mutations: { count: MUTATIONS, throws: mutThrows, noVerdict: mutNoVerdict, statuses: mutStatus },
    claims,
    held: Object.values(claims).filter((c) => c.held).length,
    of: Object.keys(claims).length,
  };
}

async function main() {
  const check = process.argv.includes('--check');
  const witnessSha = shaLF(WITNESS_PATH);
  if (witnessSha !== WITNESS_V06_SHA256) { console.error('witness.mjs at ' + WITNESS_PATH + ' is not witness v0.6 (sha256 ' + witnessSha + ')'); process.exit(2); }
  const { hostileInputs } = await import(pathToFileURL(WITNESS_PATH).href);
  const m = await measure(hostileInputs);
  const receipt = {
    kind: 'kar-veil.measure', v: 1,
    claimsFile: CLAIMS_FILE, claimsSha256: shaLF(CLAIMS_FILE),
    seed: SEED,
    witness: { tag: 'v0.6', sha256: witnessSha, used: 'hostileInputs()' },
    rerun: 'git clone --depth 1 --branch v0.6 https://github.com/sjgant80-hub/witness .witness && node measure.mjs --check',
    ...m,
  };
  const out = JSON.stringify(receipt, null, 1) + '\n';
  for (const [k, c] of Object.entries(m.claims)) console.log((c.held ? '✓ HELD   ' : '✗ FAILED ') + k + '  ' + c.claim + ' — ' + c.got);
  console.log(m.held + ' of ' + m.of + ' claims held');
  if (check) {
    const was = fs.existsSync(RECEIPT) ? fs.readFileSync(RECEIPT, 'utf8').replace(/\r\n/g, '\n') : '';
    if (was !== out) { console.error('✗ ' + RECEIPT + ' differs from this run'); process.exit(1); }
    console.log('✓ ' + RECEIPT + ' re-derived byte for byte');
    return;
  }
  fs.mkdirSync('receipts', { recursive: true });
  fs.writeFileSync(RECEIPT, out);
  console.log('wrote ' + RECEIPT);
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) await main();
