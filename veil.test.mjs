// veil.test.mjs — the v2 kernel. Every expected hash is worked out independently here with node:crypto (createHash,
// createHmac), never with veil.mjs itself, so a test cannot pass by agreeing with a broken kernel.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import V, {
  KIND_V1, KIND_V2, MARK, WARN_F1, WARN_F2, WARN_NO_TRUST, sha256, leafV1, nodeV1, leafV2, nodeV2, rootV2, levels,
  splitLines, newSecret, commit, commitV1, prove, verify, preview,
} from './veil.mjs';

const H = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const SECRET = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const saltOf = (secret, i) => createHmac('sha256', Buffer.from(secret, 'hex')).update('kar-veil:v2:salt:' + i).digest('hex');
const L2 = (i, salt, t) => H('kar-veil:v2:leaf:' + i + ':' + salt + ':' + t);
const N2 = (a, b) => H('kar-veil:v2:node:' + a + ':' + b);
const R2 = (n, top) => H('kar-veil:v2:root:' + n + ':' + top);
const L1 = (i, t) => H('leaf:' + i + ':' + t);
const N1 = (a, b) => H('node:' + a + ':' + b);
// the v2 root of a document, worked out by hand: three lines fold as ((0,1),2), the odd one promoted
const root3 = (secret, [a, b, c]) => R2(3, N2(N2(L2(0, saltOf(secret, 0), a), L2(1, saltOf(secret, 1), b)), L2(2, saltOf(secret, 2), c)));
const DOC = 'Approved by J. Smith\nAmount: 4200\nStatus: closed';
const LINES = DOC.split('\n');

test('the hash formulas are exactly the documented ones', async () => {
  assert.equal(await sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(await leafV1(2, 'a:b'), L1(2, 'a:b'));
  assert.equal(await nodeV1('x', 'y'), N1('x', 'y'));
  assert.equal(await leafV2(3, 'ss', 't'), L2(3, 'ss', 't'));
  assert.equal(await nodeV2('x', 'y'), N2('x', 'y'));
  assert.equal(await rootV2(7, 'tt'), R2(7, 'tt'));
});

test('levels folds in pairs and promotes an odd hash unchanged, never pairing it with itself', async () => {
  const cat = (a, b) => '(' + a + b + ')';
  assert.deepEqual(await levels(['a'], cat), [['a']]);
  assert.deepEqual(await levels(['a', 'b'], cat), [['a', 'b'], ['(ab)']]);
  assert.deepEqual(await levels(['a', 'b', 'c'], cat), [['a', 'b', 'c'], ['(ab)', 'c'], ['((ab)c)']]);
  assert.deepEqual(await levels(['a', 'b', 'c', 'd', 'e'], cat), [['a', 'b', 'c', 'd', 'e'], ['(ab)', '(cd)', 'e'], ['((ab)(cd))', 'e'], ['(((ab)(cd))e)']]);
});

test('splitLines: CRLF and a lone CR become line breaks; a trailing newline makes a last empty line', () => {
  assert.deepEqual(splitLines('a\r\nb\rc\nd'), ['a', 'b', 'c', 'd']);
  assert.deepEqual(splitLines('a\n'), ['a', '']);
  assert.deepEqual(splitLines(''), ['']);
  assert.deepEqual(splitLines(12), ['12']);
});

test('newSecret: 32 fresh random bytes as 64 lowercase hex', () => {
  const a = newSecret(), b = newSecret();
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, b);
});

test('commit (v2): salts are HMAC(secret, index), leaves salted, and the root binds the line count', async () => {
  const c = await commit(DOC, SECRET);
  assert.equal(c.ok, true);
  assert.equal(c.kind, KIND_V2);
  assert.equal(c.secret, SECRET);
  assert.equal(c.lineCount, 3);
  assert.deepEqual(c.lines, LINES);
  assert.deepEqual(c.salts, [0, 1, 2].map((i) => saltOf(SECRET, i)));
  assert.deepEqual(c.leaves, LINES.map((t, i) => L2(i, saltOf(SECRET, i), t)));
  assert.equal(c.root, root3(SECRET, LINES));
  // one line: the root still binds the count
  const one = await commit('only', SECRET);
  assert.equal(one.root, R2(1, L2(0, saltOf(SECRET, 0), 'only')));
});

test('commit: the secret may be 32 bytes or 64 hex (any case); anything else is refused; none given makes a fresh one', async () => {
  const bytes = Uint8Array.from(Buffer.from(SECRET, 'hex'));
  assert.equal((await commit(DOC, bytes)).root, root3(SECRET, LINES));
  assert.equal((await commit(DOC, SECRET.toUpperCase())).root, root3(SECRET, LINES));
  const why = 'the secret must be 32 bytes, written as 64 hex characters';
  assert.deepEqual(await commit(DOC, bytes.slice(0, 31)), { ok: false, why });
  assert.deepEqual(await commit(DOC, new Uint8Array(33)), { ok: false, why });
  assert.deepEqual(await commit(DOC, SECRET.slice(1)), { ok: false, why });
  assert.deepEqual(await commit(DOC, null), { ok: false, why });
  const fresh = await commit(DOC);
  assert.equal(fresh.ok, true);
  assert.match(fresh.secret, /^[0-9a-f]{64}$/);
  assert.notEqual(fresh.secret, SECRET);
  assert.equal(fresh.root, root3(fresh.secret, LINES));
});

test('commit refuses what it cannot hash faithfully', async () => {
  assert.deepEqual(await commit(42, SECRET), { ok: false, why: 'the document must be text' });
  assert.equal((await commit('a\uD800b', SECRET)).ok, false);
  assert.match((await commit('a\uD800b', SECRET)).why, /unpaired surrogate/);
  assert.equal((await commit('a😀b', SECRET)).ok, true);   // a paired surrogate (an emoji) is fine
});

test('commitV1: the old unsalted rules, kept so old roots stay checkable', async () => {
  const c = await commitV1(DOC);
  assert.equal(c.ok, true);
  assert.equal(c.kind, KIND_V1);
  assert.equal(c.root, N1(N1(L1(0, LINES[0]), L1(1, LINES[1])), L1(2, LINES[2])));
  assert.deepEqual(await commitV1(7), { ok: false, why: 'the document must be text' });
});

test('prove: visible lines carry text and salt, hidden lines only their leaf hash', async () => {
  const c = await commit(DOC, SECRET);
  const { ok, proof } = prove(c, [1]);
  assert.equal(ok, true);
  assert.deepEqual(proof, {
    kind: KIND_V2, root: c.root, lineCount: 3,
    visible: [{ index: 0, text: LINES[0], salt: c.salts[0] }, { index: 2, text: LINES[2], salt: c.salts[2] }],
    hidden: [{ index: 1, hash: c.leaves[1] }],
  });
  const v1 = prove(await commitV1(DOC), [0, 0]);
  assert.deepEqual(v1.proof.redactedHashes.map((e) => e.index), [0]);
  assert.deepEqual(v1.proof.revealed.map((e) => e.index), [1, 2]);
  assert.equal(v1.proof.kind, KIND_V1);
  assert.equal(prove(c, []).proof.hidden.length, 0);
  assert.equal(prove(c, [0, 1, 2]).proof.visible.length, 0);
});

test('prove refuses line numbers outside the document, and anything that is not a commit', async () => {
  const c = await commit(DOC, SECRET);
  const range = { ok: false, why: 'hidden lines are line numbers inside the document, counted from 0' };
  assert.deepEqual(prove(c, [3]), range);
  assert.deepEqual(prove(c, [-1]), range);
  assert.deepEqual(prove(c, [1.5]), range);
  assert.equal(prove(c, [0]).ok, true);
  assert.equal(prove(c, [2]).ok, true);
  assert.deepEqual(prove({ kind: 'other', lines: [] }, []), { ok: false, why: 'a commit made by commit()' });
  assert.equal(prove(null, [0]).ok, false);
  assert.equal(prove(c, 5).ok, false);
});

const honest = async (hidden = [1]) => { const c = await commit(DOC, SECRET); return { c, p: prove(c, hidden).proof }; };

test('verify: VERIFIED only with a trusted root that matches; CONSISTENT without one', async () => {
  const { c, p } = await honest();
  const v = await verify(p, c.root);
  assert.deepEqual(v, {
    status: 'VERIFIED', version: 2, issues: [], warnings: [], recomputedRoot: c.root, statedRoot: c.root,
    trustedCheck: 'MATCH', receivedCheck: 'not performed', lineCount: 3, hiddenCount: 1,
  });
  const alone = await verify(p);
  assert.equal(alone.status, 'CONSISTENT');
  assert.deepEqual(alone.warnings, [WARN_NO_TRUST]);
  assert.equal(alone.trustedCheck, 'not performed');
  for (const none of [null, '', '   ']) assert.equal((await verify(p, none)).status, 'CONSISTENT');
  assert.equal((await verify(JSON.stringify(p), '  ' + c.root.toUpperCase() + ' ')).status, 'VERIFIED');
  // a one-line document is a proof too
  const one = await commit('only', SECRET);
  assert.equal((await verify(prove(one, []).proof, one.root)).status, 'VERIFIED');
  assert.equal((await verify(prove(one, [0]).proof, one.root)).status, 'VERIFIED');
});

test('verify: a changed line, salt or hash, a restated root, or the wrong trusted root is BREACHED', async () => {
  const { c, p } = await honest();
  const edit = (f) => { const q = JSON.parse(JSON.stringify(p)); f(q); return q; };
  const t1 = await verify(edit((q) => { q.visible[0].text += '!'; }), c.root);
  assert.equal(t1.status, 'BREACHED');
  assert.equal(t1.trustedCheck, 'MISMATCH');
  assert.equal(t1.issues.length, 2);
  assert.match(t1.issues[0], /does not recompute to the root it states/);
  assert.match(t1.issues[1], /does not recompute to the root you trust/);
  assert.equal((await verify(edit((q) => { q.visible[1].salt = '0'.repeat(64); }), c.root)).status, 'BREACHED');
  assert.equal((await verify(edit((q) => { q.hidden[0].hash = 'f'.repeat(64); }), c.root)).status, 'BREACHED');
  // restate the root so the proof agrees with itself: alone it is CONSISTENT, against the trusted root BREACHED
  const forged = edit((q) => { q.visible[0].text = 'Approved by A. Jones'; });
  forged.root = (await verify(forged)).recomputedRoot;
  assert.equal((await verify(forged)).status, 'CONSISTENT');
  const f = await verify(forged, c.root);
  assert.equal(f.status, 'BREACHED');
  assert.deepEqual(f.issues, ['the proof does not recompute to the root you trust: it is not a proof of that committed document']);
  const other = await commit(DOC, 'ff'.repeat(32));
  assert.equal((await verify(p, other.root)).status, 'BREACHED');
  // the honest proof against its own root stays VERIFIED: the mismatch above is the root, not the proof
  assert.equal((await verify(p, c.root)).issues.length, 0);
});

test('verify: the line count is bound into the root, so folding two lines into one hidden "line" fails (F1 closed)', async () => {
  const c = await commit('a\nb\nc\nd', SECRET);
  const folded = { kind: KIND_V2, root: c.root, lineCount: 3, visible: [{ index: 0, text: 'a', salt: c.salts[0] }, { index: 1, text: 'b', salt: c.salts[1] }], hidden: [{ index: 2, hash: N2(c.leaves[2], c.leaves[3]) }] };
  assert.equal((await verify(folded, c.root)).status, 'BREACHED');
  // the same fold on v1 still matches: the fault, kept on the record
  const c1 = await commitV1('a\nb\nc\nd');
  const f1 = { kind: KIND_V1, root: c1.root, lineCount: 3, revealed: [{ index: 0, text: 'a' }, { index: 1, text: 'b' }], redactedHashes: [{ index: 2, hash: N1(c1.leaves[2], c1.leaves[3]) }] };
  assert.equal((await verify(f1, c1.root)).status, 'VERIFIED');
});

test('verify: v1 proofs still verify, always with both faults named', async () => {
  const c = await commitV1(DOC);
  const p = prove(c, [2]).proof;
  const v = await verify(p, c.root);
  assert.equal(v.status, 'VERIFIED');
  assert.equal(v.version, 1);
  assert.deepEqual(v.warnings, [WARN_F1, WARN_F2]);
  assert.deepEqual((await verify(p)).warnings, [WARN_F1, WARN_F2, WARN_NO_TRUST]);
  // v1 hex may be upper case; the verifier reads it in lower case
  const up = { ...p, root: p.root.toUpperCase(), redactedHashes: p.redactedHashes.map((e) => ({ ...e, hash: e.hash.toUpperCase() })) };
  assert.equal((await verify(up, c.root)).status, 'VERIFIED');
});

test('verify: the received document is cross-checked line for line', async () => {
  const { c, p } = await honest();
  const ok = await verify(p, c.root, 'Approved by J. Smith\n' + MARK + '\nStatus: closed');
  assert.equal(ok.status, 'VERIFIED');
  assert.equal(ok.receivedCheck, 'MATCH');
  const crlf = await verify(p, c.root, 'Approved by J. Smith\r\nanything\r\nStatus: closed');
  assert.equal(crlf.receivedCheck, 'MATCH');
  const short = await verify(p, c.root, 'Approved by J. Smith\nStatus: closed');
  assert.equal(short.status, 'BREACHED');
  assert.equal(short.receivedCheck, 'MISMATCH');
  assert.deepEqual(short.issues, ['the document you received has 2 lines; the proof has 3']);
  const long = await verify(p, c.root, DOC + '\nextra');
  assert.equal(long.receivedCheck, 'MISMATCH');
  const diff = await verify(p, c.root, 'Approved by J. Smith\nx\nStatus: open');
  assert.equal(diff.status, 'BREACHED');
  assert.deepEqual(diff.issues, ['a visible line in the document you received differs from the proof']);
  for (const none of [undefined, null, '', ' \n ']) assert.equal((await verify(p, c.root, none)).receivedCheck, 'not performed');
  assert.equal((await verify(p, c.root, 5)).status, 'MALFORMED');
});

const malformedWhy = async (proof, trusted) => { const v = await verify(proof, trusted); assert.equal(v.status, 'MALFORMED'); return v.issues[0]; };

test('verify: a proof that is not well formed is MALFORMED, with the reason', async () => {
  const { c, p } = await honest();
  const edit = (f) => { const q = JSON.parse(JSON.stringify(p)); f(q); return q; };
  assert.equal(await malformedWhy('{nope'), 'the proof is not valid JSON');
  assert.equal(await malformedWhy(p, 'abc'), 'the trusted root you gave is not 64 hex characters');
  assert.equal(await malformedWhy(p, 7), 'the trusted root you gave is not 64 hex characters');
  assert.equal(await malformedWhy([p]), 'the proof is not a JSON object');
  assert.equal(await malformedWhy(null), 'the proof is not a JSON object');
  assert.match(await malformedWhy(edit((q) => { q.kind = 'kar-veil-proof-v3'; })), /unknown proof kind/);
  assert.match(await malformedWhy(edit((q) => { q.kind = 'toString'; })), /unknown proof kind/);
  for (const n of [0, -1, 1.5, '3']) assert.equal(await malformedWhy(edit((q) => { q.lineCount = n; })), 'lineCount must be a whole number, at least 1');
  assert.equal(await malformedWhy(edit((q) => { q.root = q.root.slice(1); })), 'root must be 64 hex characters');
  assert.equal(await malformedWhy(edit((q) => { q.root = q.root.toUpperCase(); })), 'root must be 64 hex characters');
  assert.match(await malformedWhy(edit((q) => { q.hidden = {}; })), /must both be lists/);
  assert.match(await malformedWhy(edit((q) => { q.visible = 'x'; })), /must both be lists/);
  assert.equal(await malformedWhy(edit((q) => { q.lineCount = 4; })), 'the proof lists 3 lines but lineCount says 4');
  assert.equal(await malformedWhy(edit((q) => { q.lineCount = 2; })), 'the proof lists 3 lines but lineCount says 2');
  const idx = 'every line needs a whole-number index from 0 to 2';
  assert.equal(await malformedWhy(edit((q) => { q.visible[1].index = 3; })), idx);
  assert.equal(await malformedWhy(edit((q) => { q.visible[1].index = -1; })), idx);
  assert.equal(await malformedWhy(edit((q) => { q.hidden[0].index = 3; })), idx);
  assert.equal(await malformedWhy(edit((q) => { q.hidden[0].index = 0.5; })), idx);
  assert.equal(await malformedWhy(edit((q) => { q.visible[0] = 'x'; })), idx);
  assert.equal(await malformedWhy(edit((q) => { q.hidden[0] = null; })), idx);
  assert.equal(await malformedWhy(edit((q) => { q.hidden[0].index = 0; })), 'line 0 appears more than once');
  assert.equal(await malformedWhy(edit((q) => { q.visible[1].index = 0; })), 'line 0 appears more than once');
  const text = 'visible line 0 must be text with no line break or broken character';
  for (const t of [5, null, 'a\nb', 'a\rb', 'a\uDC00']) assert.equal(await malformedWhy(edit((q) => { q.visible[0].text = t; })), text);
  const salt = 'visible line 0 needs its salt, 64 lowercase hex characters';
  assert.equal(await malformedWhy(edit((q) => { delete q.visible[0].salt; })), salt);
  assert.equal(await malformedWhy(edit((q) => { q.visible[0].salt = q.visible[0].salt.toUpperCase(); })), salt);
  assert.equal(await malformedWhy(edit((q) => { q.visible[0].salt = [q.visible[0].salt]; })), salt);
  const hash = 'hidden line 1 needs its hash, 64 hex characters';
  assert.equal(await malformedWhy(edit((q) => { q.hidden[0].hash = q.hidden[0].hash.toUpperCase(); })), hash);
  assert.equal(await malformedWhy(edit((q) => { q.hidden[0].hash = [q.hidden[0].hash]; })), hash);
  assert.equal(await malformedWhy(edit((q) => { delete q.hidden[0].hash; })), hash);
  // the edges that ARE well formed: the last index, and index 0
  assert.equal((await verify(p, c.root)).status, 'VERIFIED');
  // a getter that throws is read as "could not be read", never thrown
  const toxic = { get kind() { throw new Error('boom'); } };
  assert.equal(await malformedWhy(toxic), 'the proof could not be read');
  assert.deepEqual((await verify(toxic)).warnings, []);
  assert.equal((await verify(toxic)).recomputedRoot, null);
});

test('verify answers a huge lineCount without allocating it', async () => {
  const { p } = await honest();
  assert.equal(await malformedWhy({ ...p, lineCount: 1000000001 }), 'the proof lists 3 lines but lineCount says 1000000001');
});

test('preview: the redacted document a proof stands for, MARK on every hidden line; null when malformed', async () => {
  const { p } = await honest([0, 2]);
  assert.equal(preview(p), MARK + '\nAmount: 4200\n' + MARK);
  assert.equal(preview({ ...p, lineCount: 9 }), null);
  assert.equal(preview(null), null);
  assert.equal(preview({ get kind() { throw new Error('boom'); } }), null);
});

test('the default export carries the whole surface', () => {
  for (const k of ['sha256', 'leafV1', 'nodeV1', 'leafV2', 'nodeV2', 'rootV2', 'levels', 'splitLines', 'newSecret', 'commit', 'commitV1', 'prove', 'verify', 'preview']) assert.equal(typeof V[k], 'function', k);
  assert.equal(V.KIND_V2, KIND_V2);
  assert.equal(V.MARK, '[REDACTED]');
});
