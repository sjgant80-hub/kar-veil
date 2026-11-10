// veil.mjs — the Kar-Veil kernel: commit a document to one root, prove a redacted copy against it, verify the proof.
//
// This file IS the live logic: index.html (through app.mjs) imports it, the tests in veil.test.mjs check it against an
// independent reference written with node:crypto, witness v0.6 mutation-gates it in CI, and measure.mjs measures the
// sealed claims in CLAIMS-2026-11-05-veil-v2.md with it. Browser and Node alike: it needs only WebCrypto
// (globalThis.crypto.subtle) and TextEncoder.
//
// The v2 construction, exactly as sealed:
//   salt_i = HMAC-SHA-256(secret, "kar-veil:v2:salt:" + i)                  (64 hex; the secret never enters a proof)
//   leaf_i = SHA-256("kar-veil:v2:leaf:" + i + ":" + salt_i + ":" + text_i)
//   node   = SHA-256("kar-veil:v2:node:" + left + ":" + right)               (an odd hash at any level is promoted)
//   root   = SHA-256("kar-veil:v2:root:" + lineCount + ":" + top)           (the line count fixes the tree's shape)
// v1 proofs (the page as it was from 2026-09-26) still verify under v1's rules, always with both of v1's faults
// named: F1, the line count is not in the root, so hidden lines can be folded into one; F2, hidden lines are unsalted,
// so a guessable hidden line can be confirmed from its hash.
//
// verify() never throws: anything that is not a well-formed proof is MALFORMED, with the reason.

export const KIND_V1 = 'kar-veil-proof-v1';
export const KIND_V2 = 'kar-veil-proof-v2';
export const MARK = '[REDACTED]';
export const WARN_F1 = 'v1 proof: the line count is not bound into a v1 root, so hidden lines can be folded together and the proof still matches (fault F1, found 2026-11-05). Ask for a v2 proof.';
export const WARN_F2 = 'v1 proof: v1 hidden lines are unsalted, so anyone who can guess a hidden line can confirm the guess from its hash (fault F2, found 2026-11-05). Ask for a v2 proof.';
export const WARN_NO_TRUST = 'No trusted root was given. This proof agrees with itself, but it could be a proof of any document: compare it with the root that was published before the redaction.';

const enc = new TextEncoder();
const subtle = () => globalThis.crypto.subtle;
const toHex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
const isObj = (x) => typeof x === 'object' && x !== null && !Array.isArray(x);
const HEX_V2 = /^[0-9a-f]{64}$/;
const HEX_V1 = /^[0-9a-f]{64}$/i;
const isHex = (x, re) => typeof x === 'string' && re.test(x);
// A line cannot hold a line break, and an unpaired surrogate cannot be hashed faithfully: TextEncoder turns every
// unpaired surrogate into the same U+FFFD bytes, so two different ones would give the same leaf.
const BAD_TEXT = /[\r\n]|\p{Cs}/u;

export async function sha256(str) {
  return toHex(await subtle().digest('SHA-256', enc.encode(str)));
}
export const leafV1 = (index, text) => sha256('leaf:' + index + ':' + text);
export const nodeV1 = (left, right) => sha256('node:' + left + ':' + right);
export const leafV2 = (index, salt, text) => sha256('kar-veil:v2:leaf:' + index + ':' + salt + ':' + text);
export const nodeV2 = (left, right) => sha256('kar-veil:v2:node:' + left + ':' + right);
export const rootV2 = (lineCount, top) => sha256('kar-veil:v2:root:' + lineCount + ':' + top);

/** every level of the fold, leaves first and the top last; an odd hash at the end of a level is promoted, never paired with itself */
export async function levels(hashes, node) {
  const out = [hashes];
  let level = hashes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? node(level[i], level[i + 1]) : level[i]);
    level = await Promise.all(next);
    out.push(level);
  }
  return out;
}
const top = async (hashes, node) => (await levels(hashes, node)).pop()[0];

/** pasted text as lines: \r\n and a lone \r become \n, and a trailing newline makes a last, empty line */
export function splitLines(text) {
  return String(text).replace(/\r\n?/g, '\n').split('\n');
}

function secretBytes(secret) {
  if (secret instanceof Uint8Array) return secret.length === 32 ? secret.slice() : null;
  if (!isHex(secret, HEX_V1)) return null;
  return Uint8Array.from(secret.match(/../g), (h) => parseInt(h, 16));
}

/** a fresh 32-byte commit secret, as 64 hex */
export function newSecret() {
  return toHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

/** commit a document under v2. secret: 64 hex or 32 bytes (a fresh one is made when it is left out). Keep the secret private; publish the root. */
export async function commit(text, secret) {
  if (typeof text !== 'string') return { ok: false, why: 'the document must be text' };
  if (/\p{Cs}/u.test(text)) return { ok: false, why: 'the document holds a broken character (an unpaired surrogate) that cannot be hashed faithfully' };
  const key = secret === undefined ? secretBytes(newSecret()) : secretBytes(secret);
  if (!key) return { ok: false, why: 'the secret must be 32 bytes, written as 64 hex characters' };
  const lines = splitLines(text);
  const hmac = await subtle().importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const salts = await Promise.all(lines.map(async (_, i) => toHex(await subtle().sign('HMAC', hmac, enc.encode('kar-veil:v2:salt:' + i)))));
  const leaves = await Promise.all(lines.map((t, i) => leafV2(i, salts[i], t)));
  const root = await rootV2(lines.length, await top(leaves, nodeV2));
  return { ok: true, kind: KIND_V2, secret: toHex(key), lineCount: lines.length, lines, salts, leaves, root };
}

/** commit under the old v1 rules. Kept so old roots stay checkable and so v1's faults can be measured; the page never makes a v1 proof. */
export async function commitV1(text) {
  if (typeof text !== 'string') return { ok: false, why: 'the document must be text' };
  const lines = splitLines(text);
  const leaves = await Promise.all(lines.map((t, i) => leafV1(i, t)));
  return { ok: true, kind: KIND_V1, lineCount: lines.length, lines, leaves, root: await top(leaves, nodeV1) };
}

/** a proof from a commit and the line numbers (counted from 0) to hide. A v2 commit gives a v2 proof, a v1 commit a v1 proof. */
export function prove(c, hidden) {
  try {
    const v2 = c.kind === KIND_V2;
    if (!v2 && c.kind !== KIND_V1) return { ok: false, why: 'a commit made by commit()' };
    const n = c.lines.length;
    const hide = new Set();
    for (const i of hidden) {
      if (!Number.isInteger(i) || i < 0 || i >= n) return { ok: false, why: 'hidden lines are line numbers inside the document, counted from 0' };
      hide.add(i);
    }
    const shown = [], kept = [];
    c.lines.forEach((text, index) => {
      if (hide.has(index)) kept.push({ index, hash: c.leaves[index] });
      else shown.push(v2 ? { index, text, salt: c.salts[index] } : { index, text });
    });
    const proof = v2
      ? { kind: KIND_V2, root: c.root, lineCount: n, visible: shown, hidden: kept }
      : { kind: KIND_V1, root: c.root, lineCount: n, revealed: shown, redactedHashes: kept };
    return { ok: true, proof };
  } catch {
    return { ok: false, why: 'a commit made by commit(), and a list of line numbers to hide' };
  }
}

const SPEC = {
  [KIND_V2]: { version: 2, shown: 'visible', kept: 'hidden', salted: true, hex: HEX_V2 },
  [KIND_V1]: { version: 1, shown: 'revealed', kept: 'redactedHashes', salted: false, hex: HEX_V1 },
};
const bad = (why) => ({ ok: false, why });

/** read a proof's shape without hashing anything: { ok, spec, n, root, shown, kept } or { ok: false, why } */
function shape(p) {
  if (!isObj(p)) return bad('the proof is not a JSON object');
  const spec = Object.hasOwn(SPEC, p.kind) ? SPEC[p.kind] : null;
  if (!spec) return bad('unknown proof kind: expected "' + KIND_V2 + '", or the older "' + KIND_V1 + '"');
  const n = p.lineCount;
  if (!Number.isInteger(n) || n < 1) return bad('lineCount must be a whole number, at least 1');
  if (!isHex(p.root, spec.hex)) return bad('root must be 64 hex characters');
  const shown = p[spec.shown], kept = p[spec.kept];
  if (!Array.isArray(shown) || !Array.isArray(kept)) return bad('"' + spec.shown + '" and "' + spec.kept + '" must both be lists');
  if (shown.length + kept.length !== n) return bad('the proof lists ' + (shown.length + kept.length) + ' lines but lineCount says ' + n);
  const seen = new Set();
  const place = (e) => {
    if (!isObj(e) || !Number.isInteger(e.index) || e.index < 0 || e.index >= n) return 'every line needs a whole-number index from 0 to ' + (n - 1);
    if (seen.has(e.index)) return 'line ' + e.index + ' appears more than once';
    seen.add(e.index);
    return '';
  };
  for (const e of shown) {
    const why = place(e);
    if (why) return bad(why);
    if (typeof e.text !== 'string' || BAD_TEXT.test(e.text)) return bad('visible line ' + e.index + ' must be text with no line break or broken character');
    if (spec.salted && !isHex(e.salt, HEX_V2)) return bad('visible line ' + e.index + ' needs its salt, 64 lowercase hex characters');
  }
  for (const e of kept) {
    const why = place(e);
    if (why) return bad(why);
    if (!isHex(e.hash, spec.hex)) return bad('hidden line ' + e.index + ' needs its hash, 64 hex characters');
  }
  return { ok: true, spec, n, root: p.root.toLowerCase(), shown, kept };
}

function readTrusted(x) {
  if (x === undefined || x === null) return null;
  if (typeof x !== 'string') return false;
  const t = x.trim().toLowerCase();
  if (!t) return null;
  return HEX_V2.test(t) ? t : false;
}
function readReceived(x) {
  if (x === undefined || x === null) return null;
  if (typeof x !== 'string') return false;
  return x.trim() ? x : null;
}

function verdict(status, issues, extra) {
  return { status, version: null, issues, warnings: [], recomputedRoot: null, statedRoot: null, trustedCheck: 'not performed', receivedCheck: 'not performed', lineCount: null, hiddenCount: null, ...extra };
}
const malformed = (why) => verdict('MALFORMED', [why], {});

/**
 * verify a proof (an object, or its JSON text) against a root you trust from before the redaction, and optionally
 * against the redacted document you received. Status: VERIFIED (recomputes to its stated root AND to the trusted
 * root), CONSISTENT (recomputes to its stated root; no trusted root given), BREACHED (well-formed, but a root or the
 * received document does not match), MALFORMED (not a well-formed proof, or the trusted root is not 64 hex).
 */
export async function verify(proof, trustedRoot, received) {
  try {
    let p = proof;
    if (typeof proof === 'string') {
      try { p = JSON.parse(proof); } catch { return malformed('the proof is not valid JSON'); }
    }
    const trusted = readTrusted(trustedRoot);
    if (trusted === false) return malformed('the trusted root you gave is not 64 hex characters');
    const got = readReceived(received);
    if (got === false) return malformed('the received document must be text');
    const s = shape(p);
    if (!s.ok) return malformed(s.why);
    const v2 = s.spec.version === 2;
    const leaves = new Array(s.n);
    for (const e of s.shown) leaves[e.index] = v2 ? leafV2(e.index, e.salt, e.text) : leafV1(e.index, e.text);
    for (const e of s.kept) leaves[e.index] = e.hash.toLowerCase();
    const t = await top(await Promise.all(leaves), v2 ? nodeV2 : nodeV1);
    const recomputed = v2 ? await rootV2(s.n, t) : t;
    const issues = [];
    if (recomputed !== s.root) issues.push('the proof does not recompute to the root it states: a visible line, a salt or a hidden hash was changed after the proof was made');
    let trustedCheck = 'not performed';
    if (trusted) {
      trustedCheck = recomputed === trusted ? 'MATCH' : 'MISMATCH';
      if (recomputed !== trusted) issues.push('the proof does not recompute to the root you trust: it is not a proof of that committed document');
    }
    let receivedCheck = 'not performed';
    if (got) {
      const lines = splitLines(got);
      const sameCount = lines.length === s.n;
      const same = sameCount && s.shown.every((e) => lines[e.index] === e.text);
      receivedCheck = same ? 'MATCH' : 'MISMATCH';
      if (!sameCount) issues.push('the document you received has ' + lines.length + ' lines; the proof has ' + s.n);
      else if (!same) issues.push('a visible line in the document you received differs from the proof');
    }
    const warnings = v2 ? [] : [WARN_F1, WARN_F2];
    if (!trusted) warnings.push(WARN_NO_TRUST);
    const status = issues.length ? 'BREACHED' : trusted ? 'VERIFIED' : 'CONSISTENT';
    return verdict(status, issues, { version: s.spec.version, warnings, recomputedRoot: recomputed, statedRoot: s.root, trustedCheck, receivedCheck, lineCount: s.n, hiddenCount: s.kept.length });
  } catch {
    return malformed('the proof could not be read');
  }
}

/** the redacted document a well-formed proof stands for, with MARK on every hidden line; null when the proof is not well-formed */
export function preview(proof) {
  try {
    const s = shape(proof);
    if (!s.ok) return null;
    const out = new Array(s.n).fill(MARK);
    for (const e of s.shown) out[e.index] = e.text;
    return out.join('\n');
  } catch {
    return null;
  }
}

export default { KIND_V1, KIND_V2, MARK, sha256, leafV1, nodeV1, leafV2, nodeV2, rootV2, levels, splitLines, newSecret, commit, commitV1, prove, verify, preview };
