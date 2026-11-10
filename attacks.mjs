// attacks.mjs — the measurement apparatus for CLAIMS-2026-11-05-veil-v2.md: a seeded PRNG, the random corpus, the nine
// tamper classes T1–T9, the guessing attack (F2) and the field mutations (C7). measure.mjs runs them across 400
// documents; the page's live attack run uses the same functions on its sample document, in the browser.
// Every attack works on a COPY of the proof; nothing here is trusted by verify(), which recomputes everything itself.

import { KIND_V2, levels, nodeV1, nodeV2, leafV1, leafV2, verify } from './veil.mjs';

/** mulberry32: a small, well-known 32-bit PRNG. Same seed, same stream, on every machine. */
export function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
export const int = (r, lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
export const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
const HEX = '0123456789abcdef';
const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
export const hex64 = (r) => Array.from({ length: 64 }, () => pick(r, HEX)).join('');
const clone = (x) => JSON.parse(JSON.stringify(x));

const WORDS = ['the', 'payment', 'approved', 'approver', 'case', 'ref', 'status', 'closed', 'open', 'note', 'Yes', 'No', 'J.', 'Smith',
  'A.', 'Jones', 'salary', 'account', 'date', 'invoice', 'patient', 'ward', 'witness', 'statement', 'amount', 'total', 'name',
  'address', 'reviewed', 'by', 'on', 'for', 'and', 'not', 'refused', 'granted'];
const ACCENTED = ['café', 'naïve', 'Zoë', 'São', 'Paulo', 'Ångström', 'Łódź', 'Müller', 'façade', 'résumé'];
const CJK = ['東京', '秘密', '報告書', '개인정보', '名前', '金額'];
const EMOJI = ['🔒', '📄', '✅', '❌', '👩‍⚕️', '🇬🇧'];

function token(r) {
  const roll = r();
  if (roll < 0.55) return pick(r, WORDS);
  if (roll < 0.67) return String(int(r, 0, 99999));
  if (roll < 0.77) return pick(r, ACCENTED);
  if (roll < 0.85) return pick(r, CJK);
  if (roll < 0.92) return pick(r, EMOJI);
  return pick(r, WORDS) + ':';
}
/** one random line: empty about 8% of the time, otherwise 1 to 8 tokens separated by one or two spaces */
export function line(r) {
  if (r() < 0.08) return '';
  const n = int(r, 1, 8);
  let s = token(r);
  for (let i = 1; i < n; i++) s += (r() < 0.1 ? '  ' : ' ') + token(r);
  return s;
}
/** one random document: 1 to 48 lines, about 8% of them repeating an earlier line */
export function documentText(r) {
  const n = int(r, 1, 48);
  const lines = [];
  for (let i = 0; i < n; i++) lines.push(lines.length && r() < 0.08 ? pick(r, lines) : line(r));
  return lines.join('\n');
}

/** change one character (one code point, so no surrogate is ever split) to a different one from `alphabet` */
export function changeOneChar(r, s, alphabet = ALNUM) {
  const cps = Array.from(s);
  const i = int(r, 0, cps.length - 1);
  let ch = pick(r, alphabet);
  while (ch === cps[i]) ch = pick(r, alphabet);
  cps[i] = ch;
  return cps.join('');
}

const names = (p) => (p.kind === KIND_V2 ? ['visible', 'hidden'] : ['revealed', 'redactedHashes']);

export const CLASSES = Object.freeze({
  T1: 'change one character of a visible line',
  T2: "replace a hidden line's hash with a different 64-hex value",
  T3: 'drop one line from the proof',
  T4: 'add an extra line at the end',
  T5: 'swap the positions of two lines',
  T6: 'fold every pair of lines into its parent (fault F1)',
  T7: "change a visible line, then rewrite the proof's stated root to match",
  T8: "change one character of a visible line's salt",
  T9: 'change the line count alone, by one up and by one down',
});

/** the tampered copies of `proof` for one class: [] when the class does not apply to this proof, two for T9 */
export async function tamper(cls, r, proof) {
  const [shownKey, keptKey] = names(proof);
  const v2 = proof.kind === KIND_V2;
  const p = clone(proof);
  const shown = p[shownKey], kept = p[keptKey];
  const editable = shown.filter((e) => e.text.length);
  if (cls === 'T1' || cls === 'T7') {
    if (!editable.length) return [];
    const e = pick(r, editable);
    e.text = changeOneChar(r, e.text);
    if (cls === 'T7') p.root = (await verify(p)).recomputedRoot;
    return [p];
  }
  if (cls === 'T2') {
    if (!kept.length) return [];
    const e = pick(r, kept);
    let h = hex64(r);
    while (h === e.hash) h = hex64(r);
    e.hash = h;
    return [p];
  }
  if (cls === 'T3') {
    const k = int(r, 0, shown.length + kept.length - 1);
    if (k < shown.length) shown.splice(k, 1);
    else kept.splice(k - shown.length, 1);
    return [p];
  }
  if (cls === 'T4') {
    shown.push(v2 ? { index: p.lineCount, text: line(r), salt: hex64(r) } : { index: p.lineCount, text: line(r) });
    p.lineCount += 1;
    return [p];
  }
  if (cls === 'T5') {
    const all = [...shown, ...kept];
    if (all.length < 2) return [];
    const a = int(r, 0, all.length - 1);
    let b = int(r, 0, all.length - 1);
    while (b === a) b = int(r, 0, all.length - 1);
    [all[a].index, all[b].index] = [all[b].index, all[a].index];
    return [p];
  }
  if (cls === 'T6') {
    if (proof.lineCount < 2) return [];
    const leaves = new Array(proof.lineCount);
    for (const e of shown) leaves[e.index] = v2 ? leafV2(e.index, e.salt, e.text) : leafV1(e.index, e.text);
    for (const e of kept) leaves[e.index] = e.hash;
    const next = (await levels(await Promise.all(leaves), v2 ? nodeV2 : nodeV1))[1];
    return [{ kind: proof.kind, root: proof.root, lineCount: next.length, [shownKey]: [], [keptKey]: next.map((hash, index) => ({ index, hash })) }];
  }
  if (cls === 'T8') {
    if (!v2 || !shown.length) return [];
    const e = pick(r, shown);
    e.salt = changeOneChar(r, e.salt, HEX);
    return [p];
  }
  if (cls === 'T9') {
    const up = clone(proof), down = clone(proof);
    up.lineCount += 1;
    down.lineCount -= 1;
    return [up, down];
  }
  return [];
}

/** the guessing attack on one hidden line: does any candidate text reproduce its hash? v1 needs no salt; v2 tries every salt the proof reveals, and none */
export async function guessConfirms(proof, hiddenEntry, candidates) {
  const v2 = proof.kind === KIND_V2;
  const salts = v2 ? [...proof.visible.map((e) => e.salt), ''] : [null];
  let hashes = 0, confirmed = false;
  for (const text of candidates) {
    for (const salt of salts) {
      const h = v2 ? await leafV2(hiddenEntry.index, salt, text) : await leafV1(hiddenEntry.index, text);
      hashes += 1;
      if (h === hiddenEntry.hash) confirmed = true;
    }
  }
  return { confirmed, hashes };
}

const ODD_VALUES = (r) => [null, int(r, -1000, 1000), 'x' + int(r, 0, 9999), [], [int(r, 0, 9)], {}, { index: 0 }];

/** one random change to one meaningful field of a v2 proof: delete it, or set it to null, a number, a string, an array,
 *  an object, a negative or fractional index, or a line count of 1,000,000,001. Never a no-op: a draw that leaves the
 *  proof unchanged is drawn again. Returns { proof, field, change }. */
export function mutateField(r, proof) {
  const before = JSON.stringify(proof);
  for (;;) {
    const p = clone(proof);
    const entries = [...p.visible.map((e) => ['visible', e]), ...p.hidden.map((e) => ['hidden', e])];
    const top = pick(r, ['kind', 'root', 'lineCount', 'visible', 'hidden', 'entry', 'entry', 'entry']);
    let holder = p, key = top, field = top;
    if (top === 'entry') {
      const [list, e] = pick(r, entries);
      holder = e;
      key = pick(r, list === 'visible' ? ['index', 'text', 'salt'] : ['index', 'hash']);
      field = list + '[' + e.index + '].' + key;
    }
    const changes = ['delete', 'null', 'number', 'string', 'array', 'object'];
    if (key === 'index') changes.push('negative index', 'fractional index');
    if (key === 'lineCount') changes.push('1000000001');
    const change = pick(r, changes);
    if (change === 'delete') delete holder[key];
    else if (change === 'null') holder[key] = null;
    else if (change === 'number') holder[key] = int(r, -1000, 1000);
    else if (change === 'string') holder[key] = 'x' + hex64(r).slice(0, int(r, 0, 64));
    else if (change === 'array') holder[key] = pick(r, ODD_VALUES(r).filter(Array.isArray));
    else if (change === 'object') holder[key] = pick(r, ODD_VALUES(r).filter((v) => v && typeof v === 'object' && !Array.isArray(v)));
    else if (change === 'negative index') holder[key] = -int(r, 1, 50);
    else if (change === 'fractional index') holder[key] = int(r, 0, 47) + 0.5;
    else holder[key] = 1000000001;
    if (JSON.stringify(p) !== before) return { proof: p, field, change };
  }
}

export default { rng, int, pick, hex64, line, documentText, changeOneChar, CLASSES, tamper, guessConfirms, mutateField };
