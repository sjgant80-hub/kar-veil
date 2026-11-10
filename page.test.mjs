// page.test.mjs — the page's wiring, checked without a browser: every element the script touches exists, nothing from
// a proof can reach the page as HTML, the page explains itself, and no measured number is typed into it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const js = readFileSync(new URL('./page.mjs', import.meta.url), 'utf8');
const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));

test('the page runs the gated kernel: one module script, importing veil.mjs, attacks.mjs and veilcase.mjs', () => {
  assert.match(html, /<script type="module" src="page\.mjs"><\/script>/);
  assert.equal((html.match(/<script(?![^>]*application\/ld\+json)/g) || []).length, 1, 'one executable script, the module');
  for (const m of ['./veil.mjs', './attacks.mjs', './veilcase.mjs']) assert.ok(js.includes("from '" + m + "'"), m);
  assert.ok(!/function\s+(sha256Hex|leafHash|nodeHash|buildMerkleRoot)/.test(html + js), 'no second copy of the hashing logic');
});

test('every element the script reaches for is on the page (no dead control)', () => {
  const used = new Set([...js.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]));
  for (const [, id] of js.matchAll(/\['(case-[a-z]+)',/g)) used.add(id);
  for (const [, id] of js.matchAll(/'(bp-[a-z]+)'/g)) used.add(id);
  const missing = [...used].filter((id) => !ids.has(id));
  assert.deepEqual(missing, []);
  assert.ok(used.size > 40, 'the scan found the controls');
});

test('nothing from a proof or a pasted document can reach the page as HTML', () => {
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(js));
});

test('the page explains itself and carries the buyer sections', () => {
  for (const id of ['intro', 'start', 'commit', 'redact', 'verify', 'demo', 'v2', 'how', 'blueprint', 'adoption', 'business', 'faq']) assert.ok(ids.has(id), id);
  for (const role of ['CEO.', 'CFO.', 'COO.', 'CTO / CISO.', 'Legal and compliance.']) assert.ok(html.includes('<b>' + role + '</b>'), role);
  assert.match(html, /AI Native Solutions/);
  assert.match(html, /agreed per deployment/);
  assert.match(html, /<svg[^>]*role="img"/);
});

test('the v1 overclaims are gone, and the faults are said plainly', () => {
  assert.ok(!html.includes('would require breaking SHA-256'), 'v1 said a forged hidden hash needs a collision; F1 showed it did not');
  assert.match(html, /Fault F1, structure forgery/);
  assert.match(html, /Fault F2, guessable hidden lines/);
  assert.match(html, /CLAIMS-2026-11-05-veil-v2\.md/);
});

test('no measured result is typed into the page: the claims and gate counts are read from receipts/', () => {
  assert.ok(js.includes("getJSON('receipts/measure.json')"));
  assert.ok(js.includes("getJSON('receipts/gate.json')"));
  for (const typed of [/\b\d+ of \d+ (claims )?held\b/, /\b\d+\/\d+ killed\b/, /\b\d+ of \d+ changes caught\b/]) assert.ok(!typed.test(html), String(typed));
});
