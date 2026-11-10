// page.mjs — the page's wiring. Every judgement comes from veil.mjs (the gated kernel), every attack from attacks.mjs,
// every cost figure from veilcase.mjs and the vendored basis, every measured number from receipts/. Text from a proof or
// a pasted document only ever reaches the page through textContent, never as HTML.
import { KIND_V1, MARK, commit, prove, verify, preview, splitLines, newSecret, commitV1 } from './veil.mjs';
import { rng, tamper, CLASSES, guessConfirms } from './attacks.mjs';
import { DEFAULTS, veilCase, sourcesOf } from './veilcase.mjs';

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const show = (id, on = true) => { $(id).style.display = on ? '' : 'none'; };
const say = (id, msg) => { $(id).textContent = msg || ''; };
const getJSON = async (p) => { const r = await fetch(p, { cache: 'no-cache' }); if (!r.ok) throw new Error(p + ': ' + r.status); return r.json(); };
const money = (x) => '£' + Math.round(x).toLocaleString('en-GB');

async function copyText(str, btn) {
  try { await navigator.clipboard.writeText(str); } catch {
    const t = el('textarea'); t.value = str; document.body.append(t); t.select(); try { document.execCommand('copy'); } catch {} t.remove();
  }
  if (btn) { const was = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = was; }, 1200); }
}
function downloadText(name, content) {
  const a = el('a'); a.href = URL.createObjectURL(new Blob([content], { type: 'application/json' })); a.download = name;
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

const SAMPLE = [
  'Investigation note, case HR-2291 (a made-up sample)',
  'Complainant: Priya Shah',
  'Respondent: Mark Ellis',
  'Date of interview: 4 November 2026',
  'Finding: the complaint is upheld in part',
  'Action: written warning; mediation offered',
].join('\n');

// ── 1 · commit ──────────────────────────────────────────────────────────────
$('btn-load-sample').addEventListener('click', () => { $('original-doc').value = SAMPLE; say('commit-error'); });
let lastCommit = null;
$('btn-commit').addEventListener('click', async () => {
  say('commit-error'); show('commit-result', false); show('sign-output', false);
  const text = $('original-doc').value;
  if (!text.trim()) { say('commit-error', 'Paste the original document first.'); return; }
  const c = await commit(text);
  if (!c.ok) { say('commit-error', c.why); return; }
  lastCommit = c;
  $('commit-linecount').textContent = String(c.lineCount);
  $('commit-root').textContent = c.root;
  $('commit-secret').textContent = c.secret;
  show('commit-result');
  // carry it to step 2, so a first-time user can go straight on
  $('redact-doc-input').value = text; $('redact-secret').value = c.secret; $('redact-expected-root').value = c.root;
});
$('btn-copy-root').addEventListener('click', (e) => lastCommit && copyText(lastCommit.root, e.currentTarget));
$('btn-copy-secret').addEventListener('click', (e) => lastCommit && copyText(lastCommit.secret, e.currentTarget));

// optional ECDSA P-256 signature over the root, with a key made in this tab
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from((h.match(/../g) || []).map((x) => parseInt(x, 16)));
let signingKey = null;
$('btn-sign-root').addEventListener('click', async () => {
  if (!lastCommit) return;
  signingKey = signingKey || await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey.privateKey, new TextEncoder().encode(lastCommit.root));
  $('sign-sig').textContent = hex(sig);
  $('sign-pub').textContent = JSON.stringify(await crypto.subtle.exportKey('jwk', signingKey.publicKey));
  show('sign-output');
});

// ── 2 · redact ──────────────────────────────────────────────────────────────
const hiddenSet = new Set();
$('btn-parse-lines').addEventListener('click', () => {
  say('redact-error'); hiddenSet.clear();
  const list = $('redact-line-list'); list.replaceChildren();
  const lines = splitLines($('redact-doc-input').value);
  if (!$('redact-doc-input').value.trim()) { say('redact-error', 'Paste the original document first.'); return; }
  lines.forEach((text, i) => {
    const row = el('label', 'line-row');
    const cb = el('input'); cb.type = 'checkbox';
    cb.addEventListener('change', () => { if (cb.checked) hiddenSet.add(i); else hiddenSet.delete(i); row.classList.toggle('redacted', cb.checked); });
    row.append(cb, el('span', 'idx', String(i)), el('span', 'txt', text || '(empty line)'));
    list.append(row);
  });
  show('redact-line-list'); $('btn-generate-proof').disabled = false;
});
let lastProof = null;
$('btn-generate-proof').addEventListener('click', async () => {
  say('redact-error'); show('redact-result', false);
  const secret = $('redact-secret').value.trim();
  const c = await commit($('redact-doc-input').value, secret);
  if (!c.ok) { say('redact-error', c.why); return; }
  const expected = $('redact-expected-root').value.trim().toLowerCase();
  if (expected && expected !== c.root) { say('redact-error', 'This text and secret do not commit to the root you gave. Check the original is pasted exactly, and the secret is the one from its commit.'); return; }
  const r = prove(c, [...hiddenSet].sort((a, b) => a - b));
  if (!r.ok) { say('redact-error', r.why); return; }
  lastProof = r.proof;
  $('redacted-preview').textContent = preview(r.proof);
  $('proof-output').value = JSON.stringify(r.proof, null, 2);
  show('redact-result');
});
$('btn-copy-proof').addEventListener('click', (e) => lastProof && copyText(JSON.stringify(lastProof, null, 2), e.currentTarget));
$('btn-download-proof').addEventListener('click', () => lastProof && downloadText('proof.json', JSON.stringify(lastProof, null, 2)));
$('btn-send-to-verify').addEventListener('click', () => {
  if (!lastProof) return;
  $('verify-proof-input').value = JSON.stringify(lastProof, null, 2);
  $('verify-expected-root').value = $('redact-expected-root').value.trim() || lastProof.root;
  $('verify-crosscheck-doc').value = preview(lastProof);
  $('verify').scrollIntoView({ behavior: 'smooth' });
});

// ── 3 · verify ──────────────────────────────────────────────────────────────
const VERDICT_CLASS = { VERIFIED: 'verified', CONSISTENT: 'consistent', BREACHED: 'breached', MALFORMED: 'malformed' };
const VERDICT_WORDS = {
  VERIFIED: 'Every visible line is the original\'s, and nothing else changed.',
  CONSISTENT: 'The proof agrees with itself, but no published root was given, so it could be a proof of any document.',
  BREACHED: 'Something was changed: see below.',
  MALFORMED: 'This is not a well-formed veil proof.',
};
function renderVerdict(v) {
  const wrap = $('verify-verdict-wrap'); wrap.replaceChildren();
  wrap.append(el('div', 'verdict ' + VERDICT_CLASS[v.status], v.status), el('p', 'hint', VERDICT_WORDS[v.status]));
  $('verify-issues').replaceChildren(...v.issues.map((m) => el('li', null, m)));
  $('verify-warnings').replaceChildren(...v.warnings.map((m) => el('li', null, m)));
  $('verify-version').textContent = v.version ? 'v' + v.version + (v.version === 1 ? ' (old: both faults apply)' : '') : '—';
  $('verify-recomputed-root').textContent = v.recomputedRoot || '—';
  $('verify-declared-root').textContent = v.statedRoot || '—';
  $('verify-external-check').textContent = v.trustedCheck;
  $('verify-crosscheck-result').textContent = v.receivedCheck;
  show('verify-result');
}
$('btn-verify').addEventListener('click', async () => {
  renderVerdict(await verify($('verify-proof-input').value, $('verify-expected-root').value, $('verify-crosscheck-doc').value));
});
$('verify-file').addEventListener('change', async (e) => {
  const f = e.target.files && e.target.files[0];
  if (f) $('verify-proof-input').value = await f.text();
});
$('btn-verify-sig').addEventListener('click', async () => {
  const out = $('sig-verify-result');
  try {
    const root = $('verify-expected-root').value.trim().toLowerCase() || JSON.parse($('verify-proof-input').value).root;
    const key = await crypto.subtle.importKey('jwk', JSON.parse($('verify-pub').value), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, unhex($('verify-sig').value.trim()), new TextEncoder().encode(root));
    out.textContent = ok ? 'The signature is valid for this root and this key.' : 'The signature does NOT match this root and key.';
  } catch { out.textContent = 'Could not check: the signature must be hex and the key an ECDSA P-256 JWK.'; }
});

// ── attack it ───────────────────────────────────────────────────────────────
$('btn-demo-run').addEventListener('click', async (e) => {
  const btn = e.currentTarget; btn.disabled = true;
  const out = $('demo-out'); out.replaceChildren(el('p', null, 'running…'));
  try {
    const c = await commit(SAMPLE, newSecret());
    const p = prove(c, [1, 2]).proof;
    const honest = await verify(p, c.root);
    const r = rng(20261110);
    const table = el('table', 't');
    const head = el('tr'); for (const h of ['attack', 'what it does', 'verdict against the root']) head.append(el('th', null, h));
    table.append(el('thead')); table.tHead.append(head);
    const body = el('tbody'); table.append(body);
    const row = (a, b, status) => { const tr = el('tr'); tr.append(el('td', null, a), el('td', null, b)); const td = el('td'); td.append(el('b', /VERIFIED/.test(status) && a !== 'honest proof' ? 'no' : 'ok', status)); tr.append(td); body.append(tr); };
    row('honest proof', 'the proof as made, two lines hidden', honest.status);
    for (const cls of Object.keys(CLASSES)) {
      const ts = await tamper(cls, r, p);
      const st = [];
      for (const t of ts) st.push((await verify(t, c.root)).status);
      row(cls, CLASSES[cls], st.length ? st.join(', ') : 'does not apply to this sample');
    }
    // the two v1 faults on the same sample, so the difference is visible
    const c1 = await commitV1(SAMPLE);
    const p1 = prove(c1, [1, 2]).proof;
    const f1 = (await tamper('T6', r, p1))[0];
    const f1v = (await verify(f1, c1.root)).status;
    const g1 = await guessConfirms(p1, p1.redactedHashes[0], ['Complainant: Priya Shah', 'Complainant: Ann Lee']);
    const g2 = await guessConfirms(p, p.hidden[0], ['Complainant: Priya Shah', 'Complainant: Ann Lee']);
    const tr1 = el('tr'); tr1.append(el('td', null, 'F1 on v1'), el('td', null, 'the same fold (T6) against an old v1 proof of this sample'), el('td')); tr1.lastChild.append(el('b', f1v === 'VERIFIED' ? 'no' : 'ok', f1v + (f1v === 'VERIFIED' ? ': the old fault' : ''))); body.append(tr1);
    const tr2 = el('tr'); tr2.append(el('td', null, 'F2'), el('td', null, 'guess hidden line 1 is "Complainant: Priya Shah"'), el('td'));
    tr2.lastChild.append(el('b', g1.confirmed ? 'no' : 'ok', 'v1: ' + (g1.confirmed ? 'confirmed' : 'not confirmed')), document.createTextNode(' · '), el('b', g2.confirmed ? 'no' : 'ok', 'v2: ' + (g2.confirmed ? 'confirmed' : 'not confirmed, the salt is secret')));
    body.append(tr2);
    const wrap = el('div', 'tablewrap'); wrap.append(table);
    out.replaceChildren(el('p', null, 'Sample committed under v2 with a fresh secret; lines 1 and 2 hidden. Root ' + c.root.slice(0, 16) + '…'), wrap);
  } catch (err) {
    out.replaceChildren(el('p', null, 'The run could not finish: ' + (err && err.message ? err.message : String(err))));
  } finally { btn.disabled = false; }
});

// ── what changed in v2: the sealed claims, read from the receipt ─────────────
(async () => {
  const tbody = $('claims-table').tBodies[0];
  try {
    const m = await getJSON('receipts/measure.json');
    tbody.replaceChildren();
    for (const [id, c] of Object.entries(m.claims)) {
      const tr = el('tr');
      tr.append(el('td', null, id + ' · ' + c.claim), el('td', null, c.bar), el('td', null, c.got));
      const td = el('td'); td.append(el('b', c.held ? 'ok' : 'no', c.held ? 'HELD' : 'FAILED')); tr.append(td);
      tbody.append(tr);
    }
    say('claims-note', m.held + ' of ' + m.of + ' claims held on ' + m.corpus.documents + ' documents (' + m.corpus.lines.toLocaleString('en-GB') + ' lines, ' + m.corpus.hiddenLines.toLocaleString('en-GB') + ' hidden), seed ' + m.seed + '. The v1 results in C4 and C5 are the faults reproduced, on purpose: they show the attacks have teeth.');
  } catch { tbody.replaceChildren(el('tr')); tbody.rows[0].append(el('td', null, 'the receipt could not be read; open receipts/measure.json directly')); }
})();

// ── blueprint: the gate counts, read from the receipt ───────────────────────
(async () => {
  try {
    const g = await getJSON('receipts/gate.json');
    for (const k of g.kernels) {
      const id = k.file === 'veil.mjs' ? 'bp-veil' : k.file === 'veilcase.mjs' ? 'bp-veilcase' : null;
      if (id) $(id).textContent = k.killed + ' of ' + k.total + ' changes caught' + (k.ignored.length ? ', ' + k.ignored.length + ' reviewed as equivalent' : '') + (k.clean ? ', nothing survived' : ', NOT clean') + ' · tests: ' + k.tests.replace('node --test ', '');
    }
  } catch { for (const id of ['bp-veil', 'bp-veilcase']) $(id).textContent = 'the gate receipt could not be read; open receipts/gate.json'; }
})();

// ── the cost case ───────────────────────────────────────────────────────────
const CASE = [['case-docs', 'docsPerWeek', 1], ['case-min', 'minutesPerCheck', 1], ['case-share', 'share', 100], ['case-sec', 'secondsPerVerify', 1], ['case-tool', 'toolPerMonth', 1], ['case-years', 'years', 1]];
let BASIS = null;
function runCase() {
  if (!BASIS) return;
  const input = {};
  for (const [id, key, scale] of CASE) { const v = $(id).value; input[key] = v === '' ? NaN : Number(v) / scale; }
  const r = veilCase(input, BASIS);
  if (!r.ok) {
    // the kernel takes the share as 0 to 1; this form asks for a percentage, so say it in the form's terms
    say('case-why', 'Check the inputs: ' + (/share/.test(r.why) ? 'the share is a percentage, 0 to 100' : r.why));
    $('case-big').textContent = ''; $('case-rows').replaceChildren();
    return;
  }
  say('case-why');
  $('case-big').textContent = 'About ' + Math.round(r.hoursPerYear.saved).toLocaleString('en-GB') + ' hours of checking a year handed to the proof; ' + money(r.total.saved) + ' over ' + r.inputs.years + ' year' + (r.inputs.years === 1 ? '' : 's') + ' at the UK median wage.';
  $('case-rows').replaceChildren(...r.rows.map((y) => { const tr = el('tr'); for (const v of [String(y.year), money(y.today), money(y.withProofs), money(y.saved)]) tr.append(el('td', null, v)); return tr; }));
}
(async () => {
  for (const [id, key, scale] of CASE) { $(id).value = String(DEFAULTS[key] * scale); $(id).addEventListener('input', runCase); }
  try {
    BASIS = await getJSON('vendor/sovereign-enterprise/data/basis.json');
    const s = sourcesOf(BASIS);
    const p = $('case-sources'); p.replaceChildren(document.createTextNode('Sources: '));
    s.forEach((x, i) => { if (i) p.append(document.createTextNode('; ')); const a = el('a', null, x.what); a.href = x.source; p.append(a, document.createTextNode(' (' + x.value + (x.unit ? ' ' + x.unit : '') + ')')); });
    runCase();
  } catch { say('case-why', 'The sourced basis could not be read, so no figure is shown.'); }
})();
