// veilcase.test.mjs — the cost case. Expected values are worked out by hand below from the sourced basis figures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import C, { DEFAULTS, BASIS_KEYS, WEEKS_PER_YEAR, figures, sourcesOf, veilCase } from './veilcase.mjs';

const RAW = readFileSync(new URL('./vendor/sovereign-enterprise/data/basis.json', import.meta.url));
const BASIS = JSON.parse(RAW);
const r2 = (x) => Math.round(x * 100) / 100;

test('the vendored basis is the pinned file, and the two figures read from it are sourced', () => {
  assert.equal(createHash('sha256').update(RAW).digest('hex'), '83e9c2effa2f81596dcfa7110f030940032c1910cdf928d27d628ae59d73bb42');
  assert.deepEqual(figures(BASIS), { wage: 19.67, cpi: 0.031 });
  assert.deepEqual(BASIS_KEYS, ['wageMedianHourly', 'cpi']);
  const s = sourcesOf(BASIS);
  assert.deepEqual(s.map((x) => x.key), BASIS_KEYS);
  assert.ok(s.every((x) => /^https:\/\/www\.ons\.gov\.uk\//.test(x.source) && x.what.length > 20));
  assert.equal(s[0].unit, 'GBP per hour');
  assert.equal(s[1].unit, '');
  assert.deepEqual(sourcesOf(null), []);
});

test('figures: null when a figure is missing, negative or not a number', () => {
  assert.equal(figures(null), null);
  assert.equal(figures({}), null);
  assert.equal(figures({ wageMedianHourly: { value: 19.67 }, cpi: { value: -0.1 } }), null);
  assert.equal(figures({ wageMedianHourly: { value: '19' }, cpi: { value: 0.03 } }), null);
  assert.equal(figures({ wageMedianHourly: { value: 19 }, cpi: { value: NaN } }), null);
  assert.deepEqual(figures({ wageMedianHourly: { value: 0 }, cpi: { value: 0 } }), { wage: 0, cpi: 0 });
});

test('the default case, worked by hand: 20 copies a week, 12 minutes each, a proof takes over 80% in 10 seconds', () => {
  const c = veilCase({}, BASIS);
  assert.equal(c.ok, true);
  assert.deepEqual(c.inputs, DEFAULTS);
  assert.equal(WEEKS_PER_YEAR, 52);
  // 20 x 52 = 1,040 copies a year; today 1,040 x 12 min = 208 h; with proofs 1,040 x (0.8 x 10 s + 0.2 x 12 min)
  const hoursWith = 1040 * (0.8 * 10 / 3600 + 0.2 * 12 / 60);
  assert.deepEqual(c.hoursPerYear, { today: 208, withProofs: r2(hoursWith), saved: r2(208 - hoursWith) });
  assert.equal(c.rows.length, 3);
  assert.deepEqual(c.rows[0], { year: 1, today: r2(208 * 19.67), withProofs: r2(hoursWith * 19.67), saved: r2((208 - hoursWith) * 19.67) });
  // year 2 rises by one year of CPI, year 3 by two
  assert.equal(c.rows[1].today, r2(208 * 19.67 * 1.031));
  assert.equal(c.rows[2].today, r2(208 * 19.67 * 1.031 * 1.031));
  const total = 208 * 19.67 * (1 + 1.031 + 1.031 ** 2);
  assert.equal(c.total.today, r2(total));
  assert.equal(c.total.saved, r2(total - hoursWith * 19.67 * (1 + 1.031 + 1.031 ** 2)));
});

test('a tool paid for today counts on the today side only, every year, rising with CPI', () => {
  const a = veilCase({ toolPerMonth: 100, years: 2 }, BASIS), b = veilCase({ years: 2 }, BASIS);
  assert.equal(r2(a.rows[0].today - b.rows[0].today), 1200);
  assert.equal(r2(a.rows[1].today - b.rows[1].today), r2(1200 * 1.031));
  assert.equal(a.rows[0].withProofs, b.rows[0].withProofs);
});

test('the edges: share 0 saves nothing, share 1 leaves only the seconds; one year and ten years both run', () => {
  const none = veilCase({ share: 0 }, BASIS);
  assert.equal(none.hoursPerYear.saved, 0);
  const all = veilCase({ share: 1, secondsPerVerify: 36 }, BASIS);
  assert.equal(all.hoursPerYear.withProofs, r2(1040 * 36 / 3600));
  assert.equal(veilCase({ years: 1 }, BASIS).rows.length, 1);
  assert.equal(veilCase({ years: 10 }, BASIS).rows.length, 10);
  assert.equal(veilCase({ docsPerWeek: 0 }, BASIS).total.today, 0);
});

test('garbage in gives a reason, never a throw', () => {
  const why = (input, basis = BASIS) => veilCase(input, basis).why;
  assert.equal(why({}, {}), 'the sourced basis could not be read');
  for (const k of ['docsPerWeek', 'minutesPerCheck', 'secondsPerVerify', 'toolPerMonth']) {
    assert.equal(why({ [k]: -1 }), k + ' must be a number, 0 or more');
    assert.equal(why({ [k]: '5' }), k + ' must be a number, 0 or more');
  }
  assert.equal(why({ share: 1.01 }), 'share must be from 0 to 1');
  assert.equal(why({ share: -0.1 }), 'share must be from 0 to 1');
  assert.equal(veilCase({ share: 1 }, BASIS).ok, true);
  for (const y of [0, 11, 2.5, '3']) assert.equal(why({ years: y }), 'years must be a whole number from 1 to 10');
  assert.deepEqual(veilCase('ab', BASIS).inputs, DEFAULTS);   // not an object: the defaults, and a string's characters never become inputs
  assert.equal(veilCase(null, BASIS).ok, true);
  const toxic = { get docsPerWeek() { throw new Error('boom'); } };
  assert.deepEqual(veilCase(toxic, BASIS), { ok: false, why: 'the inputs could not be read' });
  assert.equal(typeof C.veilCase, 'function');
});
