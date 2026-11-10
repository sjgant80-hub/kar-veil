// veilcase.mjs — the cost case on Kar-Veil's page: what it costs a team today to confirm that a redacted copy is a
// faithful view of its original (open both, compare them line by line, ask the redactor, chase the answer), and what
// that costs once every redaction comes with a veil proof anyone checks in seconds.
//
// The only external figures are read from the vendored, sourced basis (vendor/sovereign-enterprise/data/basis.json,
// byte for byte from sjgant80-hub/sovereign-enterprise): the UK median hourly wage and CPI. The document counts, the
// minutes, the share of the check a proof takes over and any tool the team pays for today are the reader's own.
// Floors, never top ends: staff time at the median wage with on-costs left out. No price of ours appears: Kar-Veil is
// MIT and runs in the browser; support, where a team wants it, is agreed per deployment and is not in this case.
//
// Pure, total, deterministic: garbage in gives { ok: false, why }, never a throw.

export const DEFAULTS = Object.freeze({ docsPerWeek: 20, minutesPerCheck: 12, share: 0.8, secondsPerVerify: 10, toolPerMonth: 0, years: 3 });
export const BASIS_KEYS = Object.freeze(['wageMedianHourly', 'cpi']);
export const WEEKS_PER_YEAR = 52;

const isNum = (x) => typeof x === 'number' && Number.isFinite(x) && x >= 0;
const r2 = (x) => Math.round(x * 100) / 100;

/** the two basis figures the case reads, each a sourced number; null when one is missing or unreadable */
export function figures(basis) {
  try {
    const out = { wage: basis.wageMedianHourly.value, cpi: basis.cpi.value };
    return isNum(out.wage) && isNum(out.cpi) ? out : null;
  } catch { return null; }
}

/** where each figure came from, for the page to list beside the numbers */
export function sourcesOf(basis) {
  try { return BASIS_KEYS.map((k) => ({ key: k, value: basis[k].value, unit: basis[k].unit || '', what: basis[k].what, source: basis[k].source })); } catch { return []; }
}

/**
 * the case. inputs (all the reader's own): docsPerWeek redacted copies someone has to trust, minutesPerCheck to
 * confirm one by hand today, share (0 to 1) of that checking a veil proof takes over, secondsPerVerify to check a
 * proof, toolPerMonth paid today for any comparison or review tool the proof would replace, years (1 to 10).
 */
export function veilCase(input, basis) {
  try {
    const f = figures(basis);
    if (!f) return { ok: false, why: 'the sourced basis could not be read' };
    const x = { ...DEFAULTS, ...(input && typeof input === 'object' ? input : {}) };
    for (const k of ['docsPerWeek', 'minutesPerCheck', 'secondsPerVerify', 'toolPerMonth']) {
      if (!isNum(x[k])) return { ok: false, why: k + ' must be a number, 0 or more' };
    }
    if (!isNum(x.share) || x.share > 1) return { ok: false, why: 'share must be from 0 to 1' };
    if (!Number.isInteger(x.years) || x.years < 1 || x.years > 10) return { ok: false, why: 'years must be a whole number from 1 to 10' };

    const docsPerYear = x.docsPerWeek * WEEKS_PER_YEAR;
    const hoursToday = docsPerYear * x.minutesPerCheck / 60;
    // with proofs: the share the proof covers costs seconds; the rest is still checked by hand
    const hoursWith = docsPerYear * (x.share * x.secondsPerVerify / 3600 + (1 - x.share) * x.minutesPerCheck / 60);
    const rows = [];
    let todayTotal = 0, withTotal = 0;
    for (let y = 1; y <= x.years; y++) {
      const rise = Math.pow(1 + f.cpi, y - 1);
      const today = (hoursToday * f.wage + x.toolPerMonth * 12) * rise;
      const withProofs = hoursWith * f.wage * rise;
      todayTotal += today;
      withTotal += withProofs;
      rows.push({ year: y, today: r2(today), withProofs: r2(withProofs), saved: r2(today - withProofs) });
    }
    return {
      ok: true,
      inputs: x,
      basis: f,
      hoursPerYear: { today: r2(hoursToday), withProofs: r2(hoursWith), saved: r2(hoursToday - hoursWith) },
      rows,
      total: { today: r2(todayTotal), withProofs: r2(withTotal), saved: r2(todayTotal - withTotal) },
    };
  } catch {
    return { ok: false, why: 'the inputs could not be read' };
  }
}

export default { DEFAULTS, BASIS_KEYS, WEEKS_PER_YEAR, figures, sourcesOf, veilCase };
