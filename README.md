# Kar-Veil

**Live:** https://sjgant80-hub.github.io/kar-veil/

Provable redaction, **no LLM judge**. Commit a document's original text to a root (and keep a secret), then make a
"veil proof" for a redacted version: the visible lines with their salts, and only the hashes of the hidden ones.
Anyone can recompute the root from that proof and catch tampering (an edited visible line, a forged hidden-line hash,
a dropped, added, moved or folded line) **without ever seeing the redacted content**. Optional ECDSA signing over the
root with WebCrypto. A static page and dependency-free modules: no backend, nothing sent anywhere.

## Version 2 (10 November 2026): two faults found in v1, closed and measured

On 5 November a probe of v1 (live since 26 September) found:

- **F1, structure forgery.** The line count was not in the root, and a hidden line's hash could be an inner node of
  the tree, so hidden lines could be folded together and the proof still matched. v2 binds the line count into the root.
- **F2, guessable hidden lines.** A hidden line's hash depended only on its position and text, so a guessable line
  could be confirmed by hashing guesses. v2 salts every line with `HMAC-SHA-256(secret, index)`; the secret never
  appears in a proof.

The fix and seven claims were sealed in [`CLAIMS-2026-11-05-veil-v2.md`](CLAIMS-2026-11-05-veil-v2.md) before any
code that measures them existed. [`measure.mjs`](measure.mjs) runs them on 400 seeded random documents and writes
[`receipts/measure.json`](receipts/measure.json); CI re-runs it on GitHub's runner and fails if it differs by one byte.
The live page reads the claims table from that receipt. v1 proofs still verify, always with both faults named.

## Files

| file | what it is | how it is proven |
|---|---|---|
| `veil.mjs` | commit, prove, verify, preview: the logic the page imports | `veil.test.mjs`; witness v0.6 mutation gate, every mutant |
| `veilcase.mjs` | the cost case, from the vendored sourced basis | `veilcase.test.mjs`; witness v0.6 mutation gate |
| `attacks.mjs` | seeded corpus, attacks T1–T9, the guessing attack, field mutations | reproduces both v1 faults in every applicable case |
| `measure.mjs` | runs the sealed claims, writes the receipt | re-derived byte for byte in CI |
| `gate.mjs` | writes and checks `receipts/gate.json` | CI `--verify`, plus the gate re-run on the runner |
| `index.html`, `page.mjs` | the live page | `page.test.mjs`: every control wired, no HTML sink, no typed result |

Re-run it:

```
git clone https://github.com/sjgant80-hub/kar-veil && cd kar-veil
git clone --depth 1 --branch v0.6 https://github.com/sjgant80-hub/witness .witness
node --test veil.test.mjs veilcase.test.mjs page.test.mjs
node measure.mjs --check
node gate.mjs --verify
```

**Honest limits:** it proves the visible lines are the original's and nothing else changed, relative to a root
recorded *before* the redaction. It says nothing about whether the redaction was legally right, does not timestamp,
and reveals how many lines there are and which positions are hidden.

Supplied by [AI Native Solutions](https://www.ai-nativesolutions.com); support terms are agreed per deployment.
Built by **Kar** for AI Native Solutions. MIT. Powered by the Konomi architecture, created by Thomas Frumkin.
