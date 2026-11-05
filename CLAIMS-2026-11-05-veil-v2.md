# Kar-Veil v2 — sealed claims, 2026-11-05

Sealed by Kar on 2026-11-05, in a commit of its own, before any of the code that measures it exists
(`veil.mjs`, `measure.mjs`, `receipts/measure.json` come in later commits). This file is never edited after
that commit. If a claim fails, the failure stays here and in the receipt; a fix is sealed in a NEW claims file.

## Why v2: two faults in the live v1 page (found 2026-11-05)

The page that went live on 2026-09-26 (commit 3d67cf6, logic unchanged since) hashes each line as
`SHA-256("leaf:" + index + ":" + text)`, folds pairs with `SHA-256("node:" + left + ":" + right)`, promotes an odd
hash unchanged, and takes the top of the fold as the root. A probe re-implementing exactly that logic showed:

- **F1 — structure forgery.** The line count is not bound into the root, and a hidden line's "hash" can be any
  64-hex value, including an inner node of the tree. A 4-line document's last two lines can be presented as ONE
  hidden line (their parent node) in a 3-line proof, and that proof recomputes to the original root. Folding every
  pair of leaves into its parent gives an all-hidden proof of half the lines that also recomputes to the root.
  The page says a dropped line makes the root not match; for this kind of drop it does match.
- **F2 — guessable hidden lines.** A hidden line's hash depends only on its index and its text, so anyone who can
  guess the text (a name from a staff list, "Yes"/"No", an amount) confirms the guess by hashing it. The page says
  the verifier never sees what was hidden; for a guessable line the verifier can recover it.

## The v2 construction (what the code must implement)

- A **commit secret**: 32 random bytes, kept by whoever commits, never put in a proof.
- A per-line **salt**: `HMAC-SHA-256(secret, "kar-veil:v2:salt:" + index)`, as 64 hex.
- A **leaf**: `SHA-256("kar-veil:v2:leaf:" + index + ":" + salt + ":" + text)`.
- A **node**: `SHA-256("kar-veil:v2:node:" + left + ":" + right)`; an odd hash at any level is promoted unchanged.
- The **root**: `SHA-256("kar-veil:v2:root:" + lineCount + ":" + top)`, so the line count, and with it the shape
  of the whole tree, is fixed by the root.
- A **v2 proof** carries, for each visible line, its index, its text and its salt; for each hidden line, its index
  and its leaf hash only.
- The verifier recomputes every visible leaf from the text and salt in front of it, never from a stated hash, and
  returns one of four verdicts: **VERIFIED** (recomputes to the root the proof states AND to a trusted root the
  verifier supplied), **CONSISTENT** (recomputes to its own stated root, but no trusted root was supplied, so it
  could be a proof of any document), **BREACHED** (well-formed, but a root or the received-document cross-check
  does not match), **MALFORMED** (not a well-formed proof, or the trusted root given is not a 64-hex root).
- v1 proofs still verify under the v1 rules (old roots stay checkable), always with both faults named as warnings.

## How it is measured

`measure.mjs`, deterministic: a seeded PRNG (seed `20261105`), no clock, no network, no timings in the output.
It writes `receipts/measure.json`; CI re-runs it on GitHub's runner and fails if the output differs by one byte.

- **Corpus:** 400 random documents, 1 to 48 lines each, lines drawn from ASCII words, colons, digits, spaces,
  accented and CJK characters, emoji, empty lines and repeated lines. Each committed under v2 with a 32-byte secret
  drawn from the PRNG, and under v1. Each line hidden with probability 0.4 (a proof that hides nothing is allowed).
- **Tamper classes** (applied to each document's honest proof wherever the class applies):
  - T1 change one character of a visible line's text
  - T2 replace a hidden line's hash with a different 64-hex value
  - T3 drop one entry (visible or hidden)
  - T4 add an extra line at the end (lineCount + 1)
  - T5 swap the indices of two entries
  - T6 structure forgery (F1): an all-hidden proof whose lines are the next level of the tree (every pair folded
    into its parent), lineCount = ceil(n / 2); documents with at least 2 lines
  - T7 T1, then rewrite the proof's stated root to the recomputed one, so the proof is internally consistent
  - T8 change one character of a visible line's salt (v2 only)
  - T9 change lineCount alone, by +1 and by -1
- **Guessing attack (F2):** for every hidden line, a candidate list of the true text plus 9 decoys; the attacker
  hashes each candidate at that index under v1, and under v2 with every salt the proof reveals and with an empty salt.

## The claims, with the bar each must clear

- **C1 — honest v2 proofs verify.** Every honest v2 proof, checked against the trusted root it was committed to,
  is VERIFIED. Bar: 400 of 400.
- **C2 — every tamper is caught (v2).** Every tampered v2 proof in T1–T9, checked against the trusted root, is
  BREACHED or MALFORMED, never VERIFIED or CONSISTENT. Bar: 100% in every class, every applicable case.
- **C3 — no trusted root, no VERIFIED.** Every honest v2 proof and every T7 proof checked WITHOUT a trusted root is
  CONSISTENT, never VERIFIED. Bar: all of them.
- **C4 — F1 reproduced on v1 and closed on v2.** T6 on v1 proofs: predicted VERIFIED in every applicable case (the
  fault, kept on the record). T6 on v2 proofs: 0 VERIFIED. Bar for v2: 0.
- **C5 — F2 reproduced on v1 and closed on v2.** The guessing attack confirms, predicted, every hidden line under v1
  (the fault, kept on the record), and 0 hidden lines under v2 without the secret. Bar for v2: 0 confirmed.
- **C6 — v1 proofs stay checkable.** Every honest v1 proof is VERIFIED against its v1 root, and every v1 result
  carries both fault warnings. Bar: 400 of 400, warnings on all.
- **C7 — the verifier never throws.** witness v0.6's hostile-input battery given as the proof (with and without a
  trusted root and a received document), and 2,000 random mutations of honest v2 proofs that each change one
  meaningful field (delete it, or set it to null, a number, a string, an array, an object, a negative or fractional
  index, or a lineCount of 1,000,000,001), each return a verdict. Bar: 0 throws, and 0 of the 2,000 mutations VERIFIED.

## Not claimed

That a redaction was legally right or removed enough; when a root was recorded (the root must be recorded
somewhere independent before the redaction, and Kar-Veil does not do that for you); who redacted; anything about
text that was not pasted (PDF layout, images, metadata). A v2 proof reveals the number of lines and which positions
are hidden. The security rests on SHA-256 and HMAC-SHA-256 being what the standards say they are.
