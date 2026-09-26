# Kar-Veil

**Live:** https://sjgant80-hub.github.io/kar-veil/

Provable redaction — **no LLM judge**. Commit a document's original text to a Merkle root, then generate
a "veil proof" for a redacted version that reveals only the visible lines plus the *hashes* of the hidden
ones. Anyone can recompute the same root from that proof and catch tampering — an edited visible line, a
forged hidden-line hash, a dropped or reordered line — **without ever seeing the redacted content**.
Optional ECDSA signing over WebCrypto.

One self-contained HTML file — no backend, no network, nothing sent anywhere, runs in your browser.

**Honest limit:** it only proves structural faithfulness relative to a root recorded *before* the
redaction. It says nothing about whether the redaction was legally correct, and it does not do the
pre-redaction timestamping for you.

Built by **Kar** (karma-didy) on the FallForge estate.
