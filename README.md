# Shamir's Distributed Key Splitter

A stateless, 100% client-side, offline browser-based platform for splitting and reconstructing secrets (UTF-8 text or multi-megabyte binary files) using **Shamir's Secret Sharing** over $\text{GF}(2^8)$.

Built with **Angular 22** (Standalone Components), **TypeScript 6.0**, and a high-throughput $\text{GF}(2^8)$ cryptographic engine (`src/app/shamir-fast.ts`) that is binary-compatible with [Privy's `shamir-secret-sharing`](https://github.com/privy-io/shamir-secret-sharing) and [HashiCorp Vault](https://github.com/hashicorp/vault).

## Key Features

- **100% Offline & Zero Backend:** Runs entirely in browser RAM with zero network requests, no databases, and no persistent storage.
- **High-Throughput $\text{GF}(2^8)$ Engine (`shamir-fast.ts`):**
  - Precomputed 64 KB multiplication table (`MULT_TABLE`) over $P(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`, generator `0xE5`).
  - Batched 32 KB CSPRNG slices via Web Cryptography API (`window.crypto.getRandomValues()`).
  - Once-per-share $O(k^2)$ Lagrange basis weight precomputation for fast multi-megabyte reconstruction.
  - 50 ms cooperative main-thread yielding (`scheduler.yield()` with `setTimeout(0)` fallback) so large files never freeze the UI.
- **On-Demand Ephemeral QR Codes & File I/O:**
  - Capacity-guarded QR generation ($\le 2{,}300$ Base64 chars / ~1.7 KB, ISO/IEC 18004 Level M) rendered lazily onto off-DOM `<canvas>` elements as revocable PNG Blob URLs.
  - Direct `.txt` file export/import for multi-megabyte shares.
- **10-Stage Real-Time Share Validator:** Validates share prefixes, duplicate IDs, whitespace, URL-safe characters, RFC 4648 Base64 syntax, padding, length consistency, and $O(1)$ tail-quad $\text{GF}(2^8)$ X-coordinate deduplication.
- **Defense-in-Depth Memory & DOM Sanitization:** In-place `Uint8Array.fill(0)` zeroization, automated 5-second post-split cleanup timer, `Destroy All` button, and `pagehide` / `beforeunload` / `ngOnDestroy` teardown hooks.
- **Verified Software Supply Chain:** Ships with CycloneDX v1.6 SBOMs (`sbom.json`, `sbom.prod.json`) audited with Aqua Trivy (0 CVEs).

## Quick Start

### Prerequisites
- Node.js 20+ and npm

### Install & Run Locally
```bash
npm install
npm start
```
Open `http://localhost:4200/` in your browser.

### Build Static Offline Bundle
```bash
npm run build
```
The compiled static assets are written to `dist/frontend/browser/` and can be served locally or opened from read-only air-gapped media.

### Generate SBOM & Run Security Audit
```bash
npm run sbom
npm run sbom:prod
docker run --rm -v "$(pwd):/work" aquasec/trivy:latest sbom /work/sbom.json
```

## License

This project is licensed under the [MIT License](LICENSE). See [NOTICE](NOTICE) for third-party attributions and [SECURITY.md](SECURITY.md) for the security policy.
