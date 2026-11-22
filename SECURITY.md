# Security Policy

## Security Model

This application is designed as a **100% client-side, stateless, offline** browser utility for Shamir's Secret Sharing over $\text{GF}(2^8)$:

- **Zero Network I/O:** No backend servers, telemetry, analytics, or external runtime CDN requests.
- **OS CSPRNG:** Polynomial coefficients are generated strictly via `window.crypto.getRandomValues()`.
- **Memory & DOM Hygiene:** Mutable `Uint8Array` buffers are zeroed via `.fill(0)`, QR codes render lazily onto temporary off-DOM canvases exported as revocable Blob URLs, and a 5-second post-split auto-wipe timer clears DOM inputs and buffers.
- **Recommended Deployment:** For high-value root keys or seed phrases, run the compiled static bundle (`dist/frontend/browser/`) in an air-gapped, RAM-only Live-OS environment.

## Supply-Chain Verification

This repository includes CycloneDX v1.6 SBOMs (`sbom.json` and `sbom.prod.json`). You can regenerate and audit them locally with Aqua Trivy:

```bash
npm run sbom
npm run sbom:prod
docker run --rm -v "$(pwd):/work" aquasec/trivy:latest sbom /work/sbom.json
```

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not** open a public GitHub issue. Instead, report it privately via GitHub Security Advisories ("Report a vulnerability" in the Security tab of this repository) or contact the maintainer directly.
