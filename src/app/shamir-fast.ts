// High-speed GF(2^8) Shamir's Secret Sharing Engine
// Uses the same irreducible polynomial (x^8 + x^4 + x^3 + x + 1, generator 0xe5)
// and share format (last byte = X coordinate) as shamir-secret-sharing / HashiCorp Vault,
// so shares are 100% compatible with existing shares, while supporting multi-megabyte payloads.

const LOG_TABLE = new Uint8Array([
  0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
  0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
  0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
  0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
  0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
  0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
  0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
  0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
  0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
  0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
  0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
  0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
  0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
  0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
  0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
  0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38,
]);

const EXP_TABLE = new Uint8Array([
  0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
  0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
  0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
  0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
  0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
  0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
  0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
  0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
  0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
  0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
  0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
  0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
  0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
  0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
  0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
  0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01,
]);

// Precompute 256x256 multiplication table in GF(2^8) for O(1) inner-loop lookup
const MULT_TABLE = new Uint8Array(256 * 256);
for (let a = 1; a < 256; a++) {
  const logA = LOG_TABLE[a];
  const rowOffset = a << 8;
  for (let b = 1; b < 256; b++) {
    const logB = LOG_TABLE[b];
    MULT_TABLE[rowOffset | b] = EXP_TABLE[(logA + logB) % 255];
  }
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('Cannot divide by zero in GF(256)');
  if (a === 0) return 0;
  const diff = (LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255;
  return EXP_TABLE[diff];
}

// Fill buffer with CSPRNG bytes in 65536-byte chunks (WebCrypto quota limit)
function fillRandomBytes(buffer: Uint8Array): void {
  const MAX_CHUNK = 65536;
  for (let offset = 0; offset < buffer.byteLength; offset += MAX_CHUNK) {
    const len = Math.min(MAX_CHUNK, buffer.byteLength - offset);
    crypto.getRandomValues(buffer.subarray(offset, offset + len) as Uint8Array<ArrayBuffer>);
  }
}

function generateShuffledCoordinates(): Uint8Array {
  const coords = new Uint8Array(255);
  for (let i = 0; i < 255; i++) {
    coords[i] = i + 1;
  }
  const rand = new Uint8Array(255);
  crypto.getRandomValues(rand);
  for (let i = 0; i < 255; i++) {
    const j = rand[i] % 255;
    const tmp = coords[i];
    coords[i] = coords[j];
    coords[j] = tmp;
  }
  return coords;
}

async function yieldToMain(): Promise<void> {
  const win = window as any;
  if ('scheduler' in win && typeof win.scheduler?.yield === 'function') {
    await win.scheduler.yield();
  } else {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

/**
 * Splits a Uint8Array secret of any size (including multiple megabytes) into `shares` shares
 * with threshold `threshold`, yielding to the browser main thread every 50ms.
 */
export async function fastSplit(
  secret: Uint8Array,
  shares: number,
  threshold: number,
  onProgress?: (percent: number) => void
): Promise<Uint8Array[]> {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 1) {
    throw new Error('Secret cannot be empty');
  }
  if (!Number.isInteger(shares) || shares < 2 || shares > 255) {
    throw new RangeError('Total shares (n) must be between 2 and 255');
  }
  if (!Number.isInteger(threshold) || threshold < 2 || threshold > 255) {
    throw new RangeError('Threshold (m) must be between 2 and 255');
  }
  if (shares < threshold) {
    throw new Error('Total shares (n) cannot be less than threshold (m)');
  }

  const secretLength = secret.byteLength;
  const degree = threshold - 1;
  const xCoordinates = generateShuffledCoordinates();

  const result: Uint8Array[] = new Array(shares);
  for (let j = 0; j < shares; j++) {
    const share = new Uint8Array(secretLength + 1);
    share[secretLength] = xCoordinates[j];
    result[j] = share;
  }

  // Process in chunks of 32 KB so random coefficient buffer stays tiny in L1/L2 cache
  const CHUNK_BYTES = 32768;
  const randomCoeffs = new Uint8Array(CHUNK_BYTES * degree);
  let deadline = performance.now() + 50;

  for (let chunkStart = 0; chunkStart < secretLength; chunkStart += CHUNK_BYTES) {
    const chunkLen = Math.min(CHUNK_BYTES, secretLength - chunkStart);
    const neededRand = chunkLen * degree;
    const randView = randomCoeffs.subarray(0, neededRand);
    fillRandomBytes(randView);

    for (let i = 0; i < chunkLen; i++) {
      const secretIdx = chunkStart + i;
      const intercept = secret[secretIdx];
      const coeffBase = i * degree;
      const highestCoeff = randView[coeffBase + degree - 1];

      for (let j = 0; j < shares; j++) {
        const x = xCoordinates[j];
        const xRow = x << 8;
        let y = highestCoeff;
        for (let d = degree - 2; d >= 0; d--) {
          y = MULT_TABLE[xRow | y] ^ randView[coeffBase + d];
        }
        y = MULT_TABLE[xRow | y] ^ intercept;
        result[j][secretIdx] = y;
      }
    }

    if (performance.now() >= deadline) {
      if (onProgress) {
        onProgress(Math.min(99, Math.round(((chunkStart + chunkLen) / secretLength) * 100)));
      }
      await yieldToMain();
      deadline = performance.now() + 50;
    }
  }

  // Zero-out temporary random coefficients buffer
  randomCoeffs.fill(0);
  if (onProgress) onProgress(100);
  return result;
}

/**
 * Combines `shares` to reconstruct the secret in O(k * N) time by precomputing
 * the Lagrange basis weights at x=0 once, rather than per byte.
 */
export async function fastCombine(
  shares: Uint8Array[],
  onProgress?: (percent: number) => void
): Promise<Uint8Array> {
  if (!Array.isArray(shares) || shares.length < 2 || shares.length > 255) {
    throw new RangeError('At least 2 shares are required to reconstruct the secret');
  }

  const shareLength = shares[0].byteLength;
  if (shareLength < 2) {
    throw new Error('Each share must be at least 2 bytes');
  }

  const k = shares.length;
  const xSamples = new Uint8Array(k);
  const seen = new Set<number>();

  for (let i = 0; i < k; i++) {
    const s = shares[i];
    if (s.byteLength !== shareLength) {
      throw new Error('All shares must have the exact same byte length');
    }
    const x = s[shareLength - 1];
    if (x === 0) {
      throw new Error('Invalid share coordinate (0)');
    }
    if (seen.has(x)) {
      throw new Error('Duplicate share detected');
    }
    seen.add(x);
    xSamples[i] = x;
  }

  // Precompute Lagrange basis weight L_i(0) for each share i (only depends on xSamples!)
  const basisWeights = new Uint8Array(k);
  for (let i = 0; i < k; i++) {
    let basis = 1;
    const xi = xSamples[i];
    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      const xj = xSamples[j];
      const num = xj; // 0 ^ xj
      const denom = xi ^ xj;
      const term = gfDiv(num, denom);
      basis = MULT_TABLE[(basis << 8) | term];
    }
    basisWeights[i] = basis;
  }

  const secretLength = shareLength - 1;
  const secret = new Uint8Array(secretLength);
  let deadline = performance.now() + 50;
  const CHUNK_BYTES = 65536;

  for (let chunkStart = 0; chunkStart < secretLength; chunkStart += CHUNK_BYTES) {
    const chunkEnd = Math.min(secretLength, chunkStart + CHUNK_BYTES);

    for (let j = 0; j < k; j++) {
      const weight = basisWeights[j];
      if (weight === 0) continue;
      const weightRow = weight << 8;
      const shareBytes = shares[j];

      if (weight === 1) {
        for (let idx = chunkStart; idx < chunkEnd; idx++) {
          secret[idx] ^= shareBytes[idx];
        }
      } else {
        for (let idx = chunkStart; idx < chunkEnd; idx++) {
          secret[idx] ^= MULT_TABLE[weightRow | shareBytes[idx]];
        }
      }
    }

    if (performance.now() >= deadline) {
      if (onProgress) {
        onProgress(Math.min(99, Math.round((chunkEnd / secretLength) * 100)));
      }
      await yieldToMain();
      deadline = performance.now() + 50;
    }
  }

  if (onProgress) onProgress(100);
  return secret;
}
