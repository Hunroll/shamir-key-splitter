import { TestBed } from '@angular/core/testing';
import { AppComponent } from './app.component';
import { fastSplit, fastCombine } from './shamir-fast';
import { split as referenceSplit, combine as referenceCombine } from 'shamir-secret-sharing';

describe('AppComponent & Shamir Cryptographic Engine', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AppComponent],
    }).compileComponents();
  });

  // 1. Component initialization & UI rendering
  it('should create the app with default threshold parameters (n = 5, m = 3)', () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
    expect(app.title).toEqual('Shamir Secret Sharing');
    expect(app.n).toBe(5);
    expect(app.m).toBe(3);
  });

  it('should render the main application title in the header', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain("Shamir's Distributed Key Splitter");
  });

  // 2. UTF-8 and RFC 4648 Base64 round-trip verification
  it('should perform exact UTF-8 and Base64 round trips across ASCII, Cyrillic, and emoji strings', async () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;

    const testPayloads = [
      'A',
      'Super secret payload that should be securely splitted.',
      'Секретний ключ відновлення системи 2026 — 🔐🛡️🚀',
    ];

    for (const payload of testPayloads) {
      app.secret = payload;
      app.n = 5;
      app.m = 3;
      await app.splitSecret();

      expect(app.splitError).toBeNull();
      expect(app.sharesList.length).toBe(5);

      // Select 3 distinct shares (indices 0, 2, 4)
      app.sharesInput = [
        `${app.sharesList[0].id}: ${app.sharesList[0].value}`,
        `${app.sharesList[2].id}: ${app.sharesList[2].value}`,
        `${app.sharesList[4].id}: ${app.sharesList[4].value}`,
      ].join('\n');

      await app.recoverSecret();
      expect(app.recoverError).toBeNull();
      expect(app.recoveredSecret).toBe(payload);
    }
  });

  // 3. Finite-field GF(2^8) boundary tests: (m=2, n=2), (m=3, n=5), and (m=128, n=255)
  it('should support minimum threshold boundary (n = 2, m = 2) with a 1-byte secret', async () => {
    const secretBytes = new TextEncoder().encode('A');
    const shares = await fastSplit(secretBytes, 2, 2);
    expect(shares.length).toBe(2);
    expect(shares[0].byteLength).toBe(2);

    const recovered = await fastCombine([shares[0], shares[1]]);
    expect(new TextDecoder().decode(recovered)).toBe('A');
  });

  it('should reconstruct accurately with any m shares and fail to reveal secret with m - 1 shares (n = 5, m = 3)', async () => {
    const secretText = 'Enterprise root CA recovery passphrase with 74 bytes of high-entropy data!';
    const secretBytes = new TextEncoder().encode(secretText);
    const shares = await fastSplit(secretBytes, 5, 3);

    // Any 3-share subset recovers the exact secret
    const subsetA = await fastCombine([shares[0], shares[1], shares[2]]);
    const subsetB = await fastCombine([shares[1], shares[3], shares[4]]);
    expect(new TextDecoder().decode(subsetA)).toBe(secretText);
    expect(new TextDecoder().decode(subsetB)).toBe(secretText);

    // A 2-share subset (k < m) interpolates a different polynomial and does not match the secret
    const insufficient = await fastCombine([shares[0], shares[1]]);
    expect(new TextDecoder().decode(insufficient)).not.toBe(secretText);
  });

  it('should support maximum GF(2^8) finite-field limit (n = 255, m = 128) without abscissa collisions', async () => {
    const secretBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) secretBytes[i] = (i * 7 + 13) & 0xff;

    const shares = await fastSplit(secretBytes, 255, 128);
    expect(shares.length).toBe(255);

    // Verify all 255 non-zero GF(2^8) abscissas {1..255} are distinct
    const xCoords = new Set<number>();
    for (const s of shares) {
      const x = s[s.byteLength - 1];
      expect(x).toBeGreaterThanOrEqual(1);
      expect(x).toBeLessThanOrEqual(255);
      xCoords.add(x);
    }
    expect(xCoords.size).toBe(255);

    const recovered = await fastCombine(shares.slice(0, 128));
    expect(recovered).toEqual(secretBytes);
  });

  it('should reject out-of-range (m, n) threshold parameters', async () => {
    const secretBytes = new TextEncoder().encode('test');
    await expectAsync(fastSplit(secretBytes, 1, 1)).toBeRejectedWithError(RangeError);
    await expectAsync(fastSplit(secretBytes, 256, 3)).toBeRejectedWithError(RangeError);
    await expectAsync(fastSplit(secretBytes, 3, 4)).toBeRejectedWithError(/cannot be less than threshold/);
  });

  // 4. Bidirectional binary compatibility with Cure53-audited shamir-secret-sharing (v0.0.4)
  it('should maintain 100% bidirectional share compatibility with shamir-secret-sharing', async () => {
    const secretText = 'Cross-library GF(256) compatibility verification vector (0x11B, gen 0xE5)';
    const secretBytes = new TextEncoder().encode(secretText);

    // Forward: fastSplit -> shamir-secret-sharing combine()
    const ourShares = await fastSplit(secretBytes, 5, 3);
    const recoveredByReference = await referenceCombine([ourShares[0], ourShares[2], ourShares[4]]);
    expect(new TextDecoder().decode(recoveredByReference)).toBe(secretText);

    // Backward: shamir-secret-sharing split() -> fastCombine
    const refShares = await referenceSplit(secretBytes, 5, 3);
    const recoveredByFast = await fastCombine([refShares[1], refShares[2], refShares[3]]);
    expect(new TextDecoder().decode(recoveredByFast)).toBe(secretText);
  });

  // 5. 10-Stage Share Validation Fault-Injection Matrix (Table 4.1) & Buffer Zeroing on Error
  describe('10-Stage Share Validator Fault-Injection Matrix (Table 4.1)', () => {
    let app: AppComponent;

    beforeEach(() => {
      const fixture = TestBed.createComponent(AppComponent);
      app = fixture.componentInstance;
    });

    it('Stage 1: detects out-of-range share prefix IDs (0 and 256)', () => {
      app.sharesInput = '0: CkkIUBv96/t6Xg==\n256: CkkIUBv96/t6Xg==';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[0].status).toBe('error');
      expect(app.shareValidations[0].message).toContain('Invalid share prefix "0"');
      expect(app.shareValidations[1].message).toContain('Invalid share prefix "256"');
    });

    it('Stage 2: detects duplicate Share prefix IDs', () => {
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n1: CkkIUBv96/t6Xg==';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].status).toBe('error');
      expect(app.shareValidations[1].message).toContain('Duplicate Share ID #1');
    });

    it('Stage 3: detects missing Base64 payload after colon', () => {
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2:';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].message).toContain('Missing Base64 share payload after ":"');
    });

    it('Stage 4: detects internal whitespace inside Base64 payload', () => {
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2: CkkI UBv96/t6Xg==';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].message).toContain('Share contains spaces or invisible whitespace.');
    });

    it('Stage 5: detects URL-safe Base64 characters ("-" or "_")', () => {
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2: CkkI-Bv96_t6Xg==';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].message).toContain('Contains URL-safe Base64 characters');
    });

    it('Stage 6: detects non-RFC 4648 characters ("$")', () => {
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2: CkkI$Bv96/t6Xg==';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].message).toContain('Invalid character "$" in Base64 payload.');
    });

    it('Stage 7: detects non-modulo-4 truncated Base64 share strings', () => {
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2: CkkIUBv96/t6Xg=';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].message).toContain('Truncated share string (length 15 is not a multiple of 4).');
    });

    it('Stage 8: detects misplaced "=" padding characters', () => {
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2: Ckk=UBv96/t6Xg==';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].message).toContain('Misplaced "=" padding character.');
    });

    it('Stage 9: detects shares shorter than 2 bytes (AQ==) and zero GF(256) coordinates (AAAA)', () => {
      app.sharesInput = '1: AQ==\n2: AAAA';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[0].message).toContain('Share is too short (1 byte).');
      expect(app.shareValidations[1].message).toContain('Invalid Galois Field coordinate (0x00)');
    });

    it('Stage 10: detects duplicate trailing X-coordinates and cross-share byte-length mismatches', () => {
      // Duplicate X-coordinate with different prefix IDs
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2: CkkIUBv96/t6Xg==';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].message).toContain('Identical cryptographic share to Line 1 (duplicate X-coordinate).');

      // Byte-length mismatch
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2: CkkIUBv96/t6Xl8xAA==';
      app.validateSharesInput(false);
      expect(app.hasValidationErrors).toBeTrue();
      expect(app.shareValidations[1].message).toContain('Byte length mismatch');
    });

    it('Quorum check & buffer zeroization on error: warns on single share and zeroes decoded buffers when validation fails', () => {
      app.sharesInput = '1: CkkIUBv96/t6Xg==';
      const singleBuffers = app.validateSharesInput(true);
      expect(app.hasValidationErrors).toBeFalse();
      expect(app.validSharesCount).toBe(1);
      expect(app.globalShareAdvice).toContain('At least 2 shares are required');
      expect(singleBuffers[0].every((b) => b === 0)).toBeTrue();

      // Valid Line 1 followed by invalid Line 2 -> Line 1's decoded buffer is immediately zeroed
      app.sharesInput = '1: CkkIUBv96/t6Xg==\n2: AAAA';
      const errBuffers = app.validateSharesInput(true);
      expect(app.hasValidationErrors).toBeTrue();
      expect(errBuffers.length).toBe(1);
      expect(errBuffers[0].every((b) => b === 0)).toBeTrue();
    });
  });

  // 6. Memory sanitization and lifecycle teardown
  it('should sanitize secret state and zeroize buffers on purgeSecretNow() and clearAllData()', async () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;

    app.secret = 'Ephemeral secret to wipe';
    await app.splitSecret();
    expect(app.sharesList.length).toBe(5);

    app.purgeSecretNow();
    expect(app.secret).toBe('');
    expect(app.secretCleanedMessage).toBeTrue();
    expect(app.secretCleanupCountdown).toBeNull();

    app.clearAllData();
    expect(app.sharesList.length).toBe(0);
    expect(app.sharesInput).toBe('');
    expect(app.recoveredSecret).toBeNull();
    expect(app.recoveredSecretBlobUrl).toBeNull();
  });
});
