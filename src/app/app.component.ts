import { ChangeDetectorRef, Component, ElementRef, HostListener, inject, OnDestroy, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import * as QRCode from 'qrcode';
import { fastSplit, fastCombine } from './shamir-fast';

// Maximum characters that can fit inside a standard QR Code (Version 40, Error Correction M)
const MAX_QR_PAYLOAD_LENGTH = 2300;
// Above 4 KB Base64, don't inline-render the entire string in the DOM to prevent layout freezes
const MAX_INLINE_PREVIEW_CHARS = 2048;

interface ShareItem {
  id: string;
  value: string;
  previewValue: string;
  isLarge: boolean;
  byteLength: number;
  canGenerateQr: boolean;
  qrBlobUrl?: string;
  qrError?: string;
  showQr?: boolean;
}

export interface ShareValidationItem {
  lineNumber: number;
  rawLine: string;
  displayLabel: string;
  status: 'valid' | 'error' | 'warning';
  message: string;
  advice?: string;
  byteLength?: number;
  xCoord?: number;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnDestroy {
  title = 'Shamir Secret Sharing';
  private cdr = inject(ChangeDetectorRef);

  @ViewChild('secretInput') secretInputRef?: ElementRef<HTMLTextAreaElement>;
  @ViewChild('sharesInputRef') sharesInputElementRef?: ElementRef<HTMLTextAreaElement>;
  @ViewChild('secretFileInput') secretFileInputRef?: ElementRef<HTMLInputElement>;
  @ViewChild('shareFilesInput') shareFilesInputRef?: ElementRef<HTMLInputElement>;

  // Split state
  secret: string = '';
  loadedSecretFileName: string | null = null;
  loadedSecretFileBytes: Uint8Array | null = null;
  n: number = 5;
  m: number = 3;
  sharesList: ShareItem[] = [];
  splitError: string | null = null;
  copiedId: string | null = null;
  isSplitting: boolean = false;
  splitProgress: number = 0;

  // Secret auto-wipe countdown (5 seconds)
  secretCleanupCountdown: number | null = null;
  secretCleanedMessage: boolean = false;
  private secretCleanupInterval: any = null;
  private activeSecretBuffer: Uint8Array | null = null;

  // Recover & validation state
  sharesInput: string = '';
  loadedShareFiles: { name: string; content: string }[] = [];
  sharesTouched: boolean = false;
  shareValidations: ShareValidationItem[] = [];
  validSharesCount: number = 0;
  hasValidationErrors: boolean = false;
  globalShareAdvice: string | null = null;
  recoveredSecret: string | null = null;
  recoveredSecretPreview: string | null = null;
  recoveredSecretBytesLength: number = 0;
  recoveredSecretBlobUrl: string | null = null;
  isRecoveredLarge: boolean = false;
  recoverError: string | null = null;
  isRecovering: boolean = false;
  recoverProgress: number = 0;
  private validationDebounceTimer: any = null;

  // Helper conversions
  private toUint8Array(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  private fromUint8Array(arr: Uint8Array): string {
    return new TextDecoder().decode(arr);
  }

  // Fast chunked Uint8Array -> Base64 conversion without O(N^2) string concatenation
  private uint8ArrayToBase64(bytes: Uint8Array): string {
    const CHUNK_SIZE = 0x8000; // 32KB per apply call
    const chunks: string[] = [];
    for (let i = 0; i < bytes.byteLength; i += CHUNK_SIZE) {
      const sub = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.byteLength));
      chunks.push(String.fromCharCode.apply(null, sub as unknown as number[]));
    }
    return window.btoa(chunks.join(''));
  }

  private base64ToUint8Array(base64: string): Uint8Array {
    const binary = window.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  async onSecretFileSelected(event: Event) {
    const input = event.target as HTMLInputElement;
    if (!input.files || input.files.length === 0) return;

    const file = input.files[0];
    const buffer = await file.arrayBuffer();
    this.loadedSecretFileBytes = new Uint8Array(buffer);
    this.loadedSecretFileName = `${file.name} (${this.formatBytes(file.size)})`;
    this.secretCleanedMessage = false;
    this.splitError = null;
    this.cdr.detectChanges();
  }

  clearLoadedSecretFile() {
    if (this.loadedSecretFileBytes) {
      this.loadedSecretFileBytes.fill(0);
      this.loadedSecretFileBytes = null;
    }
    this.loadedSecretFileName = null;
    if (this.secretFileInputRef?.nativeElement) {
      this.secretFileInputRef.nativeElement.value = '';
    }
  }

  private async generateQrBlobUrl(payload: string): Promise<string> {
    const canvas = document.createElement('canvas');
    await QRCode.toCanvas(canvas, payload, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 200
    });

    const blob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob((b) => resolve(b), 'image/png')
    );

    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
    canvas.width = 0;
    canvas.height = 0;

    if (!blob) {
      throw new Error('Failed to generate QR blob');
    }
    return URL.createObjectURL(blob);
  }

  async splitSecret() {
    this.splitError = null;
    this.secretCleanedMessage = false;
    this.revokeAllQrCodes();
    this.sharesList = [];

    const hasFile = this.loadedSecretFileBytes && this.loadedSecretFileBytes.byteLength > 0;
    if (!hasFile && !this.secret) {
      this.splitError = 'Secret cannot be empty. Enter text or load a file.';
      return;
    }

    if (this.n <= 1 || this.m <= 1 || this.m > this.n || this.n > 255) {
      this.splitError = 'Invalid n or m parameters. Ensure 2 <= m <= n <= 255.';
      return;
    }

    this.isSplitting = true;
    this.splitProgress = 0;

    try {
      const secretBytes = hasFile
        ? new Uint8Array(this.loadedSecretFileBytes!)
        : this.toUint8Array(this.secret);
      this.activeSecretBuffer = secretBytes;

      const rawShares = await fastSplit(secretBytes, this.n, this.m, (pct) => {
        this.splitProgress = pct;
        this.cdr.detectChanges();
      });

      const items: ShareItem[] = [];
      for (let i = 0; i < rawShares.length; i++) {
        const id = (i + 1).toString();
        const byteLength = rawShares[i].byteLength;
        const value = this.uint8ArrayToBase64(rawShares[i]);
        rawShares[i].fill(0);

        const sharePayloadLength = id.length + 2 + value.length;
        const isLarge = value.length > MAX_INLINE_PREVIEW_CHARS;
        const previewValue = isLarge
          ? `${value.slice(0, 120)} ... [${this.formatBytes(byteLength)} total] ... ${value.slice(-80)}`
          : value;

        // Lazy QR code: do NOT generate upfront! Only generate when the user clicks "QR Code".
        items.push({
          id,
          value,
          previewValue,
          isLarge,
          byteLength,
          canGenerateQr: sharePayloadLength <= MAX_QR_PAYLOAD_LENGTH,
          showQr: false
        });
      }

      this.sharesList = items;
      this.startSecretCleanupTimer();
      this.cdr.detectChanges();
    } catch (e: any) {
      this.splitError = e.message || 'An error occurred during split';
    } finally {
      this.isSplitting = false;
      this.cdr.detectChanges();
    }
  }

  private startSecretCleanupTimer() {
    this.clearSecretTimerOnly();
    this.secretCleanupCountdown = 5;
    this.cdr.detectChanges();

    this.secretCleanupInterval = window.setInterval(() => {
      if (this.secretCleanupCountdown !== null && this.secretCleanupCountdown > 1) {
        this.secretCleanupCountdown--;
        this.cdr.detectChanges();
      } else {
        this.purgeSecretNow();
      }
    }, 1000);
  }

  private clearSecretTimerOnly() {
    if (this.secretCleanupInterval) {
      clearInterval(this.secretCleanupInterval);
      this.secretCleanupInterval = null;
    }
    this.secretCleanupCountdown = null;
  }

  purgeSecretNow() {
    this.clearSecretTimerOnly();

    if (this.activeSecretBuffer) {
      this.activeSecretBuffer.fill(0);
      this.activeSecretBuffer = null;
    }

    this.clearLoadedSecretFile();
    this.secret = '';

    if (this.secretInputRef?.nativeElement) {
      const el = this.secretInputRef.nativeElement;
      el.value = '';
      el.defaultValue = '';
      el.blur();
    }

    try {
      sessionStorage.clear();
      if ('caches' in window) {
        caches.keys().then((names) => names.forEach((name) => caches.delete(name)));
      }
    } catch {
      // Ignore storage access errors
    }

    this.secretCleanedMessage = true;
    this.cdr.detectChanges();
  }

  onSecretInputChange() {
    if (this.secret && this.secretCleanedMessage) {
      this.secretCleanedMessage = false;
    }
  }

  // On-demand QR generation only when requested by the user
  async toggleQr(item: ShareItem) {
    if (item.showQr) {
      item.showQr = false;
      return;
    }

    item.qrError = undefined;
    if (!item.canGenerateQr) {
      item.qrError = `Share is too large (${this.formatBytes(item.byteLength)}) to fit in a QR code (max ~1.7 KB). Please use "Download .share" or "Copy" instead.`;
      return;
    }

    if (!item.qrBlobUrl) {
      try {
        const sharePayload = `${item.id}: ${item.value}`;
        item.qrBlobUrl = await this.generateQrBlobUrl(sharePayload);
      } catch (e: any) {
        item.qrError = e.message || 'The amount of data is too big to be stored in a QR Code.';
        this.cdr.detectChanges();
        return;
      }
    }
    item.showQr = true;
    this.cdr.detectChanges();
  }

  downloadShareFile(item: ShareItem) {
    const content = `${item.id}: ${item.value}\n`;
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `share-${item.id}-of-${this.n}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  downloadAllSharesFile() {
    const lines = this.sharesList.map((item) => `${item.id}: ${item.value}`).join('\n');
    const blob = new Blob([lines], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `all-shares-${this.m}-of-${this.n}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  revokeAllQrCodes() {
    for (const item of this.sharesList) {
      if (item.qrBlobUrl) {
        URL.revokeObjectURL(item.qrBlobUrl);
        item.qrBlobUrl = undefined;
      }
      item.showQr = false;
      item.qrError = undefined;
    }
  }

  revokeRecoveredBlob() {
    if (this.recoveredSecretBlobUrl) {
      URL.revokeObjectURL(this.recoveredSecretBlobUrl);
      this.recoveredSecretBlobUrl = null;
    }
  }

  clearAllData() {
    this.purgeSecretNow();
    this.revokeAllQrCodes();
    this.revokeRecoveredBlob();
    this.sharesList = [];
    this.sharesInput = '';
    this.loadedShareFiles = [];
    this.sharesTouched = false;
    this.shareValidations = [];
    this.validSharesCount = 0;
    this.hasValidationErrors = false;
    this.globalShareAdvice = null;
    this.recoveredSecret = null;
    this.recoveredSecretPreview = null;
    this.recoveredSecretBytesLength = 0;
    this.isRecoveredLarge = false;
    this.splitError = null;
    this.recoverError = null;

    if (this.sharesInputElementRef?.nativeElement) {
      const el = this.sharesInputElementRef.nativeElement;
      el.value = '';
      el.setCustomValidity('');
      el.removeAttribute('aria-invalid');
    }
    if (this.shareFilesInputRef?.nativeElement) {
      this.shareFilesInputRef.nativeElement.value = '';
    }
  }

  @HostListener('window:pagehide')
  @HostListener('window:beforeunload')
  onPageUnload() {
    this.clearAllData();
  }

  ngOnDestroy() {
    this.clearAllData();
  }

  async copyShare(item: ShareItem) {
    const text = `${item.id}: ${item.value}`;
    await navigator.clipboard.writeText(text);
    this.copiedId = item.id;
    this.cdr.detectChanges();
    setTimeout(() => {
      if (this.copiedId === item.id) {
        this.copiedId = null;
        this.cdr.detectChanges();
      }
    }, 2000);
  }

  async onShareFilesSelected(event: Event) {
    const input = event.target as HTMLInputElement;
    if (!input.files || input.files.length === 0) return;

    for (let i = 0; i < input.files.length; i++) {
      const file = input.files[i];
      const text = await file.text();
      const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
      for (const line of lines) {
        this.loadedShareFiles.push({
          name: file.name,
          content: line.trim()
        });
      }
    }
    input.value = '';
    this.sharesTouched = true;
    this.validateSharesInput(false);
    this.cdr.detectChanges();
  }

  removeLoadedShareFile(index: number) {
    this.loadedShareFiles.splice(index, 1);
    this.validateSharesInput(false);
  }

  onSharesInputBlur() {
    if (this.sharesInput.trim().length > 0 || this.loadedShareFiles.length > 0) {
      this.sharesTouched = true;
    }
    this.validateSharesInput(false);
  }

  onSharesInputChange() {
    this.recoverError = null;
    if (this.validationDebounceTimer) {
      clearTimeout(this.validationDebounceTimer);
    }
    // Debounce live validation when pasting large multi-megabyte strings
    const delay = this.sharesInput.length > 50000 ? 250 : 0;
    if (delay === 0) {
      this.validateSharesInput(false);
    } else {
      this.validationDebounceTimer = setTimeout(() => {
        this.validateSharesInput(false);
        this.cdr.detectChanges();
      }, delay);
    }
  }

  // Fast validation that avoids full `atob` on multi-megabyte lines unless `decodeBytes` is true
  validateSharesInput(decodeBytes: boolean = false): Uint8Array[] {
    const textLines = this.sharesInput
      .split(/\r?\n/)
      .map((l, idx) => ({ raw: l, sourceLabel: `Line ${idx + 1}` }))
      .filter((item) => item.raw.trim().length > 0);

    const fileLines = this.loadedShareFiles.map((f, idx) => ({
      raw: f.content,
      sourceLabel: `File ${f.name} (#${idx + 1})`
    }));

    const allEntries = [...fileLines, ...textLines];
    const results: ShareValidationItem[] = [];
    const validDecodedShares: Uint8Array[] = [];

    const seenIds = new Map<number, string>();
    const seenXCoords = new Map<number, string>();
    let expectedByteLength: number | null = null;
    let referenceSourceForLength: string | null = null;

    for (let idx = 0; idx < allEntries.length; idx++) {
      const entry = allEntries[idx];
      const trimmed = entry.raw.trim();
      const lineNumber = idx + 1;
      let base64Part = trimmed;
      let displayLabel = entry.sourceLabel;

      if (trimmed.includes(':')) {
        const colonIdx = trimmed.indexOf(':');
        const prefix = trimmed.slice(0, colonIdx).trim();
        base64Part = trimmed.slice(colonIdx + 1).trim();

        const idNum = Number(prefix);
        if (!prefix || !Number.isInteger(idNum) || idNum < 1 || idNum > 255) {
          results.push({
            lineNumber,
            rawLine: trimmed.slice(0, 80),
            displayLabel,
            status: 'error',
            message: `Invalid share prefix "${prefix.slice(0, 15) || '(empty)'}".`,
            advice: 'Share ID before ":" must be a whole number between 1 and 255 (e.g., "1: K9f2..."), or omit the prefix entirely.'
          });
          continue;
        }

        displayLabel = `Share #${idNum} (${entry.sourceLabel})`;

        if (seenIds.has(idNum)) {
          const prevSource = seenIds.get(idNum)!;
          results.push({
            lineNumber,
            rawLine: trimmed.slice(0, 80),
            displayLabel,
            status: 'error',
            message: `Duplicate Share ID #${idNum} (already entered in ${prevSource}).`,
            advice: 'Each share in the quorum must come from a distinct split chunk. Remove the duplicate.'
          });
          continue;
        }
        seenIds.set(idNum, entry.sourceLabel);
      }

      if (!base64Part) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: 'Missing Base64 share payload after ":".',
          advice: 'Paste the full Base64 string that follows the share number.'
        });
        continue;
      }

      if (/\s/.test(base64Part)) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: 'Share contains spaces or invisible whitespace.',
          advice: 'Remove any spaces or accidental line wraps inside the Base64 string.'
        });
        continue;
      }

      if (/[-_]/.test(base64Part)) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: 'Contains URL-safe Base64 characters ("-" or "_").',
          advice: 'Standard Base64 uses "+" and "/" instead of "-" and "_".'
        });
        continue;
      }

      const invalidCharMatch = base64Part.match(/[^A-Za-z0-9+/=]/);
      if (invalidCharMatch) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: `Invalid character "${invalidCharMatch[0]}" in Base64 payload.`,
          advice: 'Shares only contain letters (A–Z, a–z), digits (0–9), "+", "/", and optional "=" padding at the end.'
        });
        continue;
      }

      if (base64Part.length % 4 !== 0) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: `Truncated share string (length ${base64Part.length} is not a multiple of 4).`,
          advice: 'You may have missed the trailing "=" padding or cut off a character when copying.'
        });
        continue;
      }

      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64Part)) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: 'Misplaced "=" padding character.',
          advice: 'The "=" padding can only appear at the very end of the share (up to two "=" characters).'
        });
        continue;
      }

      // Compute exact decoded byte length from Base64 length & padding without decoding megabytes
      const padCount = base64Part.endsWith('==') ? 2 : base64Part.endsWith('=') ? 1 : 0;
      const computedByteLength = (base64Part.length * 3) / 4 - padCount;

      if (computedByteLength < 2) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: `Share is too short (${computedByteLength} byte).`,
          advice: 'A valid Shamir share must contain at least 2 bytes (the secret payload plus 1 coordinate byte).'
        });
        continue;
      }

      // Decode the last 4 Base64 characters to inspect the X-coordinate byte in O(1) time!
      let xCoord = 0;
      let tailBytes: Uint8Array | null = null;
      try {
        const tailQuad = base64Part.slice(-4);
        tailBytes = this.base64ToUint8Array(tailQuad);
        xCoord = tailBytes[tailBytes.byteLength - 1];
      } catch {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: 'Malformed Base64 encoding.',
          advice: 'Verify the copied share against the original output.'
        });
        continue;
      } finally {
        if (tailBytes) {
          tailBytes.fill(0);
        }
      }

      if (xCoord === 0) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: 'Invalid Galois Field coordinate (0x00) at end of share.',
          advice: 'This string is not a valid Shamir share generated by this tool.'
        });
        continue;
      }

      if (seenXCoords.has(xCoord)) {
        const prevSource = seenXCoords.get(xCoord)!;
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: `Identical cryptographic share to ${prevSource} (duplicate X-coordinate).`,
          advice: 'Even if the prefix number was changed, the underlying share data is a duplicate. Provide a different share.'
        });
        continue;
      }
      seenXCoords.set(xCoord, entry.sourceLabel);

      if (expectedByteLength === null) {
        expectedByteLength = computedByteLength;
        referenceSourceForLength = entry.sourceLabel;
      } else if (computedByteLength !== expectedByteLength) {
        results.push({
          lineNumber,
          rawLine: trimmed.slice(0, 80),
          displayLabel,
          status: 'error',
          message: `Byte length mismatch (${this.formatBytes(computedByteLength)} vs ${this.formatBytes(expectedByteLength)} in ${referenceSourceForLength}).`,
          advice: 'All shares for the same secret must have the exact same length. Ensure you did not mix shares from different secrets.'
        });
        continue;
      }

      if (decodeBytes) {
        validDecodedShares.push(this.base64ToUint8Array(base64Part));
      }

      results.push({
        lineNumber,
        rawLine: trimmed.slice(0, 80),
        displayLabel,
        status: 'valid',
        message: `Valid share (${this.formatBytes(computedByteLength - 1)} secret payload)`,
        byteLength: computedByteLength,
        xCoord
      });
    }

    this.shareValidations = results;
    this.validSharesCount = results.filter((r) => r.status === 'valid').length;
    this.hasValidationErrors = results.some((r) => r.status === 'error');

    if (results.length === 1 && !this.hasValidationErrors) {
      this.globalShareAdvice = 'At least 2 shares are required to reconstruct a secret. Add another share line or file.';
    } else if (this.hasValidationErrors) {
      const errCount = results.filter((r) => r.status === 'error').length;
      this.globalShareAdvice = `Please fix ${errCount} invalid share entry${errCount > 1 ? 's' : ''} highlighted below before reconstructing.`;
    } else {
      this.globalShareAdvice = null;
    }

    if (decodeBytes && (this.hasValidationErrors || validDecodedShares.length < 2)) {
      validDecodedShares.forEach((s) => s.fill(0));
    }

    this.syncTextareaValidity();
    return validDecodedShares;
  }

  private syncTextareaValidity() {
    const el = this.sharesInputElementRef?.nativeElement;
    if (!el) return;

    const hasBadState =
      this.hasValidationErrors ||
      (this.shareValidations.length === 1 && this.validSharesCount < 2);

    if (this.sharesInput.trim().length === 0 && this.loadedShareFiles.length === 0) {
      el.setCustomValidity('');
      el.removeAttribute('aria-invalid');
      return;
    }

    if (hasBadState) {
      el.setCustomValidity(this.globalShareAdvice || 'Invalid share format');
    } else {
      el.setCustomValidity('');
    }

    const matchesUserInvalid =
      (typeof CSS !== 'undefined' &&
        CSS.supports('selector(:user-invalid)') &&
        el.matches(':user-invalid')) ||
      (this.sharesTouched && hasBadState);

    if (matchesUserInvalid) {
      el.setAttribute('aria-invalid', 'true');
    } else {
      el.removeAttribute('aria-invalid');
    }
  }

  async recoverSecret() {
    this.sharesTouched = true;
    this.recoverError = null;
    this.recoveredSecret = null;
    this.recoveredSecretPreview = null;
    this.revokeRecoveredBlob();

    const shares = this.validateSharesInput(true);

    if (this.shareValidations.length === 0) {
      this.recoverError = 'Please paste or upload at least 2 shares to reconstruct your secret.';
      this.syncTextareaValidity();
      return;
    }

    if (this.hasValidationErrors) {
      shares.forEach((s) => s.fill(0));
      this.recoverError = 'Cannot reconstruct: one or more share entries have format errors. Check the advice below.';
      this.syncTextareaValidity();
      return;
    }

    if (shares.length < 2) {
      shares.forEach((s) => s.fill(0));
      this.recoverError = 'Shamir reconstruction requires at least 2 distinct shares.';
      this.syncTextareaValidity();
      return;
    }

    this.isRecovering = true;
    this.recoverProgress = 0;

    try {
      const recoveredBytes = await fastCombine(shares, (pct) => {
        this.recoverProgress = pct;
        this.cdr.detectChanges();
      });
      this.recoveredSecretBytesLength = recoveredBytes.byteLength;

      // Create downloadable blob for large or binary secrets
      const blob = new Blob([recoveredBytes as Uint8Array<ArrayBuffer>], { type: 'application/octet-stream' });
      this.recoveredSecretBlobUrl = URL.createObjectURL(blob);

      const textDecoded = this.fromUint8Array(recoveredBytes);
      this.isRecoveredLarge = textDecoded.length > MAX_INLINE_PREVIEW_CHARS;
      this.recoveredSecret = textDecoded;
      this.recoveredSecretPreview = this.isRecoveredLarge
        ? `${textDecoded.slice(0, 400)}\n... [${this.formatBytes(this.recoveredSecretBytesLength)} total — use Download or Copy to get full secret] ...\n${textDecoded.slice(-200)}`
        : textDecoded;

      recoveredBytes.fill(0);
      shares.forEach((s) => s.fill(0));
      this.cdr.detectChanges();
    } catch (e: any) {
      shares.forEach((s) => s.fill(0));
      this.recoverError = 'Failed to recover secret: ' + (e.message || 'Invalid shares provided');
      this.cdr.detectChanges();
    } finally {
      this.isRecovering = false;
      this.cdr.detectChanges();
    }
  }

  downloadRecoveredSecret() {
    if (!this.recoveredSecretBlobUrl) return;
    const a = document.createElement('a');
    a.href = this.recoveredSecretBlobUrl;
    a.download = 'recovered-secret.txt';
    a.click();
  }

  async copyRecoveredSecret() {
    if (!this.recoveredSecret) return;
    await navigator.clipboard.writeText(this.recoveredSecret);
  }
}
