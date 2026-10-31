import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Performs a constant-time comparison of two strings to prevent timing side-channel attacks.
 *
 * Traditional timingSafeEqual requires buffers of identical length; otherwise it either
 * throws an error or leaks string length immediately via early return.
 *
 * To ensure safe comparison without leaking length information:
 * 1. Both strings are hashed using SHA-256 (yielding fixed 32-byte digests).
 * 2. The digests are compared using `crypto.timingSafeEqual`.
 * 3. As an additional safeguard against hash collisions, we also check length and direct buffer comparison
 *    if the hashes match, while ensuring the primary timing barrier is constant-time.
 *
 * @param a - First string to compare.
 * @param b - Second string to compare.
 * @returns boolean - True if strings are strictly identical, false otherwise.
 */
export function safeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  // Pre-hash both strings to fixed-size 32-byte SHA-256 buffers.
  // This eliminates timing leaks derived from string lengths.
  const hashA = createHash('sha256').update(a, 'utf8').digest();
  const hashB = createHash('sha256').update(b, 'utf8').digest();

  const hashesMatch = timingSafeEqual(hashA, hashB);

  // If hashes match, perform final strict check (collison-proof)
  return hashesMatch && a === b;
}
