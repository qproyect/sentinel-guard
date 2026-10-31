import { describe, it, expect } from 'vitest';
import { safeEqual } from '../src/safeEqual.js';

describe('safeEqual', () => {
  it('returns true for identical strings', () => {
    expect(safeEqual('super-secret-token', 'super-secret-token')).toBe(true);
    expect(safeEqual('', '')).toBe(true);
    expect(safeEqual('abc', 'abc')).toBe(true);
  });

  it('returns false for different strings of same length', () => {
    expect(safeEqual('password1', 'password2')).toBe(false);
    expect(safeEqual('aaaa', 'bbbb')).toBe(false);
  });

  it('returns false for strings of different lengths', () => {
    expect(safeEqual('short', 'much_longer_string')).toBe(false);
    expect(safeEqual('', 'a')).toBe(false);
    expect(safeEqual('admin', 'admin1')).toBe(false);
  });

  it('handles multi-byte unicode strings properly', () => {
    expect(safeEqual('café', 'café')).toBe(true);
    expect(safeEqual('café', 'cafe')).toBe(false);
    expect(safeEqual('🔒key🔑', '🔒key🔑')).toBe(true);
    expect(safeEqual('🔒key🔑', '🔒key🔓')).toBe(false);
  });

  it('safely rejects non-string inputs', () => {
    // @ts-expect-error test non-string runtime values
    expect(safeEqual(null, 'secret')).toBe(false);
    // @ts-expect-error test non-string runtime values
    expect(safeEqual('secret', undefined)).toBe(false);
    // @ts-expect-error test non-string runtime values
    expect(safeEqual(12345, 12345)).toBe(false);
  });
});
