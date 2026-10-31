import { describe, it, expect } from 'vitest';
import { sanitizeDeep } from '../src/sanitizeDeep.js';

describe('sanitizeDeep', () => {
  it('strips prototype pollution keys (__proto__, constructor, prototype)', () => {
    // Construct an object simulating JSON payload with __proto__ and constructor
    const maliciousPayload = JSON.parse(
      '{"normalKey": "value", "__proto__": {"polluted": true}, "constructor": {"prototype": {"admin": true}}}',
    );

    const sanitized = sanitizeDeep(maliciousPayload) as Record<string, unknown>;

    expect(sanitized.normalKey).toBe('value');
    expect(Object.prototype.hasOwnProperty.call(sanitized, '__proto__')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(sanitized, 'constructor')).toBe(false);
    expect('polluted' in Object.prototype).toBe(false);
    expect('admin' in Object.prototype).toBe(false);
  });

  it('strips nested prototype pollution attacks', () => {
    const nested = {
      user: {
        profile: {
          name: 'Alice',
          __proto__: { isAdmin: true },
        },
      },
    };

    const sanitized = sanitizeDeep(nested) as typeof nested;
    expect(sanitized.user.profile.name).toBe('Alice');
    expect('isAdmin' in sanitized.user.profile).toBe(false);
  });

  it('handles circular references gracefully without stack overflow', () => {
    const parent: Record<string, unknown> = { name: 'parent' };
    const child: Record<string, unknown> = { name: 'child', parent };
    parent.child = child;

    // Default: 'replace'
    const sanitized = sanitizeDeep(parent) as Record<string, unknown>;
    expect(sanitized.name).toBe('parent');
    expect((sanitized.child as Record<string, unknown>).name).toBe('child');
    expect((sanitized.child as Record<string, unknown>).parent).toBe('[Circular]');

    // circularRefHandling: 'omit'
    const sanitizedOmit = sanitizeDeep(parent, { circularRefHandling: 'omit' }) as Record<
      string,
      unknown
    >;
    expect(sanitizedOmit.name).toBe('parent');
    expect((sanitizedOmit.child as Record<string, unknown>).parent).toBeUndefined();
  });

  it('enforces maxDepth and truncates deeply nested structures', () => {
    // Generate an object 15 levels deep
    let current: Record<string, unknown> = { level: 15 };
    for (let i = 14; i >= 1; i--) {
      current = { level: i, nested: current };
    }

    const sanitized = sanitizeDeep(current, { maxDepth: 5 }) as Record<string, unknown>;

    // Navigate down 5 levels
    let node: any = sanitized;
    for (let i = 1; i < 5; i++) {
      expect(node.level).toBe(i);
      node = node.nested;
    }
    // At depth 5, it should be marked as MaxDepthExceeded or truncated
    expect(node.nested).toBe('[MaxDepthExceeded]');
  });

  it('strips control characters while preserving safe whitespace (\\n, \\r, \\t)', () => {
    const dirty = 'Line 1\x00\x07\x1B\x7F\nLine 2\tTabbed\rReturn\u200BInvisible';
    const sanitized = sanitizeDeep(dirty);

    expect(sanitized).toBe('Line 1\nLine 2\tTabbed\rReturnInvisible');
    expect((sanitized as string).includes('\x00')).toBe(false);
    expect((sanitized as string).includes('\x1B')).toBe(false);
    expect((sanitized as string).includes('\u200B')).toBe(false);
  });

  it('truncates oversized strings to maxStringLength', () => {
    const longString = 'A'.repeat(500);
    const sanitized = sanitizeDeep(longString, { maxStringLength: 50 });

    expect(typeof sanitized).toBe('string');
    expect((sanitized as string).length).toBe(50);
    expect(sanitized).toBe('A'.repeat(50));
  });

  it('enforces maxKeys limit on objects', () => {
    const largeObj: Record<string, number> = {};
    for (let i = 0; i < 100; i++) {
      largeObj[`key_${i}`] = i;
    }

    const sanitized = sanitizeDeep(largeObj, { maxKeys: 10 }) as Record<string, number>;
    expect(Object.keys(sanitized).length).toBe(10);
  });

  it('enforces maxArrayLength limit on arrays', () => {
    const largeArr = Array.from({ length: 50 }, (_, i) => i);
    const sanitized = sanitizeDeep(largeArr, { maxArrayLength: 15 }) as number[];

    expect(sanitized.length).toBe(15);
    expect(sanitized[0]).toBe(0);
    expect(sanitized[14]).toBe(14);
  });

  it('handles primitives, null, and undefined correctly', () => {
    expect(sanitizeDeep(null)).toBe(null);
    expect(sanitizeDeep(undefined)).toBe(undefined);
    expect(sanitizeDeep(42)).toBe(42);
    expect(sanitizeDeep(true)).toBe(true);
    expect(sanitizeDeep(BigInt(100))).toBe('100');
    expect(sanitizeDeep(() => 'func')).toBe(undefined);
  });
});
