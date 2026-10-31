export interface SanitizeDeepOptions {
  /**
   * Maximum recursion depth. Exceeding depth drops nested structures or returns fallback.
   * Default: 10
   */
  maxDepth?: number;

  /**
   * Maximum length allowed for any string leaf value.
   * Strings exceeding this length will be truncated.
   * Default: 10_000
   */
  maxStringLength?: number;

  /**
   * Maximum number of keys allowed on an object.
   * Keys beyond this limit are omitted.
   * Default: 500
   */
  maxKeys?: number;

  /**
   * Maximum number of elements allowed in an array.
   * Elements beyond this limit are truncated.
   * Default: 1_000
   */
  maxArrayLength?: number;

  /**
   * Strip ASCII control characters from strings (0x00-0x1F, 0x7F) except standard whitespace (\t, \n, \r).
   * Default: true
   */
  stripControlChars?: boolean;

  /**
   * Keys to omit entirely to avoid prototype pollution or unsafe access.
   * Default: ['__proto__', 'constructor', 'prototype']
   */
  disallowedKeys?: string[];

  /**
   * Action when a circular reference is encountered.
   * 'omit': omit the field (for objects) or return undefined (for arrays).
   * 'replace': replace with a string marker "[Circular]".
   * Default: 'replace'
   */
  circularRefHandling?: 'replace' | 'omit';
}

const DEFAULT_DISALLOWED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Control characters: 0x00-0x1F and 0x7F, excluding \t (0x09), \n (0x0A), and \r (0x0D).
// Also matching Unicode formatting/bidi overrides that might alter display/parsing:
// \u200B-\u200D (zero-width spaces/joiners), \u202A-\u202E (bidi control), \uFEFF (BOM)
// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200D\u202A-\u202E\uFEFF]/g;

/**
 * Sanitizes an individual string leaf:
 * - Strips unwanted control characters
 * - Truncates to maxStringLength
 */
function sanitizeString(str: string, stripControlChars: boolean, maxStringLength: number): string {
  let cleaned = str;
  if (stripControlChars) {
    cleaned = cleaned.replace(CONTROL_CHAR_REGEX, '');
  }
  if (cleaned.length > maxStringLength) {
    cleaned = cleaned.slice(0, maxStringLength);
  }
  return cleaned;
}

/**
 * Recursively sanitizes nested JSON-compatible structures (objects, arrays, primitives).
 * Enforces depth limits, prototype pollution key stripping, control char cleaning,
 * string length caps, and handles circular references gracefully.
 */
export function sanitizeDeep<T = unknown>(value: T, options: SanitizeDeepOptions = {}): T {
  const maxDepth = options.maxDepth ?? 10;
  const maxStringLength = options.maxStringLength ?? 10_000;
  const maxKeys = options.maxKeys ?? 500;
  const maxArrayLength = options.maxArrayLength ?? 1_000;
  const stripControlChars = options.stripControlChars ?? true;
  const disallowedKeys = options.disallowedKeys
    ? new Set(options.disallowedKeys)
    : DEFAULT_DISALLOWED_KEYS;
  const circularHandling = options.circularRefHandling ?? 'replace';

  const seen = new WeakSet<object>();

  function helper(val: unknown, currentDepth: number): unknown {
    if (val === null || val === undefined) {
      return val;
    }

    if (typeof val === 'string') {
      return sanitizeString(val, stripControlChars, maxStringLength);
    }

    if (typeof val === 'number' || typeof val === 'boolean') {
      return val;
    }

    if (typeof val === 'bigint') {
      return val.toString();
    }

    // Functions, symbols are not valid JSON data types and are stripped / converted to undefined
    if (typeof val === 'function' || typeof val === 'symbol') {
      return undefined;
    }

    if (typeof val === 'object') {
      if (seen.has(val)) {
        return circularHandling === 'replace' ? '[Circular]' : undefined;
      }

      if (currentDepth >= maxDepth) {
        return circularHandling === 'replace' ? '[MaxDepthExceeded]' : undefined;
      }

      seen.add(val);

      if (Array.isArray(val)) {
        const resultArr: unknown[] = [];
        const length = Math.min(val.length, maxArrayLength);
        for (let i = 0; i < length; i++) {
          const item = helper(val[i], currentDepth + 1);
          resultArr.push(item);
        }
        seen.delete(val);
        return resultArr;
      }

      // Plain object or dictionary
      const resultObj: Record<string, unknown> = Object.create(null);
      const keys = Object.keys(val);
      let count = 0;

      for (const key of keys) {
        if (count >= maxKeys) {
          break;
        }

        // Prototype pollution defense: skip dangerous keys
        if (disallowedKeys.has(key)) {
          continue;
        }

        const sanitizedKey = sanitizeString(key, stripControlChars, maxStringLength);
        if (disallowedKeys.has(sanitizedKey)) {
          continue;
        }

        const childValue = helper((val as Record<string, unknown>)[key], currentDepth + 1);
        if (childValue !== undefined) {
          resultObj[sanitizedKey] = childValue;
          count++;
        }
      }

      seen.delete(val);
      // Return as standard plain object (prototype: Object.prototype)
      return { ...resultObj };
    }

    return undefined;
  }

  return helper(value, 0) as T;
}
