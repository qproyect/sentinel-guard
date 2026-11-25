# AGENTS.md — sentinel-guard

Context for AI coding agents (Claude, Antigravity, Codex, Jules) and for humans.
Keep it short and current: update it whenever a command or convention changes.

## What this is

A zero-runtime-dependency TypeScript library (Node 20+) that hardens untrusted content
before it reaches an LLM or a database. See the threat model in `README.md`.

## Layout

- `src/wrapUntrusted.ts` — nonce-tagged delimiters, defanging of look-alike tags and
  homoglyphs, and the matching system instruction.
- `src/sanitizeDeep.ts` — recursive JSON sanitization: prototype-pollution keys,
  depth/size ceilings, control characters, circular references.
- `src/safeEqual.ts` — constant-time string comparison.
- `src/index.ts` — public API. `tests/` — Vitest. `examples/rag-context.ts` — usage.

## Commands

```bash
npm ci
npm run lint
npm run format:check
npm run build
npm test
npm run example:rag
```

## Rules

- No runtime dependencies. Use only JavaScript and Node built-ins; dev dependencies are
  fine.
- Every attack in the README threat model needs a test, and a new defense needs one too.
  Add the failing input first, then the fix.
- Comparisons of secrets stay constant-time (`safeEqual`); never use `===` on tokens.
- Keep the public API in `src/index.ts` small and typed. Changing a signature is a
  breaking change: bump the version and note it in the README.
- Sanitizers must not throw on hostile input (the current source has no `throw`); they
  return a safe value.
