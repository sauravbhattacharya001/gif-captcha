# `gif-captcha` CLI Reference

The `gif-captcha` package ships an executable that exposes the library's core
functionality from the terminal. The binary is wired via the `bin` field in
`package.json`, so after `npm install gif-captcha` (locally or globally) you can
invoke it as:

```bash
npx gif-captcha <command> [flags]      # local install
gif-captcha <command> [flags]          # global / linked install
node ./bin/gif-captcha.js <command>    # from a clone of this repo
```

> **Note:** The CLI uses a cryptographically secure shuffle (`secureRandomInt`)
> for sample selection. `Math.random` is intentionally forbidden in any
> CAPTCHA-touching path — see [`src/crypto-utils.js`](../src/crypto-utils.js)
> and CWE-330.

## Commands

| Command | Purpose |
|---------|---------|
| [`generate`](#generate) | Emit one or more sample challenges |
| [`validate`](#validate) | Score an answer against an expected solution |
| [`benchmark`](#benchmark) | Micro-benchmark hot paths (`createChallenge`, `validateAnswer`, …) |
| [`pool`](#pool) | Build and inspect a challenge pool |
| [`trust`](#trust) | Look up a client trust score by IP |
| [`stats`](#stats) | Set-level statistics across a batch of challenges |
| [`info`](#info) | Print library version and available factory functions |
| [`doctor`](#doctor) | End-to-end diagnostic (modules + perf + validation edges) |

Run `gif-captcha` with no arguments (or with an unknown command) to print a
short usage summary equivalent to this section.

---

### `generate`

Generate a number of sample CAPTCHA challenges drawn from the built-in sample
GIF set. Useful for fixtures, manual smoke tests, or seeding a local pool.

```bash
gif-captcha generate [--count N]
```

| Flag | Default | Notes |
|------|---------|-------|
| `--count N` | `1` | Number of challenges. Capped at the sample set size (currently 10). |

Output: human-readable per-challenge block with `id`, `title`, `gifUrl`, and
the canonical keyword list.

---

### `validate`

Run the library's fuzzy matcher against a single answer/expected pair and print
the similarity score.

```bash
gif-captcha validate --answer <text> --expected <text> [--threshold N]
```

| Flag | Default | Notes |
|------|---------|-------|
| `--answer` | _required_ | The user-supplied answer. |
| `--expected` | _required_ | The canonical / human answer. |
| `--threshold` | `0.5` | Pass threshold in `[0, 1]` (forwarded to `validateAnswer`). |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Validation ran (regardless of pass/fail). |
| `1` | Missing required flag. |

---

### `benchmark`

Quick micro-benchmark of core operations. Reports total time and per-op cost
for `createChallenge`, `validateAnswer`, `textSimilarity`, and
`createSessionManager`.

```bash
gif-captcha benchmark [--rounds N] [--sessions N]
```

| Flag | Default | Notes |
|------|---------|-------|
| `--rounds` | `1000` | Iterations for challenge / validation / similarity loops. |
| `--sessions` | `100` | Iterations for the session-manager construction loop. |

---

### `pool`

Construct a `PoolManager`, seed it with `size` synthetic challenges, and print
its current stats (size, refill threshold, etc.).

```bash
gif-captcha pool [--size N] [--refill N]
```

| Flag | Default |
|------|---------|
| `--size` | `10` |
| `--refill` | `5` |

---

### `trust`

Evaluate an IP against a freshly-initialised `TrustScoreEngine` and print its
score (or the default action if the engine has no prior history for the
client).

```bash
gif-captcha trust --ip <ip>
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Lookup completed. |
| `1` | `--ip` not supplied. |

---

### `stats`

Generate `--challenges N` synthetic challenges and run them through the set
analyzer. Useful for sanity-checking diversity and balance metrics.

```bash
gif-captcha stats [--challenges N]
```

| Flag | Default |
|------|---------|
| `--challenges` | `10` |

---

### `info`

Print the installed library version (from `package.json`) plus the list of
exported factory functions. Cheap and side-effect-free — handy for verifying
which build is on the `PATH`.

```bash
gif-captcha info
```

---

### `doctor`

End-to-end diagnostic. Walks five sections:

1. **Module availability** — confirms that the expected `createX` factories are
   exported from the package entrypoint.
2. **Core functionality** — exercises `createChallenge`, `validateAnswer`,
   `textSimilarity`, `createSessionManager`, and `createPoolManager`.
3. **Performance quick-check** — 500 rounds each of challenge creation,
   validation, and similarity scoring; warns if per-op cost exceeds 1 ms.
4. **Validation edge cases** — empty answer/expected, case insensitivity,
   whitespace tolerance, exact match.
5. **Environment** — Node version and platform.

```bash
gif-captcha doctor [--verbose]
```

| Flag | Default | Notes |
|------|---------|-------|
| `--verbose` | _off_ | Print every passing check (not just failures/summaries). |

The command exits non-zero only on hard failures (errors), not on warnings —
making it safe to wire into CI as a smoke test.

---

## Scripting

The CLI is line-oriented and prints stable section headers, so most outputs
parse cleanly with `grep`/`awk`. For machine-readable workflows, prefer the
library directly:

```js
const gifCaptcha = require("gif-captcha");
const challenge = gifCaptcha.createChallenge({ /* … */ });
const result = gifCaptcha.validateAnswer(answer, challenge.humanAnswer);
```

See [`API.md`](../API.md) for the full programmatic surface.
