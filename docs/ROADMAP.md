# secret-keystore — Roadmap to the Best-in-Class KMS `.env` Library

> Status: proposal / draft for discussion
> Goal: make `secret-keystore` the **best-in-class Node.js library for AWS-KMS-encrypted
> `.env` (and JSON/YAML) configuration** — safe by default, KMS-only, Key-ID-only.

---

## 1. Design philosophy (why AWS-KMS-only is a feature, not a limit)

The deliberate constraint: **a developer only ever handles a KMS Key ID** — which is *not*
a secret — and never touches key material, a passphrase, or a private key. AWS KMS keeps all
key material server-side, enforces access through IAM, and exposes `DescribeKey` so the library
can introspect key type/spec without ever revealing the key.

This is the opposite of age/PGP/passphrase tools, which force non-experts to manage private
key material — the exact footgun KMS was built to remove. So "KMS-only" is the property that
makes the tool *safe by default*. Paired with Nitro Enclave attestation, it matches the
AWS-KMS-+-Nitro architecture used by confidential-computing platforms like Anjuna Seaglass.

**Scope decision:** stay a focused, excellent Node.js library. No multi-provider abstraction,
no cross-language ports for now. A format spec is optional hygiene (see §6), not a goal.

---

## 2. Where we are today

Strong internals already in place:

- Value / object / content operations across `.env`, JSON, and YAML.
- Path selection (explicit paths + glob-style patterns + excludes).
- Runtime `SecretKeyStore` with TTL, access limits, secure-wipe, in-memory encryption.
- **Adaptive crypto**: `DescribeKey` detects key spec — direct `Encrypt`/`Decrypt` for
  symmetric keys, AES-256-GCM envelope for RSA (to beat the RSA size limit).
- AWS Nitro Enclave attestation.
- A thorough, coded error taxonomy.

Gaps that keep it from being *best-in-class* (provider lock-in is intentionally **not** a gap):

| # | Gap | Severity |
|---|-----|----------|
| 1 | **No tests / CI / lint** — `test` is the npm placeholder; `devDependencies` empty. | Blocking |
| 2 | **Thin CLI** — `encrypt` only; no `decrypt` / `run` / `rotate` / `edit`. | High |
| 3 | **No zero-config runtime loader** — no `config()`, no file cascade, no dotenv-compat. | High |
| 4 | **`.env` parsing parity** — no `${VAR}` expansion; multiline/quoting unspecified. | Medium |
| 5 | **No key-rotation workflow** — no first-class re-encrypt-under-new-key path. | Medium |
| 6 | **Per-value KMS calls** — N vars = N API calls; no optional batching. | Medium |
| 7 | **Missing ecosystem** — schema validation, git filters, audit log, bundler plugins. | Medium |

Reference for *ergonomics* (not architecture): **dotenvx** — `run` to inject secrets into a
process at runtime, plus rotation and auditing. That UX is what drives adoption; we can match
it while keeping KMS as the trust anchor.

---

## 3. Phased plan (prioritized)

Ordering principle: **earn trust first (tests), then close the UX gap (CLI + loader), then add
KMS depth, then ecosystem.**

### Phase 0 — Foundations of trust *(prerequisite for everything)*
- Real test suite: unit + integration, with a **mocked KMS client** (`aws-sdk-client-mock`)
  covering both symmetric and RSA-envelope paths, plus round-trip property tests.
- Coverage gate (e.g. ≥90% on `src/`).
- CI workflow: lint + typecheck + test matrix on Node 18 / 20 / 22.
- ESLint + Prettier; verify `index.d.ts` matches the actual exports.
- **CLI `decrypt`** (currently encrypt-only) so round-trips are testable end to end.

*Impact: high · Effort: medium · Skipping it = nobody trusts a secrets tool with zero tests.*

### Phase 1 — Close the UX gap *(the adoption drivers)*
- CLI parity with the field: `init`, `encrypt`, `decrypt`, **`run`/`exec`** (decrypt + inject
  into a subprocess), `rotate`, `edit` (decrypt → `$EDITOR` → re-encrypt), `keys`, `status`/`diff`.
- **Zero-config runtime loader**: `keystore.config()` that auto-discovers and cascades
  `.env` → `.env.local` → `.env.<NODE_ENV>`, decrypts via KMS, and populates `process.env`.
- **dotenv migration**: an `import` command + a drop-in compat shim so `dotenv`/`dotenvx`
  users switch with one line.
- `.env` parsing parity: `${VAR}` expansion, multiline, quoting — matched to dotenv's de-facto rules.

*Impact: high (this is what earns stars/downloads) · Effort: medium–high.*

### Phase 2 — KMS-native depth *(do the AWS integration better than anyone)*
- **Key rotation / re-encryption workflow**: `rotate` re-encrypts a file under a new Key ID
  (or new alias target) in one pass; support KMS **aliases** so rotation is config, not code.
- **Optional symmetric envelope batching**: opt-in mode using `GenerateDataKey` once per file
  → one KMS call regardless of var count (cost/latency/throttling win). Off by default; still Key-ID-only.
- **Cache `DescribeKey`** results per key to avoid repeating the lookup on every call.
- **Multi-region keys** awareness; clearer IAM/grant-aware error messages (`KMS_ACCESS_DENIED`, throttling backoff).
- **Access audit log**: structured record of who decrypted what, when (hook-able).

*Impact: medium–high · Effort: medium.*

### Phase 3 — Ecosystem & integrations
- **Git integration**: pre-commit hook to block plaintext secrets + `.gitattributes`
  clean/smudge filter for encrypted diffs.
- **Schema / typed env**: required-var enforcement and typed access (envalid/zod-style).
- **Bundler/framework plugins**: Vite, Webpack, Next; refresh the NestJS/Next examples to use `run`.
- **Nitro attestation hardening + docs**: first-class guide for the KMS-+-enclave deployment path.

*Impact: medium · Effort: high (parallelizable per integration).*

---

## 4. Priority matrix (impact vs effort)

| Initiative | Impact | Effort | Phase | Do when |
|---|---|---|---|---|
| Test suite + CI (both crypto paths) | High | Med | 0 | **Now** |
| CLI `decrypt` | High | Low | 0 | **Now** |
| CLI `run`/`exec` | High | Med | 1 | After 0 |
| `config()` runtime loader + cascade | High | Med | 1 | After 0 |
| dotenv migration + `${VAR}` expansion | Med | Med | 1 | After loader |
| `rotate` + KMS aliases | Med-High | Med | 2 | After 1 |
| Optional symmetric envelope batching | Med | Med | 2 | When call-volume hurts |
| `DescribeKey` caching | Med | Low | 2 | Quick win |
| Access audit log | Med | Low-Med | 2 | Parallel |
| Git filter / pre-commit hook | Med | Med | 3 | After 1 |
| Schema / typed env | Med | Med | 3 | Parallel |
| Bundler/framework plugins | Med | High | 3 | After loader |

**Suggested first sprint:** all of Phase 0 (tests, CI, lint, CLI `decrypt`). Cheapest high-impact
work, and it makes every later change safe to ship.

---

## 5. Crypto model — keep what you have

Your `DescribeKey`-driven branching is correct and stays:

- **Symmetric key** → direct KMS `Encrypt`/`Decrypt` per value (≤4 KB plaintext; fine for env values).
- **Asymmetric (RSA) key** → AES-256-GCM envelope per value, DEK wrapped via KMS `Encrypt`
  (lifts the ~190–446 byte RSA limit).

The **only** optional addition is symmetric **batching** (Phase 2): one `GenerateDataKey` per file
instead of one `Encrypt` per value. It's a performance/cost optimization, not a correctness fix —
ship it behind a flag if and when per-value call volume becomes a problem.

---

## 6. Open questions

1. **`run` semantics** — read the private decrypt path from env (`KMS` IAM role in prod) and
   from a local profile in dev, à la dotenvx? Confirm the dev-vs-prod key-source story.
2. **Envelope batching** — worth building now, or defer until a user hits KMS throttling?
3. **Format spec** — write a short versioned `SPEC.md` for the envelope/wrapped formats as
   internal hygiene (helps testing + future-proofing), or skip until needed?
4. **Audit log sink** — built-in (file/stdout) only, or a pluggable hook for CloudTrail/SIEM?
5. **`.env` precedence** — match dotenv's "first definition wins / don't override existing
   `process.env`", or override? Pick one and document it loudly.
