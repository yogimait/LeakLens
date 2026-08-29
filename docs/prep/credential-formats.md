# Credential formats — detection research

> 📚 Research notes for hours 4–12. **No project code** — shapes, checksums, and traps, written as
> documentation before kickoff.

## The point of this document

Every rule that can be **checksum-validated offline** is a rule that produces near-zero false
positives. That directly serves two scoring axes: usefulness (35%) and innovation (10%), and it is
achievable with `node:crypto`/`node:zlib` alone — no network, no validation API.

```mermaid
flowchart LR
    C["Candidate string"] --> P{"Prefix + length<br/>match a known format?"}
    P -->|no| E{"High entropy<br/>in a secret-ish context?"}
    P -->|yes| K{"Format carries a<br/>verifiable checksum?"}
    K -->|yes| V{"Checksum valid?"}
    K -->|no| SC["Score on prefix +<br/>context + entropy"]
    V -->|yes| HIGH["🔴 High confidence"]
    V -->|no| DROP["Drop with certainty<br/>(not a real token)"]
    E -->|yes| MED["🟡 Needs triage"]
    E -->|no| NONE["Ignore"]
    SC --> MED
```

## Tier 1 — offline-verifiable (ship these first)

### GitHub tokens

40 chars total for classic tokens: `prefix(3) + "_" + entropy(30) + checksum(6)`.

| Prefix | Kind |
|---|---|
| `ghp_` | personal access token (classic) |
| `gho_` | OAuth access token |
| `ghu_` | user-to-server token |
| `ghs_` | server-to-server token |
| `ghr_` | refresh token |
| `github_pat_` | fine-grained PAT — 93 chars |

**Offline validation:** CRC32 over the entropy portion, encoded in base62 with leading-zero padding,
is the trailing 6 characters. A string with the right prefix and length but a bad checksum can be
**dropped with certainty** — no network needed. This single rule kills most `ghp_`-shaped false
positives in docs and tests.

Implementation notes: CRC32 is not in `node:crypto` — but `node:zlib` exposes `crc32` in modern
Node. Verify availability on the target Node version at hour 0; the fallback is a table-driven
CRC32, ~15 lines, still stdlib-only. Base62 alphabet ordering matters — confirm against a known-good
token pair before trusting the rule.

Source: [Behind GitHub's new authentication token formats](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)

### AWS access key IDs

20 chars: 4-char prefix + 16 base32 chars.

| Prefix | Kind |
|---|---|
| `AKIA` | long-lived IAM user key |
| `ASIA` | temporary STS key |
| `AIDA` | IAM user id (not a credential — do not report as one) |
| `AROA` | IAM role id (same) |

**Offline enrichment — better than a checksum for our purposes:** the 12-digit **AWS account ID is
derivable from the key ID alone**, no network:

```
body    = base32_decode(key_id[4:])      # RFC 4648 alphabet, no padding
first6  = body[0:6]                      # as a big-endian integer
account = (first6 & 0x7fffffffff80) >> 7 # → 12-digit account id
```

Report it in the remediation block: *"exposed key belongs to AWS account 123456789012 — disable it
in that account's IAM console."* That is a genuinely useful thing no regex-only scanner tells you,
and it costs ~20 lines of stdlib.

Caveat to state honestly: this derivation is not a validity check. A well-formed random string
decodes to *some* account number. Use it as enrichment, and as a weak sanity signal (implausible
account IDs → lower confidence), never as proof.

Sources: [Deriving AWS Account ID from Access Key](https://chamila.dev/blog/2024-03-11_deriving-aws-account-id-from-access-key/) ·
[Hacking the Cloud](https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/)

### JWTs

Three base64url segments separated by `.`. Decode the header — if it parses as JSON with an `alg`
field, it is a real JWT, not a random dotted string. Then:

| Signal | Action |
|---|---|
| `alg: "none"` | 🔴 report as a vulnerability in its own right |
| Payload has `exp` in the past | 🟡 downgrade — expired token, still worth rotating |
| Payload has no `exp` | 🔴 upgrade — non-expiring token |
| Decodes but payload is `{"sub":"1234567890","name":"John Doe"}` | ⬜ the jwt.io sample — allowlist it |

The decoded payload may itself contain secrets. **Never print decoded payload contents** in the
default output — same redaction rule as everything else.

### PEM private keys

`-----BEGIN (RSA|EC|OPENSSH|PGP|DSA)? PRIVATE KEY-----`. Validation: base64 body must decode
cleanly and be over a plausible length. Encrypted keys carry `Proc-Type: 4,ENCRYPTED` or
`-----BEGIN ENCRYPTED PRIVATE KEY-----` — still report, but note that exposure severity is lower if
the passphrase is not also present. Check the surrounding lines for a passphrase; that combination
is a 🔴.

## Tier 2 — prefix + entropy only (no public checksum)

| Provider | Shape | Trap |
|---|---|---|
| Stripe | `sk_live_`, `rk_live_`, `pk_live_`, and `_test_` variants | `pk_` is publishable — **not** a secret. `_test_` is low severity. Getting this wrong is the classic scanner false-positive |
| Slack | `xox[baprsoe]-` + digit groups | Webhook URLs `hooks.slack.com/services/T…/B…/…` are separately reportable |
| Google API | `AIza` + 35 chars | Browser-embedded API keys are often intentionally public — flag as 🟡 with a note, not 🔴 |
| OpenAI | `sk-` + 48, `sk-proj-` | `sk-` alone is a weak prefix; require length + charset |
| Anthropic | `sk-ant-` | — |
| npm | `npm_` + 36 | — |
| SendGrid | `SG.` + two base64 chunks | — |
| Twilio | `SK` + 32 hex, `AC` + 32 hex | `AC` account SID is not secret by itself |
| Postgres/Mongo/MySQL URIs | `scheme://user:password@host` | Password `password`, `postgres`, `example` → allowlist. `localhost` host → downgrade |
| Generic private key files | `id_rsa`, `*.pem`, `*.key`, `*.p12`, `*.pfx` | Path-based signal only — never the sole evidence |

## Tier 3 — entropy + context

Applies when nothing above matches. Requires **two** signals to fire:

| Signal | Threshold (starting point, tune against fixtures) |
|---|---|
| Shannon entropy, base64 charset | ≥ 4.5 bits/char over ≥ 20 chars |
| Shannon entropy, hex charset | ≥ 3.0 bits/char over ≥ 32 chars |
| Assignment context | variable/key name matches `secret\|token\|password\|passwd\|api[_-]?key\|credential\|private[_-]?key\|auth` |
| File context | `.env`, `credentials.*`, CI config, `*.tfvars` |

### Placeholder suppression — the false-positive workhorse

| Pattern | Example |
|---|---|
| Repeated character runs | `xxxxxxxx`, `AAAAAAAA`, `00000000` |
| Obvious placeholders | `your_api_key_here`, `changeme`, `<token>`, `INSERT_KEY`, `TODO` |
| Templating syntax | `${VAR}`, `{{ var }}`, `%s`, `$VAR` |
| Already an env reference | `process.env.X`, `os.environ[...]` |
| Sample values | the jwt.io token, `AKIAIOSFODNN7EXAMPLE` (AWS's own documented example key) |
| Lockfile hashes | `sha512-…` in `package-lock.json`, `yarn.lock` — high entropy, never a secret |
| Test fixtures | paths under `test/`, `fixtures/`, `__snapshots__/` → downgrade, do not drop |

`AKIAIOSFODNN7EXAMPLE` appearing in AWS's own docs is the single most common AWS false positive in
the wild. Allowlist it by value.

## False-positive sources ranked by how often they burn scanners

| Rank | Source | Handling |
|---|---|---|
| 1 | Lockfiles (`package-lock.json`, `yarn.lock`, `Cargo.lock`, `poetry.lock`) | Skip by filename for entropy rules; keep pattern rules |
| 2 | Minified/bundled JS, source maps | Long-line heuristic: skip entropy on lines > 500 chars |
| 3 | Base64-embedded assets (images, fonts, WASM) | Detect data-URI prefix; skip |
| 4 | Git object shas, content hashes, UUIDs | Length+charset exact-match exclusions |
| 5 | `.example`/`.sample`/`.template` files | Downgrade severity, still report |
| 6 | Documentation and README code fences | Downgrade, still report |
| 7 | Vendored dependency trees (`node_modules`, `vendor/`) | Skip by default, `--include-vendor` to opt in |

## Fixture hygiene — do not shoot yourself

> ⚠️ Fixtures need tokens with **valid checksums** to exercise the validation path. Generate them at
> test time from known-fake entropy (compute the CRC32 ourselves), never paste a real token into the
> repo. A secret scanner whose own repo trips secret scanners is a bad look, and this repo will be
> scanned by curious judges.

Add a self-check to the test suite: run LeakLens on its own repo, assert zero 🔴 findings outside
`tests/fixtures/`, and allowlist that directory explicitly with a comment saying why.

## Rule record shape (data, written at build time — not now)

Each rule carries what §3b of [PLAN.md](../../PLAN.md) needs to give advice, so detection and
remediation stay one table, not two:

| Field | Purpose |
|---|---|
| `id` | stable, e.g. `github-pat-classic` — used in SARIF and baselines |
| `severity` | base severity before context adjustment |
| `match` | pattern |
| `validate` | optional offline checksum function |
| `enrich` | optional derivation (e.g. AWS account id) |
| `advice` | ordered remediation steps (§3b) |
| `envName` | suggested `process.env.X` replacement |
| `references` | provider's own rotation/revocation doc URL — printed, never fetched |
