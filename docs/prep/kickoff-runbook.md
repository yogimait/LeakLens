# Kickoff runbook — environment, order of operations, per-milestone prompts

> 📝 Allowed pre-work: environment setup, AI prompt preparation, and sequencing. **No project code
> here** — the prompts are instructions to write code later, not the code.

## Before the clock starts

| Check | Command / action | Why it matters at hour 20 |
|---|---|---|
| Node version pinned | `node -v` — record it, put it in README and `.nvmrc` at kickoff | `zlib.crc32` and `inflateSync` behavior vary by version |
| `zlib.crc32` exists? | check on the exact Node you will ship against | Decides whether GitHub token checksum validation needs a fallback table (§Tier 1 of [credential-formats.md](credential-formats.md)) |
| Inflate byte-consumption | confirm how to learn how many **input** bytes an inflate consumed | Packfile objects have no stored compressed length — this blocks all pack parsing |
| Large repo cloned | any repo with >10k files and a big `.pack` | Perf pass at hour 28 needs it |
| gitleaks + trufflehog installed | outside the project directory | Head-to-head demo only. Never enters the repo, never a dependency |
| Git identity env vars ready | the fixed values from [fixture-design.md](fixture-design.md) | Deterministic fixture shas |
| Disk | a few GB free | packfile experiments |
| GitHub repo | **created at kickoff, not before** | Rules |
| Discord | joined, notifications on | Kickoff time, rule clarifications, submission instructions go there only |

## Hour 0 checklist, in order

1. Create the public GitHub repo. First commit: `README.md` stub + MIT `LICENSE` + empty
   `package.json` (`"type": "module"`, no dependency fields).
2. Copy the four prep docs into the repo as working notes — they are documentation, written before
   kickoff, which the rules permit. Say so in the commit message.
3. `tests/` directory with one trivial passing test, so `node --test` is green from commit two.
4. Then start §3 of [PLAN.md](../../PLAN.md) in section order.

Commit at every green state. The repo should never sit broken for more than ~30 minutes.

## Milestone prompts

Each prompt assumes the assistant has [PLAN.md](../../PLAN.md), [packfile-notes.md](packfile-notes.md),
and [credential-formats.md](credential-formats.md) in context. Keep them in the repo so they are
available to any tool, and so the "AI usage is allowed and expected" story is transparent rather
than hidden.

### M1 · Hours 0–4 — skeleton

> Build the CLI skeleton for LeakLens in a single `leaklens.mjs`, ESM, `node:` imports only. Sections
> in banner comments in this order: CONFIG, ARGV, TTY/RENDER, FS WALK, GIT, DETECT, CLASSIFY,
> REPORT, MAIN. Implement CONFIG, ARGV (`--help`, `--history`, `--format`, exit codes 0/1/2/3), TTY
> colour handling that disables itself when stdout is not a TTY, and a recursive directory walk with
> a gitignore-style matcher supporting `*`, `**`, `?`, `[...]`, `!`, anchored and directory-only
> patterns. Add `node:test` cases for the argument parser and the ignore matcher. No detection yet —
> print a file count.

### M2 · Hours 4–12 — detection engine

> Implement DETECT and CLASSIFY. Rule records carry: id, severity, pattern, optional offline
> `validate`, optional `enrich`, `advice` steps, `envName`, `references`. Ship the Tier 1 rules from
> credential-formats.md with real offline validation — GitHub token CRC32-over-entropy in base62, and
> AWS account-id derivation from the key ID. Then Tier 2 prefix rules and Tier 3 entropy+context.
> Include the placeholder-suppression and false-positive tables from that document. Findings are
> redacted by default and deduplicated by (rule id, secret hash, location). Tests: one per rule,
> plus a false-positive corpus that must produce zero findings.

### M3 · Hours 12–20 — git loose objects

> Implement the GIT section for loose objects only: read `.git/HEAD`, `refs/**`, and `packed-refs`;
> inflate `.git/objects/xx/yyyy…` with `node:zlib`; parse the `"<type> <size>\0"` header; verify
> SHA-1 over the inflated bytes with `node:crypto`; decode commit and tree objects; walk the commit
> graph and collect blobs. Enumerate the object directory independently of the walk so unreachable
> objects are discovered, and annotate each finding with `reachable: yes/no`. Bound everything: max
> object size, max walk depth, cycle detection. Tests against fixtures F1–F3 from fixture-design.md,
> with `git cat-file -p` as the oracle where git is available (skip cleanly if it is not).

### M4 · Hours 20–28 — packfiles and deltas ⚠️ highest risk

> Implement packfile reading per packfile-notes.md: `.idx` v2 magic and version check, 256-entry
> fanout, binary search of the sorted sha table, 4-byte offsets with the MSB escape into the 8-byte
> large-offset table; then `.pack` object headers (type + size varint), `OFS_DELTA` with the
> `((ofs+1) << 7) | (c & 0x7f)` negative-offset encoding, `REF_DELTA` by base sha, and the delta
> instruction stream (copy with its size-0-means-0x10000 rule, insert, reserved-zero rejection).
> Enforce a delta depth cap and cycle detection, and verify each applied delta against the delta
> header's target size. Tests: fixtures F4 and F5, every object compared byte-for-byte against
> `git cat-file -p`, plus the F6 hostile cases.

### M5 · Hours 28–34 — performance

> Profile a scan of the large fixture repo. Bound memory: stream large files, cap the resolved-base
> cache by bytes, avoid retaining whole packs. Only if single-threaded throughput is embarrassing,
> add a `node:worker_threads` pool with a bounded queue — measure before and after and record both
> numbers in the README.

### M6 · Hours 34–40 — reporting

> Implement REPORT: a terminal renderer (severity legend, aligned columns, redacted values), a JSON
> emitter with a stable schema, a SARIF 2.1.0 emitter that GitHub code scanning accepts, and the
> security score with its formula documented in the README. Exit codes per the CLI table.

### M7 · Hours 40–46 — remediation advisor

> Implement the §3b Remediation Advisor. Per finding, render: what was found, why it is dangerous,
> ordered remediation steps from the rule's `advice`, and the suggested `process.env.X` replacement.
> `--remediate` writes a remediation plan plus `.env.example` keys. `--remediate-patch` emits a
> unified diff replacing literals with env references — written outside the scan root, mode 0600,
> with an explicit "contains cleartext secrets, do not commit" warning, behind its own flag.
> `--verify <prev.json>` rescans and reports resolved / remaining / new, separating three facts:
> working tree state, history state, and the fact that rotation cannot be verified offline. Never
> print a clean bill of health while a secret-bearing object remains in the object database.

### M8 · Hours 46–54 — hardening

> Turn every row of the F6 hostile-input table into a `node:test` case and fix what breaks. Then run
> LeakLens against its own repository and assert zero findings outside `tests/fixtures/`.

### M9 · Hours 54–60 — reproducible build

> Write `build.mjs`: copy `leaklens.mjs` to `dist/`, normalise line endings, inject no timestamps,
> hostnames, or absolute paths, and emit `dist/SHA256SUMS` via `node:crypto`. Prove it: run twice,
> `cmp` the outputs, publish both hashes in the README. Add a dependency-proof script that prints the
> manifest, `npm ls --all`, and a check that every `import` in the file is `node:`-prefixed.

### M10 · Hours 60–70 — docs and video

> Fill the `<!-- FILL -->` markers in the README and STDLIB skeletons with real output, real counts,
> and `file:line` citations. Then record the five-minute demo along the arc in PLAN.md §6b.

## Demo video beats (5 minutes)

| Time | Beat |
|---|---|
| 0:00–0:30 | The problem: a secret deleted from HEAD is not gone |
| 0:30–1:15 | `git log -p \| grep` finds nothing. LeakLens `--history` finds the unreachable blob |
| 1:15–2:00 | The report: severities, redaction, the AWS account id derived offline |
| 2:00–3:00 | `--remediate`: the plan, the `.env.example`, the patch and its do-not-commit warning |
| 3:00–3:45 | `--verify`: working tree clean, history not, rotation unverifiable — say that line out loud |
| 3:45–4:30 | The constraint: `cat package.json`, `npm ls --all`, scroll the single file, run it in `--network none` with no git installed |
| 4:30–5:00 | Reproducible build: two runs, identical hashes |

## Rules I will not break, restated so there is no ambiguity at hour 3

| Rule | Practical meaning |
|---|---|
| No project code before kickoff | These docs are the limit. The first line of `leaklens.mjs` is written after the clock starts |
| Nothing committed before kickoff | Repo is created at kickoff |
| Commit history reflects real work | Real timestamps, pushed as work happens |
| Zero runtime dependencies | Every import is `node:`-prefixed, forever |
| No vendored third-party source | Read specs, write our own |
| No hand-rolled crypto | `node:crypto` only |
| Dev-only deps disclosed | There are none; if that changes, STDLIB.md says so |
