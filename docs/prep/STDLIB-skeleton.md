# STDLIB.md skeleton (draft — becomes STDLIB.md at kickoff)

> 📝 Worth +3 on its own (≥10 substitutions) and feeds the +3 Package Killer bonus. Everything
> except the `file:line` citations can be written now.

---

# STDLIB.md — what we would have installed, and what we used instead

LeakLens has **zero third-party runtime dependencies** and **zero development dependencies**. This
document lists every package a normal implementation of this tool would pull in, and the Node
standard-library functionality that replaced it.

## Summary

| | Count |
|---|---|
| Runtime dependencies | **0** |
| Development dependencies | **0** |
| Documented substitutions | <!-- FILL: final count, target ≥17 --> |
| Headline package replaced | `gitleaks` |

## Substitutions

| # | Normally | Instead | Where |
|---:|---|---|---|
| 1 | `gitleaks` / `trufflehog` / `detect-secrets` — secret scanning | the whole tool | <!-- FILL --> |
| 2 | `simple-git` / `isomorphic-git` / `nodegit` — git access | own `.git` reader: loose objects, `.idx` v2 binary search, packfile object headers, ofs/ref delta resolution | <!-- FILL: leaklens.mjs:NNN --> |
| 3 | `pako` / `zlib-js` — decompression | `node:zlib` `inflateSync` / `createInflate` | <!-- FILL --> |
| 4 | `commander` / `yargs` / `minimist` — argument parsing | own `process.argv` parser with `--help` and exit codes. Node ships `util.parseArgs` (v18.3), but it handles `string` and `boolean` only — no value-bearing `--out <path>` semantics, no per-error exit codes | <!-- FILL --> |
| 5 | `chalk` / `picocolors` / `kleur` — terminal color | ANSI escapes + `isTTY`, auto-disabled when piped, honouring `NO_COLOR` and `FORCE_COLOR` (chalk's contract, without chalk). Node ships `util.styleText`, but only from v22.17 — ours runs on v20 | <!-- FILL --> |
| 6 | `ora` / `cli-progress` — progress display | `\r` writes to `process.stderr` | <!-- FILL --> |
| 7 | `cli-table3` / `table` — column layout | own width-measuring formatter | <!-- FILL --> |
| 8 | `glob` / `fast-glob` / `readdirp` — file discovery | own `node:fs` recursive walk. Node ships `fs.globSync` (v22), but it has no gitignore semantics — no negation, no directory-only patterns, no last-match-wins — and would raise our floor to v22 | <!-- FILL --> |
| 9 | `ignore` / `minimatch` — gitignore semantics | own glob matcher: `*`, `**`, `?`, `[...]`, `!` negation, directory-only and anchored patterns | <!-- FILL --> |
| 10 | `dotenv` — `.env` parsing | own line parser. Node ships `process.loadEnvFile` (v20.6), but it *loads* values into `process.env`; we *parse* `.env` files as untrusted text to scan them, and must never execute their contents | <!-- FILL --> |
| 11 | `js-yaml` — YAML | minimal scalar scanner, scoped to extracting secret-shaped values | <!-- FILL --> |
| 12 | `p-limit` / `piscina` / `workerpool` — concurrency | `node:worker_threads` + own bounded queue | <!-- FILL --> |
| 13 | `shannon-entropy` / `entropy-string` | own Shannon entropy over charset-gated windows | <!-- FILL --> |
| 14 | `hasha` / `sha.js` / `js-sha1` — hashing | `node:crypto` `createHash` (SHA-1 for git object identity, SHA-256 for build hashes) | <!-- FILL --> |
| 15 | `crc-32` — checksums | `node:zlib` `crc32` when present, with a table-driven fallback so GitHub-token validation works on any Node ✅ confirmed available on v22.18 | <!-- FILL --> |
| 16 | `iconv-lite` / `isbinaryfile` — encoding detection | `node:buffer` NUL-byte and non-printable-ratio heuristic | <!-- FILL --> |
| 17 | `diff` / `jsdiff` — patch generation | own unified-diff emitter for `--remediate-patch` | <!-- FILL --> |
| 18 | `node-sarif-builder` — SARIF output | own SARIF 2.1.0 JSON emitter | <!-- FILL --> |
| 19 | `jest` / `mocha` / `chai` — testing | `node:test` + `node:assert` | <!-- FILL --> |
| 20 | `tmp` / `rimraf` — temp dirs in tests | `fs.mkdtempSync` + `fs.rmSync({ recursive: true })` | <!-- FILL --> |

<!-- FILL: prune any row that did not actually ship. A substitution claimed but not implemented is
worse than a shorter list. -->

### Why hand-roll what Node 22 already ships?

Four rows above (4, 5, 8, 10) replace packages that recent Node versions also replace —
`util.parseArgs`, `util.styleText`, `fs.globSync`, `process.loadEnvFile`. Using the built-ins
would have been less code. We wrote our own anyway, for two reasons that are checked by tests, not
asserted in prose:

| Reason | Evidence |
|---|---|
| **Portability.** Every one of those built-ins is gated on Node 20.6–22.17. LeakLens uses **zero** v22-only APIs, so it runs on Node 20 — the version still shipping in most LTS containers and CI images | <!-- FILL: cite the proof test in tests/leaklens.test.mjs --> |
| **Semantics.** `fs.globSync` cannot express gitignore's negation and last-match-wins rules; `parseArgs` cannot express our value flags and exit codes; `loadEnvFile` executes what we need to treat as untrusted input | <!-- FILL: cite the matcher and parser sections --> |

The same reasoning drives the `crc32` fallback in row 15: call the built-in when it exists, ship a
table when it does not, and the tool works either way.

## Package Killer: `gitleaks`

<!-- FILL after the head-to-head run -->

| | gitleaks | LeakLens |
|---|---|---|
| Distribution | Go binary, ~27.7k★ | one `.mjs` file |
| Reads history via | `git log -p` subprocess — requires the `git` binary | own object-database reader |
| Sees unreachable blobs | no — `git log` walks reachable commits only | **yes** |
| Remediation guidance | no | yes |
| Findings on the demo fixture | <!-- FILL --> | <!-- FILL --> |

The substantive difference is not the regex list — it is that gitleaks delegates git to git. LeakLens
implements the parts of git's object model it needs: zlib framing, object headers, the pack index
fanout and binary search, and both delta encodings. That is roughly <!-- FILL: line count --> lines
of the file, and it is why LeakLens finds objects `git log -p` cannot show it.

## Notable substitutions, in detail

### Reading packfiles instead of shelling out to `git`

<!-- FILL: short walkthrough + file:line. Cover: .idx v2 fanout → binary search → 4-byte offset with
MSB escape to the 8-byte table → object header varint → ofs-delta's (ofs+1)<<7 encoding → delta
copy/insert instruction stream → depth and cycle limits. -->

### Offline checksum validation instead of a validation API

<!-- FILL: GitHub token CRC32-over-entropy in base62; AWS account-id derivation from the key ID.
Both are pure computation — the reason LeakLens can be precise without a network call. -->

### A gitignore matcher instead of `ignore`

<!-- FILL: which gitignore semantics are supported and which are deliberately not -->

## Development dependencies

**None.** The build script, the test suite, and the fixture generator are all plain Node.

`git` is used in the test suite as an **oracle** — fixtures are created with it and our reader's
output is asserted against `git cat-file`. It is not required to run LeakLens, is not imported, and
is not part of the distributed artifact. Tests that need it skip cleanly when it is absent.

## What we did *not* reimplement, and why

| Not reimplemented | Reason |
|---|---|
| Cryptographic hash functions | Track E forbids hand-rolled crypto. `node:crypto` composes trusted primitives |
| The zlib algorithm | `node:zlib` is the standard library. Reimplementing DEFLATE would be showmanship, not engineering |
| A regex engine | `RegExp` is part of the language, not a package |
| Credential validation against provider APIs | Deliberate: zero network calls is a security property of this tool, not a missing feature |
