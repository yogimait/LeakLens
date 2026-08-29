# CLAUDE.md — no-deps-project

Project: `LeakLens` — git-aware secret scanner for **Zero Dependency 2026** (Hackathon Raptors).
Single-file Node.js, Track E, solo. Constraints and schedule live in [PLAN.md](PLAN.md).

## Hard project rules

| Rule | Detail |
|---|---|
| Zero third-party runtime deps | Node built-ins only. `package.json` has no `dependencies`/`devDependencies`. |
| No code before kickoff | Planning, docs, research, prompt prep only until the 72h window opens. |
| No vendored third-party source | Cannot copy library code in to fake an empty manifest. |
| No hand-rolled crypto | Compose `node:crypto` primitives. Document the threat model. |
| Dev-only deps | None planned. If added, disclose in STDLIB.md. |
| Single file | Implementation stays in one `leaklens.mjs`. Tests live in `tests/`. |

## Documentation & explanation style — maximize visualizers

When documenting, explaining, planning, auditing, or comparing anything in this repo: **lead with
visuals, not prose.** Default to the richest visualizer the content allows.

### Required visualizers

| Content shape | Use |
|---|---|
| Flow, control flow, architecture | ```mermaid `flowchart` |
| Request lifecycle, multi-actor interaction | ```mermaid `sequenceDiagram` |
| State machine (e.g. finding lifecycle `detected→scored→deduped→redacted→reported`) | ```mermaid `stateDiagram-v2` |
| Model / entity relationships (git object graph, finding schema) | ```mermaid `erDiagram` |
| Roadmap, schedule, dependency graph | ```mermaid `gantt` |
| Comparison, matrix, enumerable set (findings, rules, options, API surface) | Markdown table |
| Scannable status | Callouts, checklists, severity/emoji legends |

### Rules of thumb

- A paragraph describing a flow, a hierarchy, or "A then B then C" → **draw it instead**.
- Quote Mermaid node labels containing punctuation: `N["Purge: crypto erase"]` — unquoted
  punctuation breaks rendering.
- Every non-trivial doc gets a **system/overview diagram near the top** and a **summary table** of
  key points. Prose only fills gaps the visuals cannot carry.
- Cite evidence precisely alongside visuals — `file:line`, e.g. `leaklens.mjs:412` for the
  delta-resolution branch.
- Mermaid renders natively on GitHub. VS Code needs a Mermaid preview extension.
- Applies to README.md, STDLIB.md, PLAN.md, threat model, and any audit or comparison output.

## Naming & casing — non-negotiable

Judges read this file top to bottom. A name is documentation; a one-letter name is a puzzle.

### Casing (one scheme, no exceptions)

| Kind | Casing | Example |
|---|---|---|
| Functions, variables, parameters, object properties | `camelCase` | `walkFiles`, `baselineFingerprints`, `packIndex` |
| Module-level constants (fixed data, never reassigned) | `SCREAMING_SNAKE_CASE` | `CONFIG`, `RULES`, `SEVERITIES`, `PACK_TYPE` |
| Classes | `PascalCase` | `GitStore` |
| Rule ids, CLI flags, output keys | `kebab-case` | `github-token-classic`, `--remediate-patch` |

**No `snake_case` anywhere in JavaScript.** It is the single most visible sign of a file written
by several hands. Verify with: `grep -nE "\b[a-z]+_[a-z]+\s*[=(]" leaklens.mjs` — must be empty.

### Naming rules

| Rule | Bad | Good |
|---|---|---|
| Name the thing, not its type | `const p`, `const s`, `const b` | `loosePath`, `lineText`, `packBuf` |
| One meaning per name across the whole file | `p` = path *and* probability *and* prefix | `filePath`, `probability`, `pathPrefix` |
| Loop variables say what they index | `for (let i …)` over shas | `for (let objectNumber …)` |
| Callback params name the element | `.map((f) => f.rule)` | `.map((finding) => finding.rule)` |
| Errors are `err`, never `e` | `catch (e)` | `catch (err)` |
| Booleans read as assertions | `lock`, `vendor` | `isIgnored`, `isHighEntropy`, `includeVendor` |
| Counts end in `Count`, collections are plural | `n`, `hist` | `objectCount`, `historyFindingCount`, `filePaths` |
| Never shadow an import or an outer binding | `const fs_ = …` next to `import fs` | `fileFindings` |
| Spec terms keep their spec spelling | renaming `fanout` to `bucketTable` | `fanout`, `OFS_DELTA`, `REF_DELTA` |

Single letters are allowed **only** in a one-line pure-math closure where the meaning is the
formula itself, and even then prefer a word.

### When editing

Renaming for clarity is always in scope. When a rename touches many call sites, change it in one
pass, then prove nothing moved: `node --check leaklens.mjs && node --test`, plus a before/after
diff of `--format json` output on a real repository. Behaviour-preserving means byte-identical
findings, not "tests still pass".

## Code conventions

- ESM, `node:` prefixed imports only (`import { inflateSync } from "node:zlib"`).
- Single file, banner-sectioned:
  `// ===== GIT =====`. Sections in the order listed in [PLAN.md](PLAN.md) §3.
- Tests: `node:test` + `node:assert`, run with `node --test`.
- Deliberate shortcuts get a comment naming the ceiling and the upgrade path.
- Findings are redacted by default; full values only behind `--unsafe-show-secrets`.
- No network calls anywhere in the tool. Offline-safe is a design guarantee, not an accident.
