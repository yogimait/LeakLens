// End-to-end tests: the real binary, run as a subprocess, against purpose-built
// repositories from fixtures.mjs.
//
// leaklens.test.mjs covers the internals by importing them. This file covers the
// thing a user actually runs — argument handling, exit codes, what lands on
// stdout, and the files written to disk. Those are the parts a unit test cannot
// reach, because they live in main() and end in process.exit.
//
// The case matrix is exported so a reporting script can render the same runs as
// an expected-versus-actual table without restating any of it.

import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { buildRepo, hasGit, SECRETS } from "./fixtures.mjs";
import { RULES, parseArgv } from "../leaklens.mjs";

const CLI = fileURLToPath(new URL("../leaklens.mjs", import.meta.url));

// Runs the CLI and captures everything, including a non-zero exit.
export function runCli(args, cwd = process.cwd()) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      cwd, env: { ...process.env, NO_COLOR: "1" }, stdio: "pipe", maxBuffer: 32 * 1024 * 1024,
    });
    return { exitCode: 0, stdout: stdout.toString(), stderr: "" };
  } catch (err) {
    return {
      exitCode: err.status ?? -1,
      stdout: (err.stdout ?? "").toString(),
      stderr: (err.stderr ?? "").toString(),
    };
  }
}

// Fixtures are expensive to build (delta commits 30 times), so each is built
// once for the whole file rather than per case.
const built = new Map();
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "leaklens-e2e-"));
export function fixture(kind) {
  if (!built.has(kind)) built.set(kind, buildRepo(kind, path.join(scratch, kind)));
  return built.get(kind);
}
process.on("exit", () => {
  try { fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 3 }); } catch {}
});

// ===== the case matrix =====
//
// Each case states what the feature *should* do, independently of what it
// currently does. `expect.describe` is prose for the report; the checks are what
// the assertions enforce.

export const CASES = [
  // ---- detection ----
  {
    group: "Detection",
    name: "every shipped rule fires on the all-rules fixture",
    fixtureKind: "all-rules",
    args: ["--format", "json"],
    describe: `all ${RULES.length} rules report at least one finding`,
    check(result) {
      const report = JSON.parse(result.stdout);
      const found = new Set(report.findings.map((f) => f.rule));
      const missing = RULES.map((r) => r.id).filter((id) => !found.has(id));
      assert.deepEqual(missing, [], `rules that failed to fire: ${missing.join(", ")}`);
      return `${found.size} distinct rules fired, 0 missing`;
    },
  },
  {
    group: "Detection",
    name: "severities match each rule's declared level",
    fixtureKind: "all-rules",
    args: ["--format", "json"],
    describe: "a rule with no severityFor reports exactly its declared severity",
    check(result) {
      const report = JSON.parse(result.stdout);
      const mismatches = [];
      for (const finding of report.findings) {
        const rule = RULES.find((r) => r.id === finding.rule);
        // rules with severityFor compute severity from the match, so skip those
        if (!rule || rule.severityFor) continue;
        if (finding.severity !== rule.severity) {
          mismatches.push(`${finding.rule}: ${finding.severity} != ${rule.severity}`);
        }
      }
      assert.deepEqual(mismatches, []);
      return `${report.findings.length} findings, severities consistent`;
    },
  },
  {
    group: "Detection",
    name: "a GitHub token with a bad checksum is dropped, not reported",
    fixtureKind: "clean",
    args: ["--format", "json"],
    describe: "checksum validation drops provably-invalid tokens with certainty",
    setup(dir) {
      fs.writeFileSync(path.join(dir, "bad-token.js"), `const t = "${SECRETS.githubTokenBadChecksum}";\n`);
    },
    check(result) {
      const report = JSON.parse(result.stdout);
      const hits = report.findings.filter((f) => f.file === "bad-token.js");
      assert.deepEqual(hits, [], "an invalid checksum must not be reported at all");
      return "0 findings for the invalid token";
    },
  },
  {
    group: "Detection",
    name: "the AWS account id is derived from the key id, offline",
    fixtureKind: "all-rules",
    args: ["--format", "json"],
    describe: "an AWS key finding carries a 12-digit account id in its note",
    check(result) {
      const report = JSON.parse(result.stdout);
      const aws = report.findings.find((f) => f.rule === "aws-access-key-id");
      assert.ok(aws, "the AWS key must be found");
      assert.match(aws.note ?? "", /\b\d{12}\b/, "note must contain a 12-digit account id");
      return aws.note;
    },
  },

  // ---- staying quiet ----
  {
    group: "Quiet",
    name: "a repository of decoys produces nothing and exits 0",
    fixtureKind: "clean",
    args: [],
    expectExit: 0,
    describe: "documented examples, placeholders, env refs and lockfile hashes are all ignored",
    check(result) {
      assert.match(result.stdout, /No findings/);
      assert.match(result.stdout, /Score 100\/100/);
      return "0 findings, score 100, exit 0";
    },
  },

  // ---- history ----
  {
    group: "History",
    name: "a deleted secret is invisible by default and found with --history",
    fixtureKind: "deleted",
    args: ["--history", "--format", "json"],
    describe: "removing a secret in a later commit does not remove it from history",
    check(result) {
      const report = JSON.parse(result.stdout);
      const hit = report.findings.find((f) => f.rule === "github-token-classic");
      assert.ok(hit, "the deleted secret must still be found in history");
      assert.equal(hit.source, "history");
      assert.equal(hit.atHead, false, "it is no longer at HEAD");
      assert.equal(hit.reachable, true, "but it is still reachable from a ref");
      return `found in history, atHead=false, reachable=true, commit ${String(hit.commit).slice(0, 8)}`;
    },
  },
  {
    group: "History",
    name: "the same repository is clean without --history",
    fixtureKind: "deleted",
    args: [],
    expectExit: 0,
    describe: "a default scan looks only at the working tree",
    check(result) {
      assert.match(result.stdout, /No findings/);
      return "0 findings, exit 0";
    },
  },
  {
    group: "History",
    name: "an amended-away secret is found and marked unreachable",
    fixtureKind: "unreachable",
    args: ["--history", "--format", "json"],
    describe: "the headline claim: found although no ref reaches it",
    check(result) {
      const report = JSON.parse(result.stdout);
      const hit = report.findings.find((f) => f.rule === "github-token-classic");
      assert.ok(hit, "the amended-away secret must be found");
      assert.equal(hit.reachable, false, "no ref reaches this object");
      return `found, reachable=false, blob ${String(hit.blobSha).slice(0, 8)}`;
    },
  },
  {
    group: "History",
    name: "git itself cannot surface the amended-away secret",
    fixtureKind: "unreachable",
    args: null, // this case runs git, not the CLI
    describe: "`git log --all -p` finds nothing, which is why git-log-based scanners miss it",
    run(dir) {
      const patches = execFileSync("git", ["log", "--all", "-p"], { cwd: dir, stdio: "pipe" }).toString();
      return { exitCode: 0, stdout: patches, stderr: "" };
    },
    check(result) {
      assert.ok(!result.stdout.includes(SECRETS.githubToken), "git must not be able to show it");
      return "git log --all -p does not contain the token";
    },
  },
  {
    group: "History",
    name: "packing the repository does not change the findings",
    fixtureKind: "packed",
    args: ["--history", "--format", "json"],
    describe: "objects read through the packfile path give identical results",
    check(result) {
      const report = JSON.parse(result.stdout);
      const hit = report.findings.find((f) => f.rule === "github-token-classic");
      assert.ok(hit, "the secret must survive git gc");
      assert.equal(hit.reachable, false);
      return "found through the packfile path, reachable=false";
    },
  },
  {
    group: "History",
    name: "a secret inside a delta chain is reconstructed",
    fixtureKind: "delta",
    args: ["--history", "--format", "json"],
    describe: "delta-compressed objects are rebuilt from base + instructions",
    check(result) {
      const report = JSON.parse(result.stdout);
      const hit = report.findings.find((f) => f.rule === "stripe-secret-key");
      assert.ok(hit, "the secret in the delta chain must be found");
      assert.equal(hit.file, "big.txt");
      return `found in ${hit.file} after aggressive gc`;
    },
  },

  // ---- ignore semantics ----
  {
    group: "Ignore",
    name: "nested .gitignore excludes build output, but never a credential file",
    fixtureKind: "nested-ignore",
    args: ["--format", "json"],
    describe: "gitignore is honoured at every level, except for credential-shaped files",
    check(result) {
      const report = JSON.parse(result.stdout);
      const files = report.findings.map((f) => f.file);
      assert.ok(!files.includes("app/build/bundle.js"), "nested ignore must exclude build output");
      assert.ok(!files.includes("dropped.log"), "root ignore must still apply");
      assert.ok(files.includes("server/.env"), "a gitignored .env must still be scanned");
      return `scanned server/.env, skipped app/build and dropped.log`;
    },
  },

  // ---- output formats ----
  {
    group: "Formats",
    name: "--format json emits the documented schema",
    fixtureKind: "all-rules",
    args: ["--format", "json"],
    describe: "stable keys, so the output can be consumed by other tools",
    check(result) {
      const report = JSON.parse(result.stdout);
      assert.equal(report.tool, "LeakLens");
      for (const key of ["version", "root", "scannedAt", "summary", "findings"]) {
        assert.ok(key in report, `missing top-level key: ${key}`);
      }
      for (const key of ["files", "objects", "historyScanned", "score", "counts", "suppressed", "notes"]) {
        assert.ok(key in report.summary, `missing summary key: ${key}`);
      }
      for (const key of ["fingerprint", "rule", "severity", "file", "line", "col", "source", "secret"]) {
        assert.ok(key in report.findings[0], `missing finding key: ${key}`);
      }
      return "all documented keys present";
    },
  },
  {
    group: "Formats",
    name: "--format sarif emits valid SARIF 2.1.0",
    fixtureKind: "all-rules",
    args: ["--format", "sarif"],
    describe: "GitHub code scanning must be able to ingest the output",
    check(result) {
      const sarif = JSON.parse(result.stdout);
      assert.equal(sarif.version, "2.1.0");
      assert.match(sarif.$schema, /sarif-2\.1\.0/);
      const run = sarif.runs[0];
      assert.equal(run.tool.driver.name, "LeakLens");
      const declared = new Set(run.tool.driver.rules.map((r) => r.id));
      for (const finding of run.results) {
        assert.ok(declared.has(finding.ruleId), `result cites undeclared rule ${finding.ruleId}`);
        assert.ok(["error", "warning", "note"].includes(finding.level));
        const region = finding.locations[0].physicalLocation.region;
        assert.ok(region.startLine >= 1 && region.startColumn >= 1);
      }
      return `${run.results.length} results, ${declared.size} rules declared, every ruleId resolves`;
    },
  },

  // ---- redaction ----
  {
    group: "Redaction",
    name: "secrets are redacted by default",
    fixtureKind: "all-rules",
    args: ["--history"],
    describe: "scanner output reaches CI logs, so full values must never be printed",
    check(result) {
      for (const [name, value] of Object.entries(SECRETS)) {
        if (typeof value !== "string" || value.length < 12) continue;
        assert.ok(!result.stdout.includes(value), `full value of ${name} leaked into output`);
      }
      return "no full secret value appears in the default output";
    },
  },
  {
    group: "Redaction",
    name: "--unsafe-show-secrets prints full values",
    fixtureKind: "all-rules",
    args: ["--unsafe-show-secrets"],
    describe: "the opt-out exists, and is named to discourage casual use",
    check(result) {
      assert.ok(result.stdout.includes(SECRETS.githubToken), "the flag must actually reveal values");
      return "full value shown when explicitly requested";
    },
  },

  // ---- exit codes ----
  {
    group: "Exit codes",
    name: "findings exit 1",
    fixtureKind: "all-rules",
    args: [],
    expectExit: 1,
    describe: "so CI fails when a secret is present",
    check: () => "exit 1",
  },
  {
    group: "Exit codes",
    name: "an unknown flag exits 2",
    fixtureKind: "clean",
    args: ["--not-a-flag"],
    expectExit: 2,
    describe: "usage errors are distinct from findings",
    check(result) {
      assert.match(result.stderr, /unknown option/);
      return "exit 2, names the bad option";
    },
  },
  {
    group: "Exit codes",
    name: "an unknown --format value exits 2",
    fixtureKind: "clean",
    args: ["--format", "xml"],
    expectExit: 2,
    describe: "an unsupported format is rejected rather than silently defaulted",
    check(result) {
      assert.match(result.stderr, /unknown format/);
      return "exit 2, names the bad format";
    },
  },
  {
    group: "Exit codes",
    name: "a missing path exits 2",
    fixtureKind: null,
    args: [],
    expectExit: 2,
    describe: "the scan target is required",
    check(result) {
      assert.match(result.stderr, /missing <path>/);
      return "exit 2, asks for a path";
    },
  },
  {
    group: "Exit codes",
    name: "a target that is not a directory exits 2",
    fixtureKind: null,
    args: ["definitely-not-here"],
    expectExit: 2,
    describe: "an unreadable target is reported, not silently treated as empty",
    check(result) {
      assert.match(result.stderr, /not a directory/);
      return "exit 2, says the target is not a directory";
    },
  },

  // ---- help ----
  {
    group: "Help",
    name: "--help exits 0 and documents every implemented flag",
    fixtureKind: null,
    args: ["--help"],
    expectExit: 0,
    describe: "the help text and the parser cannot drift apart",
    check(result) {
      // Each flag, with a sample argv that should parse cleanly. Value-taking
      // flags need their value, so a single shape cannot cover both kinds.
      const implemented = [
        ["--history", ["--history", "."]],
        ["--format", ["--format", "json", "."]],
        ["--baseline", ["--baseline", "b.json", "."]],
        ["--remediate", ["--remediate", "."]],
        ["--remediate-patch", ["--remediate-patch", "."]],
        ["--out", ["--out", "d", "."]],
        ["--verify", ["--verify", "r.json", "."]],
        ["--unsafe-show-secrets", ["--unsafe-show-secrets", "."]],
        ["--include-vendor", ["--include-vendor", "."]],
        ["--build", ["--build"]],
        ["--prove", ["--prove"]],
      ];
      const undocumented = implemented.map(([flag]) => flag).filter((flag) => !result.stdout.includes(flag));
      assert.deepEqual(undocumented, [], `flags missing from --help: ${undocumented.join(", ")}`);
      for (const [flag, argv] of implemented) {
        assert.equal(parseArgv(argv).error, null,
          `${flag} appears in --help but the parser rejects ${JSON.stringify(argv)}`);
      }
      return `${implemented.length} flags documented and parseable`;
    },
  },

  // ---- proof ----
  {
    group: "Proof",
    name: "--prove passes on our own source",
    fixtureKind: null,
    args: ["--prove"],
    expectExit: 0,
    describe: "zero dependencies, no subprocess, no network reach — checked, not claimed",
    check(result) {
      assert.match(result.stdout, /All checks passed/);
      assert.ok(!/✘/.test(result.stdout), "no check may fail");
      return "8 checks, all passed";
    },
  },

  // ---- baseline ----
  {
    group: "Baseline",
    name: "--baseline suppresses known findings and says how many",
    fixtureKind: "all-rules",
    mutates: true,
    args: null,
    describe: "an accepted finding stops being reported, and the count is disclosed",
    run(dir) {
      const first = runCli([dir, "--format", "json"]);
      const report = JSON.parse(first.stdout);
      const baselinePath = path.join(dir, "..", "baseline.json");
      fs.writeFileSync(baselinePath, JSON.stringify({
        fingerprints: report.findings.map((f) => f.fingerprint),
      }));
      const second = runCli([dir, "--baseline", baselinePath]);
      second.meta = { suppressed: report.findings.length };
      return second;
    },
    check(result) {
      assert.equal(result.exitCode, 0, "everything suppressed means a clean exit");
      assert.match(result.stdout, /No findings/);
      assert.match(result.stdout, /suppressed by baseline/);
      return `${result.meta.suppressed} findings suppressed, exit 0`;
    },
  },

  // ---- verify ----
  {
    group: "Verify",
    name: "the verify loop separates working tree, history and rotation",
    fixtureKind: "acme-checkout",
    mutates: true,
    args: null,
    describe: "an uncommitted secret resolves; committed ones remain; rotation is never claimed",
    run(dir) {
      const before = path.join(dir, "..", "before.json");
      fs.writeFileSync(before, runCli([dir, "--history", "--format", "json"]).stdout);
      // fix only the uncommitted finding, which is the one genuinely resolvable
      const notify = path.join(dir, "src", "notify.js");
      fs.writeFileSync(notify, "const WEBHOOK = process.env.SLACK_WEBHOOK_URL;\n");
      return runCli([dir, "--verify", before]);
    },
    check(result) {
      assert.match(result.stdout, /resolved: +[1-9]/, "the uncommitted fix must count as resolved");
      assert.match(result.stdout, /remaining: +[1-9]/, "committed secrets stay in history");
      assert.match(result.stdout, /rotation: +cannot be verified offline/,
        "the tool must never claim a credential was rotated");
      assert.ok(!/100\/100/.test(result.stdout), "no clean bill of health while history holds a secret");
      return result.stdout.split("\n").filter((l) => /resolved|remaining|working tree|history|rotation/.test(l))
        .map((l) => l.trim()).join(" | ");
    },
  },

  // ---- remediation ----
  {
    group: "Remediate",
    name: "--remediate writes a redacted plan and an env template",
    fixtureKind: "all-rules",
    mutates: true,
    args: null,
    describe: "the plan is safe to share; the env file names variables and holds no values",
    run(dir) {
      const out = fs.mkdtempSync(path.join(os.tmpdir(), "leaklens-out-"));
      const result = runCli([dir, "--remediate", "--out", out]);
      result.meta = { out };
      return result;
    },
    check(result) {
      const planPath = path.join(result.meta.out, "leaklens-remediation.md");
      const envPath = path.join(result.meta.out, "leaklens.env.example");
      assert.ok(fs.existsSync(planPath), "a plan must be written");
      assert.ok(fs.existsSync(envPath), "an env template must be written");
      const plan = fs.readFileSync(planPath, "utf8");
      for (const [name, value] of Object.entries(SECRETS)) {
        if (typeof value !== "string" || value.length < 12) continue;
        assert.ok(!plan.includes(value), `plan leaked the full value of ${name}`);
      }
      const env = fs.readFileSync(envPath, "utf8");
      assert.match(env, /^[A-Z0-9_]+=$/m, "env entries must be names with empty values");
      fs.rmSync(result.meta.out, { recursive: true, force: true, maxRetries: 2 });
      return "plan written and redacted, env template holds names only";
    },
  },
  {
    group: "Remediate",
    name: "a secret-bearing patch is refused inside a git repository",
    fixtureKind: "all-rules",
    mutates: true,
    // "--out ." would resolve against whatever directory the runner happens to
    // be in, which made this pass for the wrong reason. Point it at the scanned
    // repository explicitly, which is the case the guard actually exists for.
    args: null,
    expectExit: 2,
    describe: "the patch holds cleartext secrets, so it must never land where it could be committed",
    run(dir) {
      return runCli([dir, "--remediate-patch", "--out", dir]);
    },
    check(result) {
      assert.match(result.stderr, /refusing to write the patch/);
      assert.match(result.stderr, /is inside a git repository/);
      assert.ok(!/ReferenceError|is not defined/.test(result.stderr), "the guard must not throw");
      assert.ok(!/leaklens-fix\.patch written/i.test(result.stdout), "no patch may be written");
      return "refused, exit 2, repository named, nothing written";
    },
  },

  // ---- vendor ----
  {
    group: "Vendor",
    name: "node_modules is skipped by default and scanned with --include-vendor",
    fixtureKind: "clean",
    mutates: true,
    args: null,
    describe: "other people's code is noise by default, but reachable when asked for",
    setup(dir) {
      fs.mkdirSync(path.join(dir, "node_modules", "pkg"), { recursive: true });
      fs.writeFileSync(path.join(dir, "node_modules", "pkg", "index.js"),
        `const t = "${SECRETS.githubToken}";\n`);
    },
    run(dir) {
      const skipped = runCli([dir, "--format", "json"]);
      const included = runCli([dir, "--include-vendor", "--format", "json"]);
      return { exitCode: 0, stdout: included.stdout, stderr: "", meta: { skipped: skipped.stdout } };
    },
    check(result) {
      const withVendor = JSON.parse(result.stdout).findings;
      const withoutVendor = JSON.parse(result.meta.skipped).findings;
      assert.equal(withoutVendor.length, 0, "node_modules must be skipped by default");
      assert.ok(withVendor.some((f) => f.file.startsWith("node_modules/")),
        "--include-vendor must reach into node_modules");
      return `default 0 findings, --include-vendor ${withVendor.length}`;
    },
  },

  // ---- build ----
  {
    group: "Build",
    name: "two builds produce byte-identical output",
    fixtureKind: null,
    args: null,
    describe: "no timestamp, path or hostname may reach the artifact",
    run() {
      const base = fs.mkdtempSync(path.join(os.tmpdir(), "leaklens-build-"));
      const first = runCli(["--build", path.join(base, "a")]);
      const second = runCli(["--build", path.join(base, "b")]);
      const readSums = (which) => fs.readFileSync(path.join(base, which, "SHA256SUMS"), "utf8");
      const result = {
        exitCode: first.exitCode || second.exitCode,
        stdout: `${readSums("a")}${readSums("b")}`,
        stderr: "",
        meta: {
          a: readSums("a"), b: readSums("b"),
          same: fs.readFileSync(path.join(base, "a", "leaklens.mjs")).equals(
            fs.readFileSync(path.join(base, "b", "leaklens.mjs"))),
        },
      };
      fs.rmSync(base, { recursive: true, force: true, maxRetries: 2 });
      return result;
    },
    check(result) {
      assert.equal(result.exitCode, 0);
      assert.equal(result.meta.a, result.meta.b, "the two SHA256SUMS must match");
      assert.ok(result.meta.same, "the two artifacts must be byte-identical");
      return result.meta.a.trim();
    },
  },
];

// ===== runner =====

function execute(testCase, dir) {
  if (testCase.run) return testCase.run(dir);
  const args = dir ? [dir, ...testCase.args] : [...testCase.args];
  return runCli(args);
}

for (const testCase of CASES) {
  const needsGit = testCase.fixtureKind !== null;
  test(`e2e [${testCase.group}] ${testCase.name}`, { skip: needsGit && !hasGit }, (t) => {
    let dir = null;
    if (testCase.fixtureKind) {
      dir = fixture(testCase.fixtureKind);
      // Anything that writes gets its own copy, so case order never matters and
      // a mutating case cannot poison a later read-only one.
      if (testCase.setup || testCase.mutates) {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), "leaklens-case-"));
        t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
        fs.cpSync(fixture(testCase.fixtureKind), dir, { recursive: true });
        if (testCase.setup) testCase.setup(dir);
      }
    }
    const result = execute(testCase, dir);
    if (testCase.expectExit !== undefined) {
      assert.equal(result.exitCode, testCase.expectExit,
        `expected exit ${testCase.expectExit}, got ${result.exitCode}\n${result.stderr}`);
    }
    testCase.check(result);
  });
}
