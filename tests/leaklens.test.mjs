// LeakLens test suite — node:test + node:assert only.
// git is used as a *test oracle* to build fixtures (never a runtime dependency);
// fixture tests skip cleanly when git is absent.

import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  parseArgv, makeIgnore, shannonEntropy, githubChecksum, validateGithubToken,
  awsAccountId, isPlaceholder, scanText, classify, scan, redact,
  applyDelta, securityScore, looksBinary, walkFiles, buildSelf, proveDependencies,
  RULES,
} from "../leaklens.mjs";
import { SECRETS } from "./fixtures.mjs";

// ---- fixture secret factory: fake entropy, valid checksums, never real ----

const FAKE_ENTROPY = "abcdefghijklmnopqrstuvwxyz1234"; // 30 chars, fixed seed
const ghpValid = () => "ghp_" + FAKE_ENTROPY + githubChecksum(FAKE_ENTROPY);
const ghpInvalid = () => "ghp_" + FAKE_ENTROPY + "000000";
const fakeAws = "AKIA" + "ABCDEFGHIJKLMNOP"; // base32 body, fake
const fakeStripe = "sk" + "_live_" + "FaKeFaKeFaKeFaKeFaKe1234";
const fakeStripeTest = "sk" + "_test_" + "FaKeFaKeFaKeFaKeFaKe1234";
// high-entropy, Stripe-prefixed, but inside a lockfile — must stay unreported
const lockfileNoise = "sk" + "_live_" + "notAKeyBecauseLockfileWait";

const scanOpts = { history: false, includeVendor: false, showSecrets: false };
const classified = (text, file = "config.js") =>
  classify(scanText(text, { file, source: "tree" }), scanOpts).findings;

// ===== ARGV =====

test("argv: flags and positional", () => {
  const o = parseArgv(["./repo", "--history", "--format", "json", "--unsafe-show-secrets"]);
  assert.equal(o.path, "./repo");
  assert.equal(o.history, true);
  assert.equal(o.format, "json");
  assert.equal(o.showSecrets, true);
  assert.equal(o.error, null);
});

test("argv: unknown flag and bad format are errors", () => {
  assert.ok(parseArgv(["--nope"]).error);
  assert.ok(parseArgv(["--format", "xml"]).error);
  assert.ok(parseArgv(["--format"]).error);
});

test("argv: --remediate-patch implies --remediate", () => {
  const o = parseArgv([".", "--remediate-patch"]);
  assert.equal(o.remediate, true);
  assert.equal(o.remediatePatch, true);
});

// ===== IGNORE MATCHER =====

test("ignore: basic glob, dir-only, negation, anchoring", () => {
  const ig = makeIgnore(["*.log", "build/", "!keep.log", "/root-only.txt", "docs/**/*.tmp"]);
  assert.equal(ig("a/b.log", false), true);
  assert.equal(ig("keep.log", false), false);
  assert.equal(ig("build", true), true);
  assert.equal(ig("build", false), false); // dir-only pattern, file named build
  assert.equal(ig("root-only.txt", false), true);
  assert.equal(ig("sub/root-only.txt", false), false); // anchored
  assert.equal(ig("docs/a/b/c.tmp", false), true);
  assert.equal(ig("other/a.tmp", false), false);
});

test("ignore: character classes and ?", () => {
  const ig = makeIgnore(["file?.txt", "v[0-9].md"]);
  assert.equal(ig("file1.txt", false), true);
  assert.equal(ig("file12.txt", false), false);
  assert.equal(ig("v3.md", false), true);
  assert.equal(ig("vx.md", false), false);
});

// ===== DETECT PRIMITIVES =====

test("shannon entropy sanity", () => {
  assert.equal(shannonEntropy("aaaa"), 0);
  assert.ok(shannonEntropy("Kj8#pQz2mN9xR4vB") > 3.5);
});

test("github token: valid checksum detected, invalid dropped", () => {
  assert.equal(validateGithubToken(ghpValid()), true);
  assert.equal(validateGithubToken(ghpInvalid()), false);
  const hits = classified(`const token = "${ghpValid()}";`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, "github-token-classic");
  assert.equal(hits[0].severity, "critical");
  assert.equal(classified(`const token = "${ghpInvalid()}";`).length, 0);
});

test("aws: account id derivation round-trips and enriches finding", () => {
  const acct = awsAccountId(fakeAws);
  assert.match(acct, /^\d{12}$/);
  const hits = classified(`aws_key = "${fakeAws}"`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, "aws-access-key-id");
  assert.ok(hits[0].note.includes(acct));
});

test("aws: documented example key is suppressed", () => {
  assert.equal(isPlaceholder("AKIAIOSFODNN7EXAMPLE"), true);
  assert.equal(classified('key = "AKIAIOSFODNN7EXAMPLE"').length, 0);
});

test("jwt: jwt.io sample suppressed, alg none is critical", () => {
  const sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  assert.equal(classified(`auth = "${sample}"`).length, 0);
  const hdr = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const pay = Buffer.from(JSON.stringify({ sub: "u1", admin: true })).toString("base64url");
  const noneJwt = `${hdr}.${pay}.x`;
  const hits = classified(`token = "${noneJwt}"`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "critical");
  assert.ok(hits[0].note.includes("none"));
});

test("stripe: live critical, test downgraded", () => {
  const live = classified(`key = "${fakeStripe}"`);
  assert.equal(live[0].severity, "critical");
  const testKey = classified(`key = "${fakeStripeTest}"`);
  assert.equal(testKey[0].severity, "low");
});

test("pem private key detected", () => {
  const hits = classified("-----BEGIN RSA PRIVATE KEY-----\nMIIfake\n-----END RSA PRIVATE KEY-----\n", "deploy/id_rsa");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, "pem-private-key");
});

test("connection uri: real password flagged, trivial password not", () => {
  assert.equal(classified('url = "postgres://app:s3cr3tP4ssw0rdXY@db.prod.internal:5432/app"').length, 1);
  assert.equal(classified('url = "postgres://app:password@db.prod.internal/app"').length, 0);
  const local = classified('url = "postgres://app:s3cr3tP4ssw0rdXY@localhost/app"');
  assert.equal(local[0].severity, "medium");
});

test("entropy tier: needs context signal, ignores shas/uuids/lockfiles", () => {
  const secretish = 'const apiSecret = "zX9kQ2mP8vR4nB7jW3tY6uI1oL5eD0aS";';
  assert.equal(classified(secretish).length, 1);
  // same token, no secret-ish context, non-env file → silence
  assert.equal(classified('const banner = "zX9kQ2mP8vR4nB7jW3tY6uI1oL5eD0aS";').length, 0);
  assert.equal(classified('token = "0123456789abcdef0123456789abcdef01234567"').length, 0); // 40-hex sha
  assert.equal(classified('secret = "d3b07384-d9a7-4f2a-8b1e-1a2b3c4d5e6f"').length, 0); // uuid
  assert.equal(
    classify(scanText(`integrity: "${lockfileNoise}"`, { file: "package-lock.json", source: "tree" })
      .filter((f) => f.rule === "generic-high-entropy"), scanOpts).findings.length, 0);
});

test("false-positive corpus produces zero findings", () => {
  const corpus = [
    'password = "changeme"',
    'token = "your_api_key_here"',
    'secret = "${SECRET_FROM_ENV}"',
    'apiKey = "{{ vault_api_key }}"',
    'key = process.env.API_KEY',
    'password = "xxxxxxxxxxxx"',
    'secret = "<insert-token>"',
    'const example = "AKIAIOSFODNN7EXAMPLE";',
  ].join("\n");
  assert.equal(classified(corpus).length, 0);
});

test("redaction: full value absent by default", () => {
  const tok = ghpValid();
  const hits = classified(`t = "${tok}"`);
  assert.ok(!hits[0].redacted.includes(tok.slice(8, 30)));
  assert.equal(redact("short"), "*****");
});

test("line/col are correct", () => {
  const hits = classified(`// comment\n\nconst k = "${fakeStripe}";\n`);
  assert.equal(hits[0].line, 3);
  assert.equal(hits[0].col, 'const k = "'.length + 1);
});

test("dedupe: same secret twice in one file reported once, fixture path downgraded", () => {
  const tok = ghpValid();
  assert.equal(classified(`a = "${tok}"\nb = "${tok}"`).length, 1);
  const fx = classify(scanText(`t = "${tok}"`, { file: "tests/fixtures/seed.js", source: "tree" }), scanOpts).findings;
  assert.equal(fx[0].severity, "high"); // downgraded from critical, not dropped
});

test("score formula", () => {
  assert.equal(securityScore([]), 100);
  assert.equal(securityScore([{ severity: "critical" }, { severity: "low" }]), 74);
});

test("applyDelta: copy + insert + guards", () => {
  const base = Buffer.from("hello world, hello git");
  // src size, dst size varints then: copy(0,5) + insert " git"
  const delta = Buffer.from([base.length, 9, 0x91, 0x00, 0x05, 4, 0x20, 0x67, 0x69, 0x74]);
  assert.equal(applyDelta(base, delta).toString(), "hello git");
  assert.throws(() => applyDelta(Buffer.from("x"), Buffer.from([5, 1, 0x00])), /size mismatch|reserved/);
});

test("binary sniff", () => {
  assert.equal(looksBinary(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x0d])), true);
  assert.equal(looksBinary(Buffer.from("plain text\n")), false);
});

// ===== GIT FIXTURES (oracle: real git; skipped when unavailable) =====

let hasGit = true;
try { execFileSync("git", ["--version"], { stdio: "ignore" }); } catch { hasGit = false; }

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "LeakLens Fixture", GIT_AUTHOR_EMAIL: "fixture@leaklens.test",
  GIT_COMMITTER_NAME: "LeakLens Fixture", GIT_COMMITTER_EMAIL: "fixture@leaklens.test",
  GIT_AUTHOR_DATE: "2026-01-01T00:00:00Z", GIT_COMMITTER_DATE: "2026-01-01T00:00:00Z",
  // empty config file — os.devNull breaks git on Windows ("//./nul")
  GIT_CONFIG_GLOBAL: path.join(os.tmpdir(), "leaklens-empty-gitconfig"),
  GIT_CONFIG_SYSTEM: path.join(os.tmpdir(), "leaklens-empty-gitconfig"),
};
fs.writeFileSync(GIT_ENV.GIT_CONFIG_GLOBAL, "");
const git = (cwd, ...args) => execFileSync("git", ["-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", ...args], { cwd, env: GIT_ENV, stdio: "pipe" }).toString();

function tmpRepo(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "leaklens-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
  git(dir, "init", "-q", "-b", "main");
  return dir;
}
const findingsOf = (dir, opts = {}) => scan(dir, { ...scanOpts, ...opts }).findings;

test("F1: working-tree secret found with location", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, "config.js"), `const token = "${ghpValid()}";\n`);
  git(dir, "add", "."); git(dir, "commit", "-qm", "add config");
  const f = findingsOf(dir);
  assert.equal(f.length, 1);
  assert.equal(f[0].file, "config.js");
  assert.equal(f[0].line, 1);
  assert.equal(f[0].source, "tree");
});

test("F2: secret deleted from HEAD still found with --history", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, "config.js"), `const token = "${ghpValid()}";\n`);
  git(dir, "add", "."); git(dir, "commit", "-qm", "add secret");
  fs.writeFileSync(path.join(dir, "config.js"), "const token = process.env.GITHUB_TOKEN;\n");
  git(dir, "commit", "-aqm", "remove secret");
  assert.equal(findingsOf(dir).length, 0); // default scan clean
  const hist = findingsOf(dir, { history: true });
  assert.equal(hist.length, 1);
  assert.equal(hist[0].source, "history");
  assert.equal(hist[0].atHead, false);
  assert.equal(hist[0].reachable, true);
  assert.ok(hist[0].commit);
  assert.equal(hist[0].author, "LeakLens Fixture");
});

test("F3: amended-away secret is unreachable yet found", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, "app.js"), `const key = "${fakeStripe}";\n`);
  git(dir, "add", "."); git(dir, "commit", "-qm", "oops");
  fs.writeFileSync(path.join(dir, "app.js"), "const key = process.env.STRIPE_SECRET_KEY;\n");
  git(dir, "add", "."); git(dir, "commit", "-q", "--amend", "-m", "clean");
  // the oracle git relies on: git log -p sees nothing
  assert.ok(!git(dir, "log", "--all", "-p").includes(fakeStripe));
  const hist = findingsOf(dir, { history: true });
  const hit = hist.find((f) => f.rule === "stripe-secret-key");
  assert.ok(hit, "amended-away secret must be found");
  assert.equal(hit.reachable, false);
});

test("F4: packed repo (git gc) — same findings, incl. unreachable", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, "app.js"), `const key = "${fakeStripe}";\n`);
  git(dir, "add", "."); git(dir, "commit", "-qm", "oops");
  fs.writeFileSync(path.join(dir, "app.js"), "clean\n");
  git(dir, "add", "."); git(dir, "commit", "-q", "--amend", "-m", "clean");
  git(dir, "gc", "-q"); // packs objects; no prune of recent unreachables
  assert.ok(fs.readdirSync(path.join(dir, ".git", "objects", "pack")).some((f) => f.endsWith(".idx")));
  const hit = findingsOf(dir, { history: true }).find((f) => f.rule === "stripe-secret-key");
  assert.ok(hit, "secret must survive packing");
  assert.equal(hit.reachable, false);
});

test("F5: delta-compressed objects resolve correctly", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  const page = "x".repeat(600) + "\n";
  for (let i = 0; i < 30; i++) {
    const secret = i === 13 ? `key = "${fakeStripe}"\n` : "";
    fs.writeFileSync(path.join(dir, "big.txt"), page.repeat(10) + secret + `version ${i}\n`);
    git(dir, "add", "."); git(dir, "commit", "-qm", `v${i}`);
  }
  git(dir, "gc", "-q", "--aggressive");
  const hit = findingsOf(dir, { history: true }).find((f) => f.rule === "stripe-secret-key");
  assert.ok(hit, "secret inside a delta chain must be found");
  assert.equal(hit.file, "big.txt");
});

test("F6: truncated pack does not crash the scan", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, "a.txt"), "hello\n");
  git(dir, "add", "."); git(dir, "commit", "-qm", "one");
  git(dir, "gc", "-q");
  const packDir = path.join(dir, ".git", "objects", "pack");
  for (const f of fs.readdirSync(packDir)) {
    if (f.endsWith(".pack")) {
      const p = path.join(packDir, f);
      fs.chmodSync(p, 0o644); // git writes packs read-only
      fs.writeFileSync(p, fs.readFileSync(p).subarray(0, 20)); // truncate hard
    }
  }
  const result = scan(dir, { ...scanOpts, history: true });
  assert.ok(Array.isArray(result.findings)); // survived
  assert.ok(result.notes.length > 0, "corruption must be noted, not hidden");
});

test("self-scan: this repo has no unbaselined critical findings", () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..");
  const result = scan(root, scanOpts);
  const bad = result.findings.filter((f) => f.severity === "critical");
  assert.deepEqual(bad, []);
});

// ===== ZERO-DEPENDENCY / ZERO-SHELL-OUT PROOF =====
// Track A's stated disqualifier is "an empty manifest that shells out to
// separately-installed tools" — which is exactly how gitleaks reads history.
// This test makes our claim runnable rather than rhetorical.

const IMPL = fs.readFileSync(new URL("../leaklens.mjs", import.meta.url), "utf8");

test("proof: every import in leaklens.mjs is a node: built-in", () => {
  const specs = [...IMPL.matchAll(/^import\s+.*?from\s+["']([^"']+)["']/gm)].map((m) => m[1]);
  assert.ok(specs.length > 0, "no imports found — regex is wrong, not the file");
  for (const spec of specs) assert.match(spec, /^node:/, `non-builtin import: ${spec}`);
});

test("proof: leaklens.mjs never shells out and loads nothing at runtime", () => {
  const banned = [
    [/child_process/, "child_process — we parse .git ourselves, never call git"],
    [/\brequire\s*\(/, "require() — no CommonJS escape hatch"],
    [/\bimport\s*\(/, "dynamic import() — nothing loaded at runtime"],
    [/process\.binding/, "process.binding — no internal escape hatch"],
    [/\bcreateRequire\b/, "createRequire — no CommonJS escape hatch"],
  ];
  for (const [rx, why] of banned) assert.equal(rx.test(IMPL), false, why);
});

test("proof: no network primitive is reachable from the implementation", () => {
  // The offline guarantee is a property of the source, not a runtime setting.
  for (const rx of [/node:https?/, /node:net/, /node:dgram/, /\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/]) {
    assert.equal(rx.test(IMPL), false, `network primitive found: ${rx}`);
  }
});

test("proof: implementation avoids Node-22-only APIs, so it runs on Node 20", () => {
  // We hand-rolled these substitutions; using the built-ins would raise our floor to v22.
  for (const rx of [/fs\.globSync/, /styleText/, /util\.parseArgs/, /loadEnvFile/]) {
    assert.equal(rx.test(IMPL), false, `v22-only API used: ${rx}`);
  }
});

// ===== IGNORE SEMANTICS AND CONTEXT DETECTION =====
// These lock in two behaviours that were wrong once and are easy to break again.

test("ignore: nested .gitignore applies below its own directory", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "leaklens-nested-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
  fs.mkdirSync(path.join(dir, "app", "build"), { recursive: true });
  fs.mkdirSync(path.join(dir, "other"), { recursive: true });
  // only app/ ignores build output; other/ must be unaffected
  fs.writeFileSync(path.join(dir, "app", ".gitignore"), "build/\n");
  fs.writeFileSync(path.join(dir, "app", "build", "bundle.js"), "x\n");
  fs.writeFileSync(path.join(dir, "app", "src.js"), "x\n");
  fs.writeFileSync(path.join(dir, "other", "keep.js"), "x\n");

  const walked = walkFiles(dir, scanOpts, []);
  assert.ok(!walked.includes("app/build/bundle.js"), "nested .gitignore must exclude app/build");
  assert.ok(walked.includes("app/src.js"));
  assert.ok(walked.includes("other/keep.js"), "nested rule must not leak into sibling dirs");
});

test("ignore: a nested negation re-includes what a parent excluded", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "leaklens-neg-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
  fs.mkdirSync(path.join(dir, "pkg"), { recursive: true });
  fs.writeFileSync(path.join(dir, ".gitignore"), "*.log\n");
  fs.writeFileSync(path.join(dir, "pkg", ".gitignore"), "!keep.log\n");
  fs.writeFileSync(path.join(dir, "drop.log"), "x\n");
  fs.writeFileSync(path.join(dir, "pkg", "keep.log"), "x\n");

  const walked = walkFiles(dir, scanOpts, []);
  assert.ok(!walked.includes("drop.log"), "parent rule still applies where unopposed");
  assert.ok(walked.includes("pkg/keep.log"), "deeper negation must win beneath its directory");
});

test("ignore: credential files are scanned even when gitignored", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "leaklens-env-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
  fs.mkdirSync(path.join(dir, "server"), { recursive: true });
  fs.writeFileSync(path.join(dir, ".gitignore"), ".env\nserver/.env\n*.pem\nbuild/\n");
  fs.writeFileSync(path.join(dir, "server", ".env"), `TOKEN=${ghpValid()}\n`);
  fs.writeFileSync(path.join(dir, "key.pem"), "-----BEGIN RSA PRIVATE KEY-----\nMII\n");
  fs.mkdirSync(path.join(dir, "build"), { recursive: true });
  fs.writeFileSync(path.join(dir, "build", "out.js"), "x\n");

  const walked = walkFiles(dir, scanOpts, []);
  // gitignored is not the same as safe: these are the files most likely to hold a real key
  assert.ok(walked.includes("server/.env"), ".env must be scanned despite .gitignore");
  assert.ok(walked.includes("key.pem"), ".pem must be scanned despite .gitignore");
  assert.ok(!walked.includes("build/out.js"), "ordinary ignored build output stays ignored");

  const found = scan(dir, scanOpts).findings;
  assert.ok(found.some((f) => f.file === "server/.env" && f.rule === "github-token-classic"));
});

test("context: substrings of ordinary words do not create a secret context", () => {
  const entropy = "zX9kQ2mP8vR4nB7jW3tY6uI1oL5eD0aS";
  for (const word of ["unauthorized", "tokenizer", "author", "authored"]) {
    assert.equal(classified(`const ${word} = "${entropy}";`).length, 0, `${word} must not fire`);
  }
});

test("context: snake, kebab, upper and camel spellings all fire", () => {
  const entropy = "zX9kQ2mP8vR4nB7jW3tY6uI1oL5eD0aS";
  const contexts = [
    `const access_token = "${entropy}";`,
    `api-key: ${entropy}`,
    `API_KEY=${entropy}`,
    `Authorization: ${entropy}`,
    `const apiSecret = "${entropy}";`,
    `const authToken = "${entropy}";`,
    `const dbPassword = "${entropy}";`,
  ];
  for (const line of contexts) {
    assert.equal(classified(line).length, 1, `should fire: ${line}`);
  }
});

// ===== HOSTILE INPUT =====
// Every row of the F6 table in the design notes. A repository is attacker-
// controlled input: the scan must degrade with a recorded note, never crash and
// never silently skip. "No findings" and "could not read this" are different
// answers, and the report has to distinguish them.

// git marks loose objects and packfiles read-only; corruption tests chmod first.
function overwrite(filePath, buf) {
  fs.chmodSync(filePath, 0o644);
  fs.writeFileSync(filePath, buf);
}
function eachLooseObject(dir, fn) {
  const objectsDir = path.join(dir, ".git", "objects");
  for (const prefix of fs.readdirSync(objectsDir)) {
    if (!/^[0-9a-f]{2}$/.test(prefix)) continue;
    for (const rest of fs.readdirSync(path.join(objectsDir, prefix))) {
      fn(path.join(objectsDir, prefix, rest));
    }
  }
}
const historyOpts = { ...scanOpts, history: true };
const tmpDir = (t, tag) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `leaklens-${tag}-`));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
  return dir;
};

test("hostile: directory that is not a repository", (t) => {
  const dir = tmpDir(t, "norepo");
  const result = scan(dir, historyOpts);
  assert.deepEqual(result.findings, []);
  assert.ok(result.notes.some((n) => n.includes("no .git")), "must say why history was skipped");
});

test("hostile: empty repo and bare repo", { skip: !hasGit }, (t) => {
  assert.doesNotThrow(() => scan(tmpRepo(t), historyOpts));
  const bare = tmpDir(t, "bare");
  git(bare, "init", "-q", "--bare", "-b", "main");
  assert.doesNotThrow(() => scan(bare, historyOpts));
});

test("hostile: .git file pointing at a missing gitdir", (t) => {
  const dir = tmpDir(t, "gitfile");
  fs.writeFileSync(path.join(dir, ".git"), "gitdir: /definitely/not/here\n");
  assert.doesNotThrow(() => scan(dir, historyOpts));
});

test("hostile: HEAD points at a ref that does not exist", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, ".git", "HEAD"), "ref: refs/heads/nope\n");
  assert.doesNotThrow(() => scan(dir, historyOpts));
});

test("hostile: corrupt zlib stream is noted, scan continues", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, "a.txt"), "hello\n");
  git(dir, "add", "."); git(dir, "commit", "-qm", "one");
  eachLooseObject(dir, (p) => overwrite(p, Buffer.from("not a zlib stream")));
  const result = scan(dir, historyOpts);
  assert.ok(result.notes.some((n) => n.includes("corrupt loose object")));
});

test("hostile: object whose SHA-1 disagrees with its path is not trusted", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, "a.txt"), "hello\n");
  git(dir, "add", "."); git(dir, "commit", "-qm", "one");
  let replaced = false;
  eachLooseObject(dir, (p) => {
    if (replaced) return;
    // valid zlib, valid object header, wrong content for this filename
    const header = Buffer.from("blob 5" + String.fromCharCode(0) + "WRONG");
    overwrite(p, zlib.deflateSync(header));
    replaced = true;
  });
  const result = scan(dir, historyOpts);
  assert.ok(result.notes.some((n) => n.includes("sha mismatch")), "must refuse unverified content");
});

test("hostile: truncated pack index is skipped with a note", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  fs.writeFileSync(path.join(dir, "a.txt"), "hello\n");
  git(dir, "add", "."); git(dir, "commit", "-qm", "one");
  git(dir, "gc", "-q");
  const packDir = path.join(dir, ".git", "objects", "pack");
  for (const f of fs.readdirSync(packDir)) {
    if (!f.endsWith(".idx")) continue;
    const p = path.join(packDir, f);
    overwrite(p, fs.readFileSync(p).subarray(0, 100));
  }
  const result = scan(dir, historyOpts);
  assert.ok(result.notes.some((n) => n.includes("pack index")), "unreadable index must be reported");
});

test("hostile: unsupported pack index version is declined clearly", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  const packDir = path.join(dir, ".git", "objects", "pack");
  fs.mkdirSync(packDir, { recursive: true });
  const fake = Buffer.alloc(1032 + 40);
  fake.writeUInt32BE(0xff744f63, 0); // correct magic
  fake.writeUInt32BE(3, 4);          // a version we do not support
  fs.writeFileSync(path.join(packDir, "pack-fake.idx"), fake);
  const result = scan(dir, historyOpts);
  assert.ok(result.notes.some((n) => /index version 3/.test(n)), "must name the unsupported version");
});

test("hostile: garbage in the loose object directory", { skip: !hasGit }, (t) => {
  const dir = tmpRepo(t);
  const sub = path.join(dir, ".git", "objects", "ab");
  fs.mkdirSync(sub, { recursive: true });
  fs.writeFileSync(path.join(sub, "c".repeat(38)), "not an object");
  assert.doesNotThrow(() => scan(dir, historyOpts));
});

test("hostile: odd encodings and enormous lines do not crash", (t) => {
  const dir = tmpDir(t, "enc");
  const BOM = String.fromCharCode(0xfeff);
  const LONE_SURROGATE = String.fromCharCode(0xd800);
  fs.writeFileSync(path.join(dir, "utf16.txt"), Buffer.from(BOM + "password = secret", "utf16le"));
  fs.writeFileSync(path.join(dir, "crlf.txt"), 'line1\r\napi_key = "' + LONE_SURROGATE + 'abc"\r\n');
  fs.writeFileSync(path.join(dir, "min.js"), "var x=" + "a".repeat(600_000) + ";");
  fs.writeFileSync(path.join(dir, "--history"), "password = hunter2\n"); // filename looks like a flag
  assert.doesNotThrow(() => scan(dir, scanOpts));
});

test("hostile: malformed .gitignore lines are tolerated", (t) => {
  const dir = tmpDir(t, "badignore");
  fs.writeFileSync(path.join(dir, ".gitignore"), "\n\n#c\n!\n[\n***\n   \n[a-\n");
  fs.writeFileSync(path.join(dir, "a.txt"), "hello\n");
  assert.doesNotThrow(() => walkFiles(dir, scanOpts, []));
});

// ===== BUILD AND PROOF =====

test("build: two builds of the same source are byte-identical", (t) => {
  const dir = tmpDir(t, "build");
  const first = buildSelf(path.join(dir, "a"), { silent: true });
  const second = buildSelf(path.join(dir, "b"), { silent: true });
  assert.equal(first.digest, second.digest, "the build must embed no timestamp, path, or host");
  assert.deepEqual(fs.readFileSync(first.artifactPath), fs.readFileSync(second.artifactPath));
  // and the artifact must be a real module, not a truncated copy
  assert.match(fs.readFileSync(first.artifactPath, "utf8"), /export function scanText/);
});

test("proof: the dependency audit passes on our own source", () => {
  assert.equal(proveDependencies({ silent: true }), true);
});

// ===== PATCH GUARD =====
// The refusal path lives in main() and ends in process.exit, so it has to be
// exercised as a real process. It went untested once and drifted into a
// ReferenceError that only fired when a user did the right thing and pointed
// --out somewhere unsafe. A security guard that crashes is a guard that failed.

const IMPL_PATH = fileURLToPath(new URL("../leaklens.mjs", import.meta.url));

function runCli(args, cwd) {
  try {
    const stdout = execFileSync(process.execPath, [IMPL_PATH, ...args], {
      cwd, env: { ...process.env, NO_COLOR: "1" }, stdio: "pipe",
    });
    return { status: 0, stdout: stdout.toString(), stderr: "" };
  } catch (err) {
    return {
      status: err.status,
      stdout: (err.stdout ?? "").toString(),
      stderr: (err.stderr ?? "").toString(),
    };
  }
}

test("patch guard: refuses to write a secret-bearing patch inside a git repo", { skip: !hasGit }, (t) => {
  const repo = tmpRepo(t);
  fs.writeFileSync(path.join(repo, "config.js"), `const token = "${ghpValid()}";\n`);
  git(repo, "add", "."); git(repo, "commit", "-qm", "add config");

  // --out points at the scanned repository itself: the worst possible destination
  const result = runCli([repo, "--remediate-patch", "--out", repo], repo);

  assert.equal(result.status, 2, "must exit with a usage error, not crash");
  assert.match(result.stderr, /refusing to write the patch/);
  assert.match(result.stderr, /is inside a git repository/);
  assert.ok(!/ReferenceError|is not defined/.test(result.stderr), "the guard itself must not throw");
  // it names the offending repository so the user knows what to change
  assert.ok(result.stderr.includes(repo), "must name the repository it refused to write into");
  assert.ok(!fs.existsSync(path.join(repo, "leaklens-fix.patch")), "no patch may be left behind");
});

test("patch guard: writes the patch when --out is outside any repository", { skip: !hasGit }, (t) => {
  const repo = tmpRepo(t);
  fs.writeFileSync(path.join(repo, "config.js"), `const token = "${ghpValid()}";\n`);
  git(repo, "add", "."); git(repo, "commit", "-qm", "add config");
  const outside = tmpDir(t, "patch-out"); // a plain temp dir, not a repo

  const result = runCli([repo, "--remediate-patch", "--out", outside], outside);

  assert.equal(result.status, 1, "findings present, so exit 1");
  const patchPath = path.join(outside, "leaklens-fix.patch");
  assert.ok(fs.existsSync(patchPath), "the patch should be written when the destination is safe");
  assert.match(result.stderr, /do not commit/i, "must warn that the patch holds cleartext secrets");
  // the patch necessarily contains the secret; that is why the guard exists
  assert.match(fs.readFileSync(patchPath, "utf8"), /process\.env\.GITHUB_TOKEN/);
});

// ===== PER-RULE DETECTION =====
// One case per shipped rule. The fixture credentials are assembled from
// fragments in fixtures.mjs, so no key-shaped literal reaches the repository.

const ruleCases = [
  ["github-pat-fine-grained", "critical", (s) => `const t = "${s.githubFineGrained}";`],
  ["aws-secret-access-key", "critical", (s) => `aws_secret_access_key = "${s.awsSecret}"`],
  ["slack-token", "high", (s) => `const bot = "${s.slackToken}";`],
  ["slack-webhook", "medium", (s) => `const url = "${s.slackWebhook}";`],
  ["google-api-key", "medium", (s) => `const key = "${s.googleApiKey}";`],
  ["anthropic-api-key", "critical", (s) => `const key = "${s.anthropicKey}";`],
  ["openai-api-key", "critical", (s) => `const key = "${s.openaiKey}";`],
  ["npm-token", "high", (s) => `const t = "${s.npmToken}";`],
  ["sendgrid-api-key", "high", (s) => `const key = "${s.sendgridKey}";`],
  ["twilio-api-key", "high", (s) => `const sid = "${s.twilioKey}";`],
];

for (const [ruleId, expectedSeverity, makeLine] of ruleCases) {
  test(`rule ${ruleId}: fires with severity ${expectedSeverity}`, () => {
    const hits = classified(makeLine(SECRETS), "src/providers.js");
    const hit = hits.find((f) => f.rule === ruleId);
    assert.ok(hit, `${ruleId} did not fire on its own sample`);
    assert.equal(hit.severity, expectedSeverity);
    assert.ok(!hit.redacted.includes(hit.value), "the finding must carry a redacted form");
  });
}

test("every rule ships a remediation path", () => {
  // The submission checklist says no rule ships without a fix path. This is the
  // check that keeps that true as rules are added.
  const incomplete = RULES.filter((rule) =>
    !Array.isArray(rule.advice) || rule.advice.length === 0 ||
    !rule.reference || !rule.severity || rule.envName === undefined);
  assert.deepEqual(incomplete.map((r) => r.id), [], "rules missing advice, reference, severity or envName");
});

test("every rule id is unique and kebab-case", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate rule id");
  for (const id of ids) assert.match(id, /^[a-z0-9]+(-[a-z0-9]+)*$/, `not kebab-case: ${id}`);
});

test("every rule pattern is global, or matchAll would throw", () => {
  for (const rule of RULES) {
    assert.ok(rule.pattern.global, `${rule.id} pattern must carry the g flag`);
  }
});
