// Purpose-built repositories for the end-to-end suite, and for the demo video.
//
// Two rules govern this file:
//
//  1. No credential-shaped literal may appear in the source. Every fake value is
//     assembled from fragments at runtime. GitHub's push protection scans the
//     committed blob, not the runtime value, and it blocked this repository's
//     first push over exactly this. A secret scanner whose own repo trips secret
//     scanners is also a bad look on its own merits.
//
//  2. Nothing here is, or ever was, a real credential. The GitHub token carries a
//     genuine checksum — computed with the tool's own githubChecksum — so the
//     offline validation path is exercised rather than bypassed.
//
// ponytail: the git helpers below duplicate a few lines from leaklens.test.mjs.
// Sharing them would mean refactoring a passing suite; the duplication is cheaper
// than the churn. Merge them if a third consumer ever appears.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { githubChecksum } from "../leaklens.mjs";

// ===== git plumbing =====

const GIT_CONFIG_STUB = path.join(os.tmpdir(), "leaklens-fixture-gitconfig");
try { fs.writeFileSync(GIT_CONFIG_STUB, ""); } catch {}

// Pinned identity and dates, so object shas are identical on every machine.
export const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "Priya Raman", GIT_AUTHOR_EMAIL: "priya@acme.example",
  GIT_COMMITTER_NAME: "Priya Raman", GIT_COMMITTER_EMAIL: "priya@acme.example",
  GIT_AUTHOR_DATE: "2026-08-14T09:20:00Z", GIT_COMMITTER_DATE: "2026-08-14T09:20:00Z",
  GIT_CONFIG_GLOBAL: GIT_CONFIG_STUB, GIT_CONFIG_SYSTEM: GIT_CONFIG_STUB,
};

export function git(cwd, ...args) {
  return execFileSync(
    "git",
    ["-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", ...args],
    { cwd, env: GIT_ENV, stdio: "pipe" },
  ).toString();
}

export const hasGit = (() => {
  try { execFileSync("git", ["--version"], { stdio: "ignore" }); return true; }
  catch { return false; }
})();

// ===== fake credentials =====

const join = (...parts) => parts.join("");
const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

// Every value below is deliberately varied in character (isPlaceholder rejects
// anything with two or fewer distinct characters) and avoids the words
// "example", "sample", "dummy", "mock" and "fake", which downgrade severity when
// they appear in the surrounding line.
export const SECRETS = {
  // 30 entropy chars + 6 base62 checksum = the 36 the rule expects
  githubToken: join("gh", "p_", "abcdefghijklmnopqrstuvwxyz1234", githubChecksum("abcdefghijklmnopqrstuvwxyz1234")),
  githubTokenBadChecksum: join("gh", "p_", "abcdefghijklmnopqrstuvwxyz1234", "000000"),
  githubFineGrained: join("github", "_pat_", "11ABCDEFG0hIjKlMnOpQrS", "_",
    "9zYxWvUtSrQpOnMlKjIhGfEdCbA8765432109zYxWvUtSrQpOnMlKjIhGfE"),
  awsKeyId: join("AK", "IA", "QYXP7RTMN2LKVHB4"),
  // 40 chars of [A-Za-z0-9/+], the length the rule requires
  awsSecret: join("QhRtMnBvCxZaSdFgHjKl", "PoIuYtRe93847562/1A+"),
  stripeLive: join("sk", "_live_", "51QhRtMnBvCxZaSdFgHjKl"),
  stripeTest: join("sk", "_test_", "51QhRtMnBvCxZaSdFgHjKl"),
  slackToken: join("xo", "xb-", "2183746501-9384756201-QhRtMnBvCxZaSdFgHjKl"),
  slackWebhook: join("https://hooks.slack.com/services/", "T04QhRtMn", "/", "B07BvCxZa", "/", "SdFgHjKlQhRtMnBvCxZa"),
  // AIza + exactly 35 chars
  googleApiKey: join("AI", "za", "SyQhRtMnBvCxZaSdFgHjKlPoIuYtRe93847"),
  anthropicKey: join("sk-", "ant-", "api03-QhRtMnBvCxZaSdFgHjKlPoIuYtRe"),
  openaiKey: join("sk-", "proj-", "QhRtMnBvCxZaSdFgHjKlPoIuYtRe9384756201MnBv"),
  npmToken: join("npm", "_", "QhRtMnBvCxZaSdFgHjKlPoIuYtRe93847562"),
  sendgridKey: join("SG", ".", "QhRtMnBvCxZaSdFg", ".", "HjKlPoIuYtRe9384756201MnBvCxZa"),
  twilioKey: join("SK", "3f9a2b7c4d8e1f6a5b0c9d2e7f4a8b1c"),
  connectionUri: join("postgres://checkout:", "Xk29fjq8ZlaQ7vTm", "@db.acme.internal:5432/orders"),
  pemKey: [
    "-----BEGIN RSA PRIVATE KEY-----",
    "MIIEowIBAAKCAQEAx8vJ2kQhRtMnBvCxZaSdFgHjKlPoIuYtRe9384756201Mn",
    "BvCxZaSdFgHjKlPoIuYtRe9384756201MnBvCxZaSdFgHjKlPoIuYtRe93847",
    "-----END RSA PRIVATE KEY-----",
  ].join("\n"),
  // no exp claim, so the rule upgrades it and explains why
  jwtNoExp: `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "svc-checkout", role: "admin" })}.ZmFrZXNpZ25hdHVyZQ`,
  // high entropy, but never in a credential context
  highEntropy: "zX9kQ2mP8vR4nB7jW3tY6uI1oL5eD0aS",
  // AWS publishes this key id in its own documentation; must always be ignored
  awsDocumented: join("AK", "IAIOSFODNN7EXAMPLE"),
};

// ===== helpers =====

function write(root, rel, content) {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content.endsWith("\n") ? content : content + "\n");
}

function initRepo(dir) {
  fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  fs.mkdirSync(dir, { recursive: true });
  git(dir, "init", "-q", "-b", "main");
  return dir;
}

const commit = (dir, message) => { git(dir, "add", "-A"); git(dir, "commit", "-qm", message); };

// Decoys shared by several fixtures. Not one of these is a secret, and a scanner
// that reports any of them is noise a team switches off within a week.
function writeDecoys(dir) {
  write(dir, "src/config.js", [
    "// none of the values below are credentials",
    `const documentedKey = "${SECRETS.awsDocumented}";`,
    "const githubToken = process.env.GITHUB_TOKEN;",
    'const apiKey = "your_api_key_here";',
    'const templated = "${DEPLOY_KEY}";',
    "// high entropy, but 'unauthorized' is a status, not a credential context",
    `const unauthorizedResponseId = "${SECRETS.highEntropy}";`,
  ].join("\n"));
  write(dir, "package-lock.json", JSON.stringify({
    name: "fixture", lockfileVersion: 3,
    packages: {
      "node_modules/a": { integrity: "sha512-" + "K7dQmVx2pLnT4hRbYcW9zEuAfJ0sMgNvXi3ZoBqUeH1yTlPaCdRkSwF6vN8jGmXtQbLyAoZrEuIcVdKfMnPq2w==" },
      "node_modules/b": { integrity: "sha512-" + "Rj9WsKpNc4mLdXvTgY7bZaQoEuHi2fMxAlOn3ScVrPtBkDyUeIqWzXmJ0gLhNfCvRoTaYdKuSbEwMzPxQn1A5g==" },
    },
  }, null, 2));
}

// ===== fixtures =====

const BUILDERS = {
  // One planted credential per rule. Every one of the 16 must fire.
  "all-rules": (dir) => {
    initRepo(dir);
    write(dir, ".env", [
      `GITHUB_TOKEN=${SECRETS.githubToken}`,
      `NPM_TOKEN=${SECRETS.npmToken}`,
      `GOOGLE_API_KEY=${SECRETS.googleApiKey}`,
    ].join("\n"));
    write(dir, "src/providers.js", [
      `const fineGrained = "${SECRETS.githubFineGrained}";`,
      `const anthropic = "${SECRETS.anthropicKey}";`,
      `const openai = "${SECRETS.openaiKey}";`,
      `const sendgrid = "${SECRETS.sendgridKey}";`,
      `const twilio = "${SECRETS.twilioKey}";`,
    ].join("\n"));
    write(dir, "src/billing.js", `const stripe = require("stripe")("${SECRETS.stripeLive}");`);
    write(dir, "src/chat.js", [
      `const botToken = "${SECRETS.slackToken}";`,
      `const alertUrl = "${SECRETS.slackWebhook}";`,
    ].join("\n"));
    write(dir, "src/auth.js", `const SERVICE_TOKEN = "${SECRETS.jwtNoExp}";`);
    write(dir, "src/db.js", `const url = "${SECRETS.connectionUri}";`);
    write(dir, "deploy/deploy.sh", [
      "#!/bin/sh",
      `AWS_ACCESS_KEY_ID=${SECRETS.awsKeyId}`,
      `aws_secret_access_key = "${SECRETS.awsSecret}"`,
    ].join("\n"));
    write(dir, "deploy/id_rsa", SECRETS.pemKey);
    commit(dir, "initial commit");
    return dir;
  },

  // Decoys only. Must produce zero findings and score 100.
  clean: (dir) => {
    initRepo(dir);
    writeDecoys(dir);
    write(dir, "README.md", "# clean\n\nNothing in here is a credential.");
    commit(dir, "initial commit");
    return dir;
  },

  // Secret committed, then removed in a later commit. Still reachable in history.
  deleted: (dir) => {
    initRepo(dir);
    write(dir, "config.js", `const token = "${SECRETS.githubToken}";`);
    commit(dir, "add config");
    write(dir, "config.js", "const token = process.env.GITHUB_TOKEN;");
    commit(dir, "read the token from the environment");
    return dir;
  },

  // Secret committed, then amended away. The old commit is unreferenced, so
  // `git log` cannot reach it — but the blob is still in the object database.
  unreachable: (dir) => {
    initRepo(dir);
    write(dir, "README.md", "# service");
    commit(dir, "initial commit");
    write(dir, "src/webhook.js", `const RELEASE_TOKEN = "${SECRETS.githubToken}";`);
    commit(dir, "add webhook verification");
    write(dir, "src/webhook.js", "const RELEASE_TOKEN = process.env.RELEASE_TOKEN;");
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "--amend", "-m", "add webhook verification");
    return dir;
  },

  // The same, packed. Findings must be identical through the packfile path.
  packed: (dir) => {
    BUILDERS.unreachable(dir);
    git(dir, "gc", "-q");
    return dir;
  },

  // Many near-identical large blobs force git to store deltas.
  delta: (dir) => {
    initRepo(dir);
    const page = "x".repeat(600) + "\n";
    for (let version = 0; version < 30; version++) {
      const planted = version === 13 ? `const key = "${SECRETS.stripeLive}";\n` : "";
      write(dir, "big.txt", page.repeat(10) + planted + `version ${version}\n`);
      commit(dir, `v${version}`);
    }
    git(dir, "gc", "-q", "--aggressive");
    return dir;
  },

  // A nested .gitignore excludes build output; a gitignored .env must still be
  // scanned, because "ignored by git" is not the same as "safe".
  "nested-ignore": (dir) => {
    initRepo(dir);
    write(dir, ".gitignore", "*.log\nserver/.env\n");
    write(dir, "app/.gitignore", "build/\n");
    write(dir, "app/build/bundle.js", `const leaked = "${SECRETS.stripeLive}";`);
    write(dir, "app/src.js", "export const ok = true;");
    write(dir, "server/.env", `GITHUB_TOKEN=${SECRETS.githubToken}`);
    write(dir, "dropped.log", `const leaked = "${SECRETS.stripeLive}";`);
    commit(dir, "initial commit");
    return dir;
  },

  // The narrative repository used in the demo video: a small checkout service
  // with eight findings across four severities, plus decoys. The only GitHub
  // token in it is the one that gets amended away, which keeps the on-camera
  // proof unambiguous: grepping all of history for one returns nothing.
  "acme-checkout": (dir) => {
    initRepo(dir);
    write(dir, "README.md", [
      "# acme-checkout",
      "",
      "Sample service used to demonstrate LeakLens. Every credential in this",
      "repository is fabricated and none of them are, or ever were, valid.",
    ].join("\n"));
    write(dir, "package-lock.json", JSON.stringify({
      name: "acme-checkout", lockfileVersion: 3,
      packages: {
        "node_modules/a": { integrity: "sha512-" + "K7dQmVx2pLnT4hRbYcW9zEuAfJ0sMgNvXi3ZoBqUeH1yTlPaCdRkSwF6vN8jGmXtQbLyAoZrEuIcVdKfMnPq2w==" },
      },
    }, null, 2));
    commit(dir, "initial commit");

    write(dir, "src/db.js", `const url = "${SECRETS.connectionUri}";`);
    write(dir, "src/payments.js", [
      "// test-mode key: low severity, but still worth rotating",
      `const stripe = require("stripe")("${SECRETS.stripeTest}");`,
    ].join("\n"));
    commit(dir, "add orders db and payments client");

    write(dir, "src/auth.js", [
      "// service-to-service auth for the checkout worker",
      `const SERVICE_TOKEN = "${SECRETS.jwtNoExp}";`,
    ].join("\n"));
    writeDecoys(dir);
    commit(dir, "service auth + config");

    write(dir, "deploy/deploy.sh", [
      "#!/bin/sh",
      "set -eu",
      `AWS_ACCESS_KEY_ID=${SECRETS.awsKeyId}`,
      "aws s3 sync ./dist s3://acme-checkout-static",
    ].join("\n"));
    write(dir, "deploy/id_rsa", SECRETS.pemKey);
    commit(dir, "staging deploy script");

    write(dir, ".env", [
      "NODE_ENV=production",
      `NPM_TOKEN=${SECRETS.npmToken}`,
      "SENTRY_DSN=your_api_key_here",
    ].join("\n"));
    git(dir, "add", "-f", ".env"); git(dir, "commit", "-qm", "add environment config");

    // the finale: leaked, then amended away
    write(dir, "src/webhook.js", `const GH_RELEASE_TOKEN = "${SECRETS.githubToken}";`);
    commit(dir, "add webhook verification");
    write(dir, "src/webhook.js", "const GH_RELEASE_TOKEN = process.env.GH_RELEASE_TOKEN;");
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "--amend", "-m", "add webhook verification");

    // uncommitted, so --verify has something genuinely resolvable to report
    write(dir, "src/notify.js", `const WEBHOOK = "${SECRETS.slackWebhook}";`);
    return dir;
  },
};

export const FIXTURE_NAMES = Object.keys(BUILDERS);

export function buildRepo(kind, dir) {
  const builder = BUILDERS[kind];
  if (!builder) throw new Error(`unknown fixture: ${kind} (have ${FIXTURE_NAMES.join(", ")})`);
  return builder(path.resolve(dir));
}

// Builds into a fresh temp directory that the test context removes afterwards.
export function fixtureRepo(t, kind) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `leaklens-${kind}-`));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }));
  return buildRepo(kind, dir);
}
