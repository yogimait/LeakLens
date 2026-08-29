
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import crypto from "node:crypto";
import { pathToFileURL, fileURLToPath } from "node:url";

export const VERSION = "0.1.0";

// ===== CONFIG =====

export const CONFIG = {
  maxFileBytes: 5 * 1024 * 1024, // ponytail: skip-with-note over streaming; stream if real repos demand it
  maxObjectBytes: 10 * 1024 * 1024,
  maxDeltaDepth: 100,
  objectCacheBytes: 64 * 1024 * 1024,
  entropyBase64: 4.5,
  entropyBase64MinLen: 20,
  entropyHex: 3.0,
  entropyHexMinLen: 32,
  longLineSkip: 500,
  exit: { ok: 0, findings: 1, usage: 2, error: 3 },
};

const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const SEV_WEIGHT = { critical: 25, high: 15, medium: 5, low: 1, info: 0 };

// ===== ARGV =====

const USAGE = `LeakLens v${VERSION} — git-aware secret scanner. Node stdlib only, no network.

Usage: node leaklens.mjs <path> [options]

Options:
  --history               Also scan git history, including unreachable objects
  --format <tty|json|sarif>  Output format (default tty)
  --baseline <file>       Suppress findings whose fingerprints appear in <file>
  --remediate             Write leaklens-remediation.md + leaklens.env.example
  --remediate-patch       Also emit a unified diff (contains cleartext secrets!)
  --out <path>            Output dir (or .patch file path) for remediation artifacts
  --verify <report.json>  Rescan and diff against a previous JSON report
  --unsafe-show-secrets   Print full secret values (redacted by default)
  --include-vendor        Scan node_modules/ and vendor/ too
  --build [dir]           Build the distributable artifact (default dist/) + SHA256SUMS
  --prove                 Prove zero dependencies and no network/subprocess reach
  -h, --help              This text

Exit codes: 0 no findings · 1 findings · 2 usage error · 3 scan error`;

export function parseArgv(argv) {
  const options = {
    path: null, history: false, format: "tty", baseline: null,
    remediate: false, remediatePatch: false, out: null, verify: null,
    showSecrets: false, includeVendor: false, help: false, error: null,
    build: false, buildDir: null, prove: false,
  };
  for (let argIndex = 0; argIndex < argv.length; argIndex++) {
    const arg = argv[argIndex];
    // Consumes the next argv entry as this flag's value, or records a usage error.
    const takeValue = () => {
      if (argIndex + 1 >= argv.length) { options.error = `${arg} needs a value`; return null; }
      return argv[++argIndex];
    };
    switch (arg) {
      case "-h": case "--help": options.help = true; break;
      case "--history": options.history = true; break;
      case "--remediate": options.remediate = true; break;
      case "--remediate-patch": options.remediatePatch = true; options.remediate = true; break;
      case "--unsafe-show-secrets": options.showSecrets = true; break;
      case "--include-vendor": options.includeVendor = true; break;
      case "--prove": options.prove = true; break;
      case "--build": {
        options.build = true;
        // optional directory argument: only consume it if it is not another flag
        if (argIndex + 1 < argv.length && !argv[argIndex + 1].startsWith("-")) {
          options.buildDir = argv[++argIndex];
        }
        break;
      }
      case "--format": {
        const format = takeValue(); if (format === null) return options;
        if (!["tty", "json", "sarif"].includes(format)) {
          options.error = `unknown format: ${format}`; return options;
        }
        options.format = format; break;
      }
      case "--baseline": {
        const baselinePath = takeValue(); if (baselinePath === null) return options;
        options.baseline = baselinePath; break;
      }
      case "--out": {
        const outPath = takeValue(); if (outPath === null) return options;
        options.out = outPath; break;
      }
      case "--verify": {
        const reportPath = takeValue(); if (reportPath === null) return options;
        options.verify = reportPath; break;
      }
      default:
        if (arg.startsWith("-")) { options.error = `unknown option: ${arg}`; return options; }
        if (options.path) { options.error = `unexpected argument: ${arg}`; return options; }
        options.path = arg;
    }
  }
  return options;
}

// ===== TTY / RENDER =====

// NO_COLOR always wins; FORCE_COLOR=0 means off, any other value forces on
// (chalk's contract — we honour it without chalk)
const forcedColor = process.env.FORCE_COLOR;
const useColor = !process.env.NO_COLOR &&
  (forcedColor ? forcedColor !== "0" : !!process.stdout.isTTY);
const paint = (code) => (text) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : String(text));
const c = {
  red: paint(31), yellow: paint(33), green: paint(32), cyan: paint(36),
  gray: paint(90), bold: paint(1), magenta: paint(35),
};
const SEV_COLOR = { critical: c.red, high: c.red, medium: c.yellow, low: c.cyan, info: c.gray };

// ===== FS WALK =====

// gitignore-style glob → RegExp source. Supports *, **, ?, [...] classes.
export function globToRegExp(glob) {
  let regexSource = "";
  for (let charIndex = 0; charIndex < glob.length; charIndex++) {
    const char = glob[charIndex];
    if (char === "*") {
      if (glob[charIndex + 1] === "*") {
        // "**/" spans directory boundaries; a bare "**" matches anything at all.
        if (glob[charIndex + 2] === "/") { regexSource += "(?:[^/]+/)*"; charIndex += 2; }
        else { regexSource += ".*"; charIndex += 1; }
      } else regexSource += "[^/]*"; // a single "*" stops at a slash
    } else if (char === "?") {
      regexSource += "[^/]";
    } else if (char === "[") {
      let classEnd = charIndex + 1;
      let negatedClass = false;
      if (glob[classEnd] === "!" || glob[classEnd] === "^") { negatedClass = true; classEnd++; }
      let charClass = "";
      for (; classEnd < glob.length && glob[classEnd] !== "]"; classEnd++) charClass += glob[classEnd];
      // Unterminated or empty "[" is a literal bracket, as git treats it.
      if (classEnd >= glob.length || charClass === "") { regexSource += "\\["; continue; }
      regexSource += "[" + (negatedClass ? "^" : "") + charClass.replace(/\\/g, "\\\\") + "]";
      charIndex = classEnd;
    } else {
      regexSource += char.replace(/[.+^${}()|\\]/g, "\\$&");
    }
  }
  return regexSource;
}

// One .gitignore line → a matcher rule, or null for blanks and comments.
function compileIgnorePattern(line) {
  let pattern = String(line ?? "");
  if (!pattern || pattern.startsWith("#")) return null;
  pattern = pattern.replace(/(?<!\\)\s+$/, "");
  if (!pattern) return null;
  let negated = false, dirOnly = false;
  if (pattern.startsWith("!")) { negated = true; pattern = pattern.slice(1); }
  if (pattern.endsWith("/")) { dirOnly = true; pattern = pattern.slice(0, -1); }
  let anchored = false;
  if (pattern.startsWith("/")) { anchored = true; pattern = pattern.slice(1); }
  else if (pattern.includes("/")) anchored = true; // slash mid-pattern anchors, per gitignore rules
  const regex = new RegExp("^" + (anchored ? "" : "(?:.*/)?") + globToRegExp(pattern) + "$");
  return { regex, negated, dirOnly };
}

// Tri-state matcher: true = ignored, false = explicitly re-included by a "!"
// rule, null = this file had no opinion. The third state is what lets a nested
// .gitignore override a parent one only where it actually says something.
export function makeIgnoreMatcher(patterns) {
  const rules = patterns.map(compileIgnorePattern).filter(Boolean);
  return (relPath, isDir) => {
    let verdict = null;
    for (const rule of rules) {
      if (rule.dirOnly && !isDir) continue;
      if (rule.regex.test(relPath)) verdict = !rule.negated; // last match wins
    }
    return verdict;
  };
}

// Boolean convenience wrapper: "no opinion" means "not ignored".
export function makeIgnore(patterns) {
  const match = makeIgnoreMatcher(patterns);
  return (relPath, isDir) => match(relPath, isDir) === true;
}

function readIgnoreFile(filePath) {
  try { return fs.readFileSync(filePath, "utf8").split(/\r?\n/); }
  catch { return null; }
}

// Applies a stack of matchers, shallowest first. A deeper .gitignore wins over a
// shallower one, but only for paths beneath it and only when it has an opinion.
function isPathIgnored(matcherStack, relPath, isDir) {
  let ignored = false;
  for (const matcher of matcherStack) {
    if (matcher.base && !relPath.startsWith(matcher.base + "/")) continue;
    const relativeToMatcher = matcher.base ? relPath.slice(matcher.base.length + 1) : relPath;
    const verdict = matcher.match(relativeToMatcher, isDir);
    if (verdict !== null) ignored = verdict;
  }
  return ignored;
}

// Files scanned even when .gitignore excludes them. A .env is the single most
// common home for a real credential, and "gitignored" is not "safe": the file is
// still on disk, still in backups, still one `git add -f` from being committed.
// Ignoring it because git does would defeat the point of the tool.
const ALWAYS_SCAN = /(^|\/)\.env(\.|$)|(^|\/)credentials?\.|\.(pem|key|p12|pfx)$|(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i;

// Iterative walk that honours .gitignore at every level, not just the root.
// Nested files matter in practice: a Next.js project ignores .next/ from
// dashboard/.gitignore, and reading only the root would scan build output.
export function walkFiles(root, opts, notes) {
  const rootPatterns = [".git/"];
  if (!opts.includeVendor) rootPatterns.push("node_modules/", "vendor/", ".pnpm-store/");
  const rootIgnoreLines = readIgnoreFile(path.join(root, ".gitignore"));
  if (rootIgnoreLines) rootPatterns.push(...rootIgnoreLines);

  const filePaths = [];
  const pendingDirs = [{
    dirRelPath: "",
    matcherStack: [{ base: "", match: makeIgnoreMatcher(rootPatterns) }],
  }];

  while (pendingDirs.length) {
    const { dirRelPath, matcherStack } = pendingDirs.pop();

    // A .gitignore inside this directory applies to everything below it.
    let stack = matcherStack;
    if (dirRelPath) {
      const nestedLines = readIgnoreFile(path.join(root, dirRelPath, ".gitignore"));
      if (nestedLines) {
        stack = [...matcherStack, { base: dirRelPath, match: makeIgnoreMatcher(nestedLines) }];
      }
    }

    let dirEntries;
    try { dirEntries = fs.readdirSync(path.join(root, dirRelPath), { withFileTypes: true }); }
    catch (err) { notes.push(`unreadable dir: ${dirRelPath || "."} (${err.code})`); continue; }

    for (const entry of dirEntries) {
      const entryRelPath = dirRelPath ? dirRelPath + "/" + entry.name : entry.name;
      if (entry.isSymbolicLink()) continue; // threat model: symlinks not followed
      if (entry.isDirectory()) {
        if (!isPathIgnored(stack, entryRelPath, true)) {
          pendingDirs.push({ dirRelPath: entryRelPath, matcherStack: stack });
        }
      } else if (entry.isFile()) {
        const keepRegardless = ALWAYS_SCAN.test(entryRelPath);
        if (keepRegardless || !isPathIgnored(stack, entryRelPath, false)) {
          filePaths.push(entryRelPath);
        }
      }
    }
  }
  return filePaths.sort();
}

// A NUL byte, or a high ratio of control bytes, means "do not treat as text".
export function looksBinary(buf) {
  const sampleSize = Math.min(buf.length, 8192);
  if (sampleSize === 0) return false;
  let controlBytes = 0;
  for (let byteIndex = 0; byteIndex < sampleSize; byteIndex++) {
    const byte = buf[byteIndex];
    if (byte === 0) return true;
    if (byte < 7 || (byte > 13 && byte < 32)) controlBytes++;
  }
  return controlBytes / sampleSize > 0.3;
}

// ===== GIT =====
// Own .git reader: loose objects, packfile .idx v2, ofs/ref deltas.
// SHA-1 here is object *addressing*, never a security boundary (threat model).
  
// Locates the git directory: a normal ".git/" folder, a ".git" *file* holding a
// "gitdir:" pointer (worktrees and submodules), or a bare repo where root is it.
export function findGitDir(root) {
  const dotGitPath = path.join(root, ".git");
  try {
    const dotGitStat = fs.statSync(dotGitPath);
    if (dotGitStat.isDirectory()) return dotGitPath;
    const gitdirMatch = fs.readFileSync(dotGitPath, "utf8").match(/^gitdir:\s*(.+)$/m);
    if (gitdirMatch) return path.resolve(root, gitdirMatch[1].trim());
  } catch {}
  // bare repo: root itself is the git dir
  try {
    if (fs.statSync(path.join(root, "objects")).isDirectory() &&
        fs.existsSync(path.join(root, "HEAD"))) return root;
  } catch {}
  return null;
}

const isSha = (value) => /^[0-9a-f]{40}$/.test(value);

// Follows a ref through symbolic "ref: refs/heads/main" indirection to a real
// sha, falling back to packed-refs when the loose ref file is absent.
function refTargetSha(gitdir, refText, followDepth = 0) {
  const trimmed = refText.trim();
  if (isSha(trimmed.split(/\s/)[0])) return trimmed.split(/\s/)[0];
  if (trimmed.startsWith("ref: ") && followDepth < 5) {
    const refName = trimmed.slice(5).trim();
    try {
      return refTargetSha(gitdir, fs.readFileSync(path.join(gitdir, refName), "utf8"), followDepth + 1);
    } catch {
      // loose ref file missing — the ref may only exist in packed-refs
      try {
        const packedRefs = fs.readFileSync(path.join(gitdir, "packed-refs"), "utf8");
        const escapedRefName = refName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const packedMatch = packedRefs.match(new RegExp(`^([0-9a-f]{40}) ${escapedRefName}$`, "m"));
        if (packedMatch) return packedMatch[1];
      } catch {}
    }
  }
  return null;
}

// Every commit sha we can reach from a ref: HEAD, refs/**, and packed-refs.
// These are the starting points for the "reachable" half of the history walk.
export function collectRefs(gitdir) {
  const commitShas = new Set();
  const addIfSha = (value) => { if (isSha(value)) commitShas.add(value); };

  for (const refFileName of ["HEAD", "ORIG_HEAD", "MERGE_HEAD"]) {
    try {
      const sha = refTargetSha(gitdir, fs.readFileSync(path.join(gitdir, refFileName), "utf8"));
      if (sha) addIfSha(sha);
    } catch {}
  }

  const pendingRefDirs = [path.join(gitdir, "refs")];
  while (pendingRefDirs.length) {
    const refDir = pendingRefDirs.pop();
    let dirEntries;
    try { dirEntries = fs.readdirSync(refDir, { withFileTypes: true }); } catch { continue; }
    for (const entry of dirEntries) {
      const entryPath = path.join(refDir, entry.name);
      if (entry.isDirectory()) pendingRefDirs.push(entryPath);
      else {
        try { addIfSha(fs.readFileSync(entryPath, "utf8").trim().split(/\s/)[0]); } catch {}
      }
    }
  }

  try {
    const packedRefLines = fs.readFileSync(path.join(gitdir, "packed-refs"), "utf8").split("\n");
    for (const line of packedRefLines) {
      const shaMatch = /^([0-9a-f]{40}) /.exec(line);
      if (shaMatch) addIfSha(shaMatch[1]);
    }
  } catch {}

  return commitShas;
}

// Pack object type codes, per gitformat-pack. Indexes 5 is reserved/unused.
const PACK_TYPE = [null, "commit", "tree", "blob", "tag", null, "ofs-delta", "ref-delta"];

// Parses a .idx v2 header into the byte offsets of its four parallel tables.
// Layout: magic(4) version(4) fanout(1024) shas(20N) crcs(4N) offsets(4N) largeOffsets(8K)
function parseIdx(idxPath) {
  const indexBuf = fs.readFileSync(idxPath);
  if (indexBuf.length < 1032 + 40 || indexBuf.readUInt32BE(0) !== 0xff744f63)
    throw new Error(`unsupported pack index (not v2 magic): ${path.basename(idxPath)}`);
  if (indexBuf.readUInt32BE(4) !== 2)
    throw new Error(`unsupported pack index version ${indexBuf.readUInt32BE(4)}: ${path.basename(idxPath)}`);

  // fanout[b] = how many objects have a first sha byte <= b, so fanout[255] is the total.
  const fanout = new Uint32Array(256);
  for (let fanoutSlot = 0; fanoutSlot < 256; fanoutSlot++) {
    fanout[fanoutSlot] = indexBuf.readUInt32BE(8 + 4 * fanoutSlot);
  }
  const objectCount = fanout[255];
  const shaTableOffset = 1032;
  const crcTableOffset = shaTableOffset + 20 * objectCount;
  const offsetTableOffset = crcTableOffset + 4 * objectCount;
  const largeOffsetTableOffset = offsetTableOffset + 4 * objectCount;

  return {
    indexBuf, fanout, objectCount,
    shaTableOffset, offsetTableOffset, largeOffsetTableOffset,
    packPath: idxPath.replace(/\.idx$/, ".pack"),
  };
}

// Byte offset of the nth object inside the .pack. A set top bit means the value
// is really an index into the 8-byte table, used by packs larger than 2 GiB.
function idxOffsetAt(packIndex, objectNumber) {
  const rawOffset = packIndex.indexBuf.readUInt32BE(packIndex.offsetTableOffset + 4 * objectNumber);
  if (rawOffset & 0x80000000) {
    const largeOffsetSlot = rawOffset & 0x7fffffff;
    return Number(packIndex.indexBuf.readBigUInt64BE(
      packIndex.largeOffsetTableOffset + 8 * largeOffsetSlot));
  }
  return rawOffset;
}

function idxShaAt(packIndex, objectNumber) {
  const shaStart = packIndex.shaTableOffset + 20 * objectNumber;
  return packIndex.indexBuf.toString("hex", shaStart, shaStart + 20);
}

// Finds an object's pack offset, or -1. The fanout narrows the search to the
// slice of shas sharing a first byte, so we binary-search 1/256th of the table.
function idxLookup(packIndex, shaHex) {
  const targetSha = Buffer.from(shaHex, "hex");
  const firstByte = targetSha[0];
  let low = firstByte === 0 ? 0 : packIndex.fanout[firstByte - 1];
  let high = packIndex.fanout[firstByte];
  while (low < high) {
    const mid = (low + high) >> 1;
    const midShaStart = packIndex.shaTableOffset + 20 * mid;
    const comparison = targetSha.compare(packIndex.indexBuf, midShaStart, midShaStart + 20);
    if (comparison === 0) return idxOffsetAt(packIndex, mid);
    if (comparison < 0) high = mid; else low = mid + 1;
  }
  return -1;
}

// Rebuilds an object from its base plus a delta instruction stream.
// Each instruction byte: bit 7 set = copy a run from the base, clear and
// non-zero = insert that many literal bytes, zero = reserved and rejected.
export function applyDelta(base, delta) {
  let deltaPos = 0;
  // Plain 7-bit little-endian varint, used only by the two size headers.
  const readVarint = () => {
    let value = 0, shift = 0, byte;
    do {
      byte = delta[deltaPos++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    } while (byte & 0x80);
    return value;
  };

  const expectedBaseSize = readVarint();
  const resultSize = readVarint();
  if (expectedBaseSize !== base.length) throw new Error("delta source size mismatch");
  if (resultSize > CONFIG.maxObjectBytes) throw new Error("delta target over size cap");

  const result = Buffer.allocUnsafe(resultSize);
  let resultPos = 0;
  while (deltaPos < delta.length) {
    const instruction = delta[deltaPos++];
    if (instruction & 0x80) {
      // COPY: bits 0-3 select which offset bytes follow, bits 4-6 which size bytes.
      let copyFrom = 0, copyLength = 0;
      for (let offsetByte = 0; offsetByte < 4; offsetByte++) {
        if (instruction & (1 << offsetByte)) copyFrom += delta[deltaPos++] * 2 ** (8 * offsetByte);
      }
      for (let sizeByte = 0; sizeByte < 3; sizeByte++) {
        if (instruction & (1 << (4 + sizeByte))) copyLength += delta[deltaPos++] * 2 ** (8 * sizeByte);
      }
      if (copyLength === 0) copyLength = 0x10000; // spec: an encoded size of 0 means 65536
      if (copyFrom + copyLength > base.length) throw new Error("delta copy out of range");
      base.copy(result, resultPos, copyFrom, copyFrom + copyLength);
      resultPos += copyLength;
    } else if (instruction) {
      // INSERT: the low 7 bits are how many literal bytes follow.
      delta.copy(result, resultPos, deltaPos, deltaPos + instruction);
      deltaPos += instruction;
      resultPos += instruction;
    } else {
      throw new Error("delta reserved opcode 0");
    }
  }
  if (resultPos !== resultSize) throw new Error("delta result size mismatch");
  return result;
}

// Reads git objects out of a repository: loose files first, then every packfile.
// Holds the parsed pack indexes and a byte-bounded cache of resolved objects,
// because a deep delta chain re-reads the same bases many times.
export class GitStore {
  constructor(gitdir, notes = []) {
    this.gitdir = gitdir;
    this.notes = notes;
    this.objectCache = new Map(); // "packPath:offset" -> {type, data}
    this.objectCacheBytes = 0;
    this.packBuffers = new Map(); // packPath -> Buffer
    this.packIndexes = [];

    const packDir = path.join(gitdir, "objects", "pack");
    let packDirEntries = [];
    try { packDirEntries = fs.readdirSync(packDir); } catch {}
    for (const fileName of packDirEntries) {
      if (!fileName.endsWith(".idx")) continue;
      try { this.packIndexes.push(parseIdx(path.join(packDir, fileName))); }
      catch (err) { notes.push(`skipped pack index: ${err.message}`); }
    }
  }

  packBuffer(packIndex) {
    let buffer = this.packBuffers.get(packIndex.packPath);
    if (!buffer) {
      // ponytail: whole pack in memory; windowed reads if multi-GB packs show up
      buffer = fs.readFileSync(packIndex.packPath);
      this.packBuffers.set(packIndex.packPath, buffer);
    }
    return buffer;
  }

  cacheObject(cacheKey, gitObject) {
    this.objectCacheBytes += gitObject.data.length;
    // ponytail: whole-cache flush rather than true LRU; revisit if hit rate drops
    if (this.objectCacheBytes > CONFIG.objectCacheBytes) {
      this.objectCache.clear();
      this.objectCacheBytes = gitObject.data.length;
    }
    this.objectCache.set(cacheKey, gitObject);
  }

  // Reads one object at a byte offset in a pack, resolving delta chains.
  // chainKeys carries the set of objects already in this chain so a malicious
  // cyclic delta is rejected instead of looping forever.
  readPackedAt(packIndex, packOffset, chainDepth = 0, chainKeys = new Set()) {
    const cacheKey = `${packIndex.packPath}:${packOffset}`;
    const cached = this.objectCache.get(cacheKey);
    if (cached) return cached;
    if (chainDepth > CONFIG.maxDeltaDepth) throw new Error("delta chain too deep");
    if (chainKeys.has(cacheKey)) throw new Error("cyclic delta chain");
    chainKeys.add(cacheKey);

    const packBuf = this.packBuffer(packIndex);
    let readPos = packOffset;

    // Object header varint: bits 6-4 of the first byte are the type, the
    // remaining bits accumulate the inflated size little-endian.
    let headerByte = packBuf[readPos++];
    const objectType = (headerByte >> 4) & 7;
    let inflatedSize = headerByte & 15;
    let sizeShift = 4;
    while (headerByte & 0x80) {
      headerByte = packBuf[readPos++];
      inflatedSize += (headerByte & 0x7f) * 2 ** sizeShift;
      sizeShift += 7;
    }
    if (inflatedSize > CONFIG.maxObjectBytes) {
      throw new Error(`object over size cap (${inflatedSize} bytes)`);
    }

    if (objectType >= 1 && objectType <= 4) {
      const data = zlib.inflateSync(packBuf.subarray(readPos));
      if (data.length !== inflatedSize) throw new Error("inflated size mismatch");
      const gitObject = { type: PACK_TYPE[objectType], data };
      this.cacheObject(cacheKey, gitObject);
      return gitObject;
    }

    if (objectType === 6) {
      // OFS_DELTA: base sits at a negative offset from this header. The "+1" in
      // the continuation makes the encoding non-redundant; omitting it yields
      // offsets that are almost right, which reads as random corruption.
      let offsetByte = packBuf[readPos++];
      let baseDistance = offsetByte & 0x7f;
      while (offsetByte & 0x80) {
        offsetByte = packBuf[readPos++];
        baseDistance = (baseDistance + 1) * 128 + (offsetByte & 0x7f);
      }
      const baseObject = this.readPackedAt(packIndex, packOffset - baseDistance, chainDepth + 1, chainKeys);
      const deltaStream = zlib.inflateSync(packBuf.subarray(readPos));
      const gitObject = { type: baseObject.type, data: applyDelta(baseObject.data, deltaStream) };
      this.cacheObject(cacheKey, gitObject);
      return gitObject;
    }

    if (objectType === 7) {
      // REF_DELTA: base named by raw sha, and may live in another pack or loose.
      const baseSha = packBuf.toString("hex", readPos, readPos + 20);
      readPos += 20;
      if (chainKeys.has(`sha:${baseSha}`)) throw new Error("cyclic ref-delta chain");
      chainKeys.add(`sha:${baseSha}`);
      const baseObject = this.readObject(baseSha, chainDepth + 1, chainKeys);
      if (!baseObject) throw new Error(`unresolvable delta base ${baseSha} (thin pack?)`);
      const deltaStream = zlib.inflateSync(packBuf.subarray(readPos));
      const gitObject = { type: baseObject.type, data: applyDelta(baseObject.data, deltaStream) };
      this.cacheObject(cacheKey, gitObject);
      return gitObject;
    }

    throw new Error(`unknown pack object type ${objectType}`);
  }

  // Loose object: zlib stream of "<type> <size>\0<content>", named by the SHA-1
  // of those very bytes. We recompute it and refuse content that disagrees.
  readLoose(sha) {
    const loosePath = path.join(this.gitdir, "objects", sha.slice(0, 2), sha.slice(2));
    let rawObject;
    try { rawObject = zlib.inflateSync(fs.readFileSync(loosePath)); }
    catch (err) {
      if (err.code === "ENOENT") return null;
      this.notes.push(`corrupt loose object ${sha.slice(0, 12)}: ${err.message}`);
      return null;
    }

    const headerEnd = rawObject.indexOf(0);
    if (headerEnd < 0) {
      this.notes.push(`malformed loose object header ${sha.slice(0, 12)}`);
      return null;
    }
    const [objectType, declaredSize] = rawObject.toString("utf8", 0, headerEnd).split(" ");
    if (rawObject.length - headerEnd - 1 !== Number(declaredSize)) {
      this.notes.push(`loose object size mismatch ${sha.slice(0, 12)}`);
      return null;
    }
    const computedSha = crypto.createHash("sha1").update(rawObject).digest("hex");
    if (computedSha !== sha) {
      this.notes.push(`sha mismatch for ${sha.slice(0, 12)} — content not trusted, skipped`);
      return null;
    }
    return { type: objectType, data: rawObject.subarray(headerEnd + 1) };
  }

  // Returns the object, or null with a note. Never throws: one bad object must
  // not abort a scan of an otherwise readable repository.
  readObject(sha, chainDepth = 0, chainKeys = new Set()) {
    try {
      const looseObject = this.readLoose(sha);
      if (looseObject) return looseObject;
      for (const packIndex of this.packIndexes) {
        const packOffset = idxLookup(packIndex, sha);
        if (packOffset >= 0) return this.readPackedAt(packIndex, packOffset, chainDepth, chainKeys);
      }
    } catch (err) {
      this.notes.push(`unreadable object ${sha.slice(0, 12)}: ${err.message}`);
    }
    return null;
  }

  // Every object sha in the database: loose directories plus every pack index.
  // Independent of refs — this is what makes unreachable blobs visible.
  enumerate() {
    const allShas = new Set();
    const objectsDir = path.join(this.gitdir, "objects");

    let shaPrefixDirs = [];
    try { shaPrefixDirs = fs.readdirSync(objectsDir); } catch {}
    for (const prefixDir of shaPrefixDirs) {
      if (!/^[0-9a-f]{2}$/.test(prefixDir)) continue;
      for (const shaRemainder of fs.readdirSync(path.join(objectsDir, prefixDir))) {
        if (/^[0-9a-f]{38}$/.test(shaRemainder)) allShas.add(prefixDir + shaRemainder);
      }
    }

    for (const packIndex of this.packIndexes) {
      for (let objectNumber = 0; objectNumber < packIndex.objectCount; objectNumber++) {
        allShas.add(idxShaAt(packIndex, objectNumber));
      }
    }
    return allShas;
  }
}

// Commit object: a header block of "tree"/"parent"/"author" lines, a blank
// line, then the message. We only need the graph edges and the attribution.
export function parseCommit(data) {
  const commitText = data.toString("utf8");
  const headerText = commitText.split("\n\n")[0];
  const treeSha = /^tree ([0-9a-f]{40})$/m.exec(headerText)?.[1] ?? null;
  const parentShas = [...headerText.matchAll(/^parent ([0-9a-f]{40})$/gm)].map((match) => match[1]);
  const authorMatch = /^author (.+?) <.*?> (\d+)/m.exec(headerText);
  return {
    tree: treeSha,
    parents: parentShas,
    author: authorMatch ? authorMatch[1] : null,
    date: authorMatch ? new Date(Number(authorMatch[2]) * 1000).toISOString().slice(0, 10) : null,
  };
}

// Tree object: repeated "<mode> <name>\0<20 raw sha bytes>", no separators.
export function parseTree(data) {
  const entries = [];
  let readPos = 0;
  while (readPos < data.length) {
    const spaceIndex = data.indexOf(0x20, readPos);
    const nulIndex = data.indexOf(0, spaceIndex);
    if (spaceIndex < 0 || nulIndex < 0 || nulIndex + 21 > data.length) {
      throw new Error("malformed tree entry");
    }
    const mode = data.toString("utf8", readPos, spaceIndex);
    let entryName = data.toString("utf8", spaceIndex + 1, nulIndex);
    // threat model: tree entry names are attacker-controlled; never let them resolve to real paths
    if (entryName.includes("/") || entryName === ".." || entryName === ".") {
      entryName = `[unsafe:${JSON.stringify(entryName)}]`;
    }
    entries.push({ mode, name: entryName, sha: data.toString("hex", nulIndex + 1, nulIndex + 21) });
    readPos = nulIndex + 21;
  }
  return entries;
}

// Walks a tree recursively, recording every blob's path and the commit it came
// from. A blob already recorded as unreachable is upgraded when a reachable
// commit also contains it, so the "reachable" flag reflects the best evidence.
function walkTreeCollect(store, treeSha, pathPrefix, commitInfo, reachable, blobMeta, seenTrees) {
  const visitKey = treeSha + (reachable ? "r" : "u");
  if (seenTrees.has(visitKey)) return;
  seenTrees.add(visitKey);

  const treeObject = store.readObject(treeSha);
  if (!treeObject || treeObject.type !== "tree") return;
  let entries;
  try { entries = parseTree(treeObject.data); }
  catch (err) { store.notes.push(`bad tree ${treeSha.slice(0, 12)}: ${err.message}`); return; }

  for (const entry of entries) {
    const entryPath = pathPrefix ? pathPrefix + "/" + entry.name : entry.name;
    if (entry.mode === "40000") {
      walkTreeCollect(store, entry.sha, entryPath, commitInfo, reachable, blobMeta, seenTrees);
    } else if (entry.mode === "120000" || entry.mode === "160000") {
      continue; // symlink / submodule — no blob content of ours to scan
    } else if (!blobMeta.has(entry.sha) || (reachable && !blobMeta.get(entry.sha).reachable)) {
      blobMeta.set(entry.sha, { path: entryPath, ...commitInfo, reachable });
    }
  }
}

// Scans the object database rather than the commit log. Five passes:
//   1. walk commits reachable from refs        -> blobs marked reachable
//   2. collect HEAD's blobs                    -> lets findings say "still at HEAD"
//   3. enumerate every object, find commits pass 1 never saw -> the amended-away ones
//   4. walk those                              -> their blobs get paths, marked unreachable
//   5. scan every blob found, plus orphans nothing referenced
// Pass 3 is what "git log -p" structurally cannot do, since it only walks refs.
export function scanHistory(root, opts, notes) {
  const gitdir = findGitDir(root);
  const findings = [];
  if (!gitdir) {
    notes.push("no .git directory — history scan skipped");
    return { findings, objects: 0 };
  }

  const store = new GitStore(gitdir, notes);
  const blobMeta = new Map(); // blob sha -> {path, commit, author, date, reachable}
  const seenCommits = new Set();
  const seenTrees = new Set();

  const walkCommits = (startShas, reachable) => {
    const pendingCommits = [...startShas];
    while (pendingCommits.length) {
      const commitSha = pendingCommits.pop();
      if (seenCommits.has(commitSha)) continue;
      seenCommits.add(commitSha);
      const commitObject = store.readObject(commitSha);
      if (!commitObject || commitObject.type !== "commit") continue;
      const commit = parseCommit(commitObject.data);
      if (commit.tree) {
        walkTreeCollect(store, commit.tree, "",
          { commit: commitSha, author: commit.author, date: commit.date },
          reachable, blobMeta, seenTrees);
      }
      pendingCommits.push(...commit.parents);
    }
  };

  walkCommits(collectRefs(gitdir), true);

  // Pass 2: which blobs are still present in the current checkout?
  const headBlobShas = new Set();
  try {
    const headSha = refTargetSha(gitdir, fs.readFileSync(path.join(gitdir, "HEAD"), "utf8"));
    if (headSha) {
      const headCommitObject = store.readObject(headSha);
      if (headCommitObject?.type === "commit") {
        const headBlobMeta = new Map();
        walkTreeCollect(store, parseCommit(headCommitObject.data).tree, "",
          { commit: headSha }, true, headBlobMeta, new Set());
        for (const blobSha of headBlobMeta.keys()) headBlobShas.add(blobSha);
      }
    }
  } catch {}

  // Pass 3 + 4: commits in the object database that no ref reaches.
  const allShas = store.enumerate();
  const unreachableCommitShas = [];
  for (const sha of allShas) {
    if (seenCommits.has(sha)) continue;
    const object = store.readObject(sha);
    if (object?.type === "commit") unreachableCommitShas.push(sha);
  }
  walkCommits(unreachableCommitShas, false);

  // Pass 5: scan the blob contents.
  let objectsScanned = 0;
  const scanBlob = (blobSha, meta) => {
    const blobObject = store.readObject(blobSha);
    if (!blobObject || blobObject.type !== "blob") return;
    objectsScanned++;
    if (blobObject.data.length > CONFIG.maxFileBytes) {
      notes.push(`skipped: size (${blobSha.slice(0, 12)})`);
      return;
    }
    if (looksBinary(blobObject.data)) return;
    findings.push(...scanText(blobObject.data.toString("utf8"), {
      file: meta.path ?? `git-object:${blobSha.slice(0, 12)}`,
      source: "history",
      blobSha,
      commit: meta.commit ?? null,
      author: meta.author ?? null,
      date: meta.date ?? null,
      reachable: meta.reachable ?? false,
      atHead: headBlobShas.has(blobSha),
    }));
  };

  for (const [blobSha, meta] of blobMeta) scanBlob(blobSha, meta);
  for (const sha of allShas) {
    if (blobMeta.has(sha) || seenCommits.has(sha)) continue;
    const object = store.readObject(sha);
    if (object?.type === "blob") scanBlob(sha, { reachable: false });
  }

  return { findings, objects: objectsScanned };
}

// ===== DETECT =====

// Shannon entropy in bits per character. Random-looking strings score high;
// English words and repeated runs score low.
export function shannonEntropy(text) {
  const charCounts = new Map();
  for (const char of text) charCounts.set(char, (charCounts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of charCounts.values()) {
    const probability = count / text.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

// CRC32: node:zlib has it on modern Node; the table fallback keeps us working on
// older releases without reaching for the crc-32 package.
const crc32 = zlib.crc32
  ? (buf) => zlib.crc32(buf) >>> 0
  : (() => {
      const CRC_TABLE = new Uint32Array(256);
      for (let tableIndex = 0; tableIndex < 256; tableIndex++) {
        let remainder = tableIndex;
        for (let bit = 0; bit < 8; bit++) {
          remainder = remainder & 1 ? 0xedb88320 ^ (remainder >>> 1) : remainder >>> 1;
        }
        CRC_TABLE[tableIndex] = remainder >>> 0;
      }
      return (buf) => {
        let remainder = 0xffffffff;
        for (const byte of buf) remainder = CRC_TABLE[(remainder ^ byte) & 0xff] ^ (remainder >>> 8);
        return (remainder ^ 0xffffffff) >>> 0;
      };
    })();
export { crc32 };

const BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
export function base62(value, width = 6) {
  let encoded = "";
  do {
    encoded = BASE62_ALPHABET[value % 62] + encoded;
    value = Math.floor(value / 62);
  } while (value > 0);
  return encoded.padStart(width, "0");
}

// GitHub classic token: prefix_ + 30 entropy chars + 6 checksum chars, where the
// checksum is base62(CRC32(entropy)). A mismatch means the string is provably
// not a real token, so we can drop it instead of guessing.
// ponytail: alphabet assumed "0-9A-Za-z" per GitHub's blog; verify against a
// real (revoked) token pair before trusting the hard-drop in production.
export function githubChecksum(entropyPart) {
  return base62(crc32(Buffer.from(entropyPart, "utf8")), 6);
}

export function validateGithubToken(token) {
  const tokenBody = token.slice(4); // strip the "ghp_" style prefix
  if (tokenBody.length !== 36) return false;
  return githubChecksum(tokenBody.slice(0, 30)) === tokenBody.slice(30);
}

// The AWS account id is encoded inside the access key id itself, so we can name
// the owning account with no network call. Enrichment, not proof: a well-formed
// random string also decodes to *some* number.
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function awsAccountId(keyId) {
  let decodedBits = 0n;
  for (const char of keyId.slice(4)) {
    const charValue = BASE32_ALPHABET.indexOf(char);
    if (charValue < 0) return null;
    decodedBits = (decodedBits << 5n) | BigInt(charValue);
  }
  const first48Bits = decodedBits >> 32n; // 16 chars x 5 = 80 bits; keep the first 6 bytes
  const accountId = (first48Bits & 0x7fffffffff80n) >> 7n;
  return accountId.toString().padStart(12, "0");
}

// Decodes one base64url JWT segment, or null if it is not JSON.
function decodeBase64UrlJson(segment) {
  try { return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")); }
  catch { return null; }
}

// Values that look like credentials but provably are not: documented examples,
// template syntax, repeated filler, and references to an env var.
const PLACEHOLDER_VALUES = new Set(["AKIAIOSFODNN7EXAMPLE"]);
export function isPlaceholder(value) {
  if (PLACEHOLDER_VALUES.has(value)) return true;
  if (value.length >= 6 && new Set(value).size <= 2) return true; // xxxxxxxx, 00000000
  const lowerValue = value.toLowerCase();
  if (/(example|sample|changeme|change-me|placeholder|dummy|your[_-]|insert[_-]?|fixme|redacted|deadbeef|not[_-]?a[_-]?real|todo\b)/.test(lowerValue)) return true;
  if (/[<>]|\$\{|\{\{|%[sv]/.test(value)) return true;   // <token>, ${VAR}, {{ var }}, %s
  if (/^\$[A-Za-z_]+$/.test(value)) return true;         // $VAR
  if (/process\.env|os\.environ/.test(value)) return true;
  return false;
}

// Words that make a line "about" a credential. The lookarounds reject letters
// on either side but allow "_" and "-", so "access_token" and "api-key" match
// while "tokenizer", "unauthorized", and "author" do not. Plain  would fail
// here: "_" is a word character, so token would miss "access_token".
// Does this line talk about a credential? Two spellings, because one regex
// cannot express both without false positives:
//
//   snake / kebab / standalone  api_key, API-KEY, "auth", token=
//   camelCase                   apiSecret, authToken, dbPassword
//
// A plain \b fails here — "_" is a word character, so \btoken\b misses
// "access_token" — and a plain substring match fires on "unauthorized",
// "tokenizer", and "author", which is the false positive this replaced.
const CTX_WORDS = "(secret|token|passwd|password|api[_-]?key|apikey|credential|private[_-]?key|authorization|auth)";
const CTX_SNAKE = new RegExp(`(?<![A-Za-z])${CTX_WORDS}(?![A-Za-z])`, "i");
// In camelCase the word starts with a capital, so a preceding lowercase letter
// or digit *is* the boundary. Case-sensitive on purpose.
const CTX_CAMEL = /(?<=[a-z0-9])(Secret|Token|Passwd|Password|ApiKey|Apikey|Credential|PrivateKey|Authorization|Auth)(?![a-z])/;
const isSecretContext = (line) => CTX_SNAKE.test(line) || CTX_CAMEL.test(line);
const CTX_DUMMY = /(example|dummy|sample|fake|mock|spec)/i;
const LOCKFILES = new Set([
  "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock",
  "poetry.lock", "composer.lock", "gemfile.lock", "go.sum",
]);

// Rule records: detection + remediation are one table, not two.
export const RULES = [
  {
    id: "github-token-classic", name: "GitHub token (classic)", severity: "critical",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g,
    validate: (v) => validateGithubToken(v), // bad checksum → drop with certainty
    envName: "GITHUB_TOKEN",
    advice: [
      "Revoke the token: GitHub → Settings → Developer settings → Personal access tokens",
      "Issue a replacement with the minimum scopes needed",
      "Replace the literal with process.env.GITHUB_TOKEN",
      "If it ever reached a remote, treat it as compromised even after deletion",
    ],
    reference: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure",
  },
  {
    id: "github-pat-fine-grained", name: "GitHub fine-grained PAT", severity: "critical",
    pattern: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g,
    envName: "GITHUB_TOKEN",
    advice: [
      "Revoke the token in GitHub → Settings → Developer settings → Fine-grained tokens",
      "Issue a replacement scoped to the specific repositories it needs",
      "Replace the literal with process.env.GITHUB_TOKEN",
    ],
    reference: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure",
  },
  {
    id: "aws-access-key-id", name: "AWS access key ID", severity: "high",
    pattern: /\b(?:AKIA|ASIA)[A-Z2-7]{16}\b/g,
    enrich: (v) => {
      const acct = awsAccountId(v);
      return acct ? `belongs to AWS account ${acct} (derived offline — enrichment, not proof)` : null;
    },
    envName: "AWS_ACCESS_KEY_ID",
    advice: [
      "Disable the key in the owning account's IAM console (see derived account id)",
      "Create a replacement key or switch to role-based credentials",
      "Move the value to the environment or a secrets manager",
      "Search history for the paired secret access key — it usually travels with the id",
    ],
    reference: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
  },
  {
    id: "aws-secret-access-key", name: "AWS secret access key", severity: "critical",
    pattern: /(?:aws[_-]?)?secret[_-]?(?:access[_-]?)?key['"]?\s*[:=]+\s*['"]?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
    group: 1,
    envName: "AWS_SECRET_ACCESS_KEY",
    advice: [
      "Disable the paired access key in IAM immediately",
      "Create a replacement and store it in the environment or a secrets manager",
      "Audit CloudTrail for use of the exposed key",
    ],
    reference: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
  },
  {
    id: "pem-private-key", name: "Private key (PEM)", severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    severityFor: (m) => (m[0].includes("ENCRYPTED") ? "high" : "critical"),
    enrich: (v) => (v.includes("ENCRYPTED") ? "encrypted — lower exposure unless the passphrase leaked too" : null),
    envName: null,
    advice: [
      "Revoke the certificate or key pair wherever it is trusted",
      "Generate a new pair; load it from a file path outside the repo, never inline",
      "Purge the old key from deploy targets and history",
    ],
    reference: "https://datatracker.ietf.org/doc/html/rfc7468",
  },
  {
    id: "jwt", name: "JSON Web Token", severity: "high",
    pattern: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    validate: (v) => {
      const hdr = decodeBase64UrlJson(v.split(".")[0]);
      return !!hdr && typeof hdr.alg === "string";
    },
    severityFor: (m) => {
      const [h, p] = m[0].split(".");
      const hdr = decodeBase64UrlJson(h), pay = decodeBase64UrlJson(p) ?? {};
      if (hdr?.alg?.toLowerCase() === "none") return "critical";
      if (typeof pay.exp === "number" && pay.exp * 1000 < Date.now()) return "medium"; // expired
      return "high";
    },
    enrich: (v) => {
      const hdr = decodeBase64UrlJson(v.split(".")[0]);
      const pay = decodeBase64UrlJson(v.split(".")[1]) ?? {};
      if (hdr?.alg?.toLowerCase() === "none") return 'alg "none" — the token is unsigned; that is a vulnerability in itself';
      if (typeof pay.exp !== "number") return "no exp claim — token never expires";
      return null;
    },
    placeholder: (v) => {
      const pay = decodeBase64UrlJson(v.split(".")[1]);
      return pay?.sub === "1234567890" && pay?.name === "John Doe"; // the jwt.io sample
    },
    envName: "JWT_SECRET",
    advice: [
      "Rotate the signing secret",
      "Invalidate outstanding tokens signed with it",
      "Move the secret to the environment",
      "Never log decoded payloads — they may carry PII or further secrets",
    ],
    reference: "https://datatracker.ietf.org/doc/html/rfc7519",
  },
  {
    id: "stripe-secret-key", name: "Stripe secret key", severity: "critical",
    pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    severityFor: (m) => (m[0].includes("_test_") ? "low" : "critical"),
    enrich: (v) => (v.includes("_test_") ? "test-mode key — low direct risk, still rotate" : null),
    envName: "STRIPE_SECRET_KEY",
    advice: [
      "Roll the key: Stripe Dashboard → Developers → API keys",
      "Replace the literal with process.env.STRIPE_SECRET_KEY",
      "Review Stripe logs for unauthorized use",
    ],
    reference: "https://docs.stripe.com/keys",
  },
  {
    id: "slack-token", name: "Slack token", severity: "high",
    pattern: /\bxox[baprsoe]-[A-Za-z0-9-]{10,}\b/g,
    envName: "SLACK_TOKEN",
    advice: [
      "Revoke the token: Slack app settings → OAuth & Permissions",
      "Reinstall the app to mint a fresh token",
      "Replace the literal with process.env.SLACK_TOKEN",
    ],
    reference: "https://api.slack.com/authentication/token-types",
  },
  {
    id: "slack-webhook", name: "Slack incoming webhook URL", severity: "medium",
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
    envName: "SLACK_WEBHOOK_URL",
    advice: [
      "Regenerate the webhook in the Slack app configuration",
      "Replace the literal with process.env.SLACK_WEBHOOK_URL",
    ],
    reference: "https://api.slack.com/messaging/webhooks",
  },
  {
    id: "google-api-key", name: "Google API key", severity: "medium",
    pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g,
    enrich: () => "browser-embedded Google keys are often intentionally public — verify restrictions instead of assuming compromise",
    envName: "GOOGLE_API_KEY",
    advice: [
      "Check key restrictions in Google Cloud Console → Credentials",
      "Regenerate if unrestricted; add HTTP referrer / IP restrictions",
    ],
    reference: "https://cloud.google.com/docs/authentication/api-keys",
  },
  {
    id: "anthropic-api-key", name: "Anthropic API key", severity: "critical",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    envName: "ANTHROPIC_API_KEY",
    advice: [
      "Revoke the key in the Anthropic Console",
      "Issue a replacement and store it in the environment",
    ],
    reference: "https://docs.anthropic.com/en/api/getting-started",
  },
  {
    id: "openai-api-key", name: "OpenAI API key", severity: "critical",
    pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{40,}\b/g,
    envName: "OPENAI_API_KEY",
    advice: [
      "Revoke the key in the OpenAI dashboard",
      "Issue a replacement and store it in the environment",
    ],
    reference: "https://platform.openai.com/docs/api-reference/authentication",
  },
  {
    id: "npm-token", name: "npm access token", severity: "high",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    envName: "NPM_TOKEN",
    advice: [
      "Revoke: npm token revoke, or npmjs.com → Access Tokens",
      "Issue a replacement (prefer granular tokens)",
      "A leaked publish token is a supply-chain incident — audit recent publishes",
    ],
    reference: "https://docs.npmjs.com/about-access-tokens",
  },
  {
    id: "sendgrid-api-key", name: "SendGrid API key", severity: "high",
    pattern: /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b/g,
    envName: "SENDGRID_API_KEY",
    advice: ["Delete the key in SendGrid → Settings → API Keys", "Issue a scoped replacement"],
    reference: "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys",
  },
  {
    id: "twilio-api-key", name: "Twilio API key SID", severity: "high",
    pattern: /\bSK[0-9a-f]{32}\b/g,
    envName: "TWILIO_API_KEY",
    advice: ["Delete the key in the Twilio Console", "Issue a replacement and move it to the environment"],
    reference: "https://www.twilio.com/docs/iam/api-keys",
  },
  {
    id: "connection-uri", name: "Connection string with password", severity: "high",
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/([^\s:@/]+):([^\s@/]+)@[^\s"'`]+/g,
    validate: (v, m) => !isPlaceholder(m[2]) && !["password", "postgres", "root", "admin", "pass"].includes(m[2].toLowerCase()),
    severityFor: (m) => (/@(localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(m[0]) ? "medium" : "high"),
    envName: "DATABASE_URL",
    advice: [
      "Rotate the database password",
      "Replace the literal with process.env.DATABASE_URL",
      "Restrict network access to the database while rotating",
    ],
    reference: "https://www.postgresql.org/docs/current/libpq-connstring.html",
  },
];

const GENERIC_ADVICE = {
  envName: null,
  advice: [
    "Triage: confirm this is a live credential, not test data",
    "If real: rotate it at the provider, then remove the literal",
    "If a false positive: add its fingerprint to the baseline file",
  ],
  reference: null,
};

// Precomputes line-start offsets so a string index can be turned into a
// line:col pair by binary search rather than counting newlines each time.
function lineIndexer(text) {
  const lineStarts = [0];
  for (let charIndex = 0; charIndex < text.length; charIndex++) {
    if (text[charIndex] === "\n") lineStarts.push(charIndex + 1);
  }
  return {
    starts: lineStarts,
    at(charIndex) {
      let low = 0, high = lineStarts.length - 1;
      while (low < high) {
        const mid = (low + high + 1) >> 1;
        if (lineStarts[mid] <= charIndex) low = mid; else high = mid - 1;
      }
      return { line: low + 1, col: charIndex - lineStarts[low] + 1 };
    },
    lineText(lineNumber) {
      const lineStart = lineStarts[lineNumber - 1];
      const lineEnd = lineNumber < lineStarts.length ? lineStarts[lineNumber] - 1 : text.length;
      return text.slice(lineStart, lineEnd).replace(/\r$/, "");
    },
  };
}

const downgrade = (severity) => SEVERITIES[Math.max(1, SEVERITIES.indexOf(severity) - 1)];

// The only place secrets are found. Both working-tree files and git blobs arrive
// here as a string plus metadata describing where the string came from.
export function scanText(text, meta) {
  const findings = [];
  const lineIndex = lineIndexer(text);
  const fileName = path.posix.basename((meta.file ?? "").toLowerCase());
  const filePath = (meta.file ?? "").toLowerCase();
  const isLockfile = LOCKFILES.has(fileName);
  const isEnvLikeFile = /(^|\/)\.env(\..+)?$|credentials|\.tfvars$|(^|\/)\.github\/.+\.ya?ml$|\.gitlab-ci\.ya?ml$/.test(filePath);

  // Values a rule rejected with certainty. The entropy pass must not resurrect
  // them, or a bad-checksum token would be reported anyway and the validation
  // would have bought nothing.
  const rejectedValues = [];

  const addFinding = (rule, value, charIndex, severity, note) => {
    const { line, col } = lineIndex.at(charIndex);
    const lineText = lineIndex.lineText(line);
    // Judge the words *around* the value, not the value itself: a secret that
    // happens to contain "sample" should not downgrade on its own account.
    const contextWithoutValue = lineText.split(value).join("");
    if (CTX_DUMMY.test(contextWithoutValue)) severity = downgrade(severity);
    findings.push({
      rule: rule.id, ruleName: rule.name, severity, value, line, col,
      note: note ?? null, envName: rule.envName ?? null,
      ...meta,
    });
  };

  // Layer 1-2: known credential shapes, with optional offline validation.
  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    for (const match of text.matchAll(rule.pattern)) {
      const value = match[rule.group ?? 0];
      if (isPlaceholder(value)) { rejectedValues.push(value); continue; }
      if (rule.placeholder?.(value)) { rejectedValues.push(value); continue; }
      if (rule.validate && !rule.validate(value, match)) { rejectedValues.push(value); continue; }
      const severity = rule.severityFor ? rule.severityFor(match) : rule.severity;
      addFinding(rule, value, match.index, severity, rule.enrich?.(value) ?? null);
    }
  }

  // Layer 3: entropy, which requires a second signal — a secret-ish word on the
  // line, or a filename that is inherently about credentials.
  if (isLockfile) return findings;

  for (let lineNumber = 1; lineNumber <= lineIndex.starts.length; lineNumber++) {
    const lineText = lineIndex.lineText(lineNumber);
    if (!lineText || lineText.length > CONFIG.longLineSkip) continue; // minified or bundled
    if (/data:[^;]+;base64,/.test(lineText)) continue;                // embedded asset
    if (!(isSecretContext(lineText) || isEnvLikeFile)) continue;    // no second signal

    for (const match of lineText.matchAll(/[A-Za-z0-9+/=_-]{20,}/g)) {
      const candidate = match[0];
      if (isPlaceholder(candidate)) continue;
      if (rejectedValues.some((rejected) => rejected.includes(candidate) || candidate.includes(rejected))) continue;
      if (/(.)\1{7,}/.test(candidate)) continue;                       // long repeated run
      if (/^[0-9a-f]{40}$/i.test(candidate)) continue;                 // git sha
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(candidate)) continue; // uuid
      if (candidate.startsWith("sha512-") || candidate.startsWith("sha256-")) continue; // integrity hash

      const isHex = /^[0-9a-fA-F]+$/.test(candidate);
      const isHighEntropy = isHex
        ? candidate.length >= CONFIG.entropyHexMinLen && shannonEntropy(candidate) >= CONFIG.entropyHex
        : candidate.length >= CONFIG.entropyBase64MinLen && shannonEntropy(candidate) >= CONFIG.entropyBase64;
      if (!isHighEntropy) continue;

      addFinding(
        { id: "generic-high-entropy", name: "High-entropy string in secret context", envName: null },
        candidate, lineIndex.starts[lineNumber - 1] + match.index, "medium", null,
      );
    }
  }

  return findings;
}

// ===== CLASSIFY =====

// Masks a secret for display. Short values become all asterisks so a 6-character
// value does not leak two thirds of itself.
export function redact(value) {
  if (value.length <= 8) return "*".repeat(value.length);
  return value.slice(0, 4) + "…" + value.slice(-2);
}

// Paths where a credential-shaped string is probably test data or documentation.
const FIXTUREISH = /(^|\/)(tests?|__tests__|__snapshots__|fixtures?|spec|examples?|docs?)(\/|$)|\.(example|sample|template)(\.|$)/;

// Turns raw hits into the reported set: shadow generic entropy behind specific
// rules, downgrade fixture paths, fingerprint, apply the baseline, dedupe, sort.
export function classify(rawFindings, opts, baselineFingerprints = new Set()) {
  const findingByFingerprint = new Map();
  let suppressedCount = 0;

  // A named rule and the entropy layer often fire on the same value; the named
  // rule carries better severity and advice, so the generic hit is dropped.
  const locationsWithNamedRule = new Set(
    rawFindings
      .filter((finding) => finding.rule !== "generic-high-entropy")
      .map((finding) => `${finding.file}:${finding.line}`),
  );

  for (const finding of rawFindings) {
    const location = `${finding.file}:${finding.line}`;
    if (finding.rule === "generic-high-entropy" && locationsWithNamedRule.has(location)) continue;
    // Downgrade, never drop: a real secret can still be committed under tests/.
    if (FIXTUREISH.test(finding.file)) finding.severity = downgrade(finding.severity);

    const valueHash = crypto.createHash("sha256").update(finding.value).digest("hex").slice(0, 16);
    finding.fingerprint = `${finding.rule}:${valueHash}:${finding.file}`;
    finding.redacted = redact(finding.value);

    if (baselineFingerprints.has(finding.fingerprint)) { suppressedCount++; continue; }

    const existing = findingByFingerprint.get(finding.fingerprint);
    const isMoreSevere = !existing ||
      SEVERITIES.indexOf(finding.severity) > SEVERITIES.indexOf(existing.severity);
    if (isMoreSevere) findingByFingerprint.set(finding.fingerprint, finding);
  }

  const findings = [...findingByFingerprint.values()].sort((a, b) =>
    SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) ||
    a.file.localeCompare(b.file) ||
    a.line - b.line,
  );
  return { findings, suppressed: suppressedCount };
}

// ===== REPORT =====

// Score formula, documented in the README: 100 minus the summed severity
// weights, floored at zero.
export function securityScore(findings) {
  const deductions = findings.reduce(
    (total, finding) => total + (SEV_WEIGHT[finding.severity] ?? 0), 0);
  return Math.max(0, 100 - deductions);
}

function severityCounts(findings) {
  const counts = {};
  for (const severity of SEVERITIES) counts[severity] = 0;
  for (const finding of findings) counts[finding.severity]++;
  return counts;
}

// The bracketed provenance label: where the secret lives and whether git can see it.
function findingTag(finding) {
  if (finding.source === "tree") return "working tree";
  const labelParts = ["history"];
  if (finding.commit) labelParts.push(finding.commit.slice(0, 8));
  if (finding.reachable === false) labelParts.push("UNREACHABLE — invisible to git log");
  else if (!finding.atHead) labelParts.push("removed from HEAD");
  return labelParts.join(", ");
}

// Terminal width, defaulting to 80 when not attached to a TTY.
const termWidth = () => Math.max(60, Math.min(process.stdout.columns || 80, 120));

// ANSI sequences occupy no columns — measure printable text only.
const visibleLength = (text) => String(text).replace(/\x1b\[[0-9;]*m/g, "").length;

// Own column formatter (replaces cli-table3): measure, then pad to the widest cell.
function columns(rows) {
  const widths = [];
  for (const row of rows) {
    row.forEach((cell, i) => { widths[i] = Math.max(widths[i] ?? 0, visibleLength(cell)); });
  }
  return rows.map((row) =>
    row.map((cell, i) =>
      i === row.length - 1 ? cell : cell + " ".repeat(widths[i] - visibleLength(cell))));
}

function wrap(text, width) {
  const words = String(text).split(/\s+/);
  const wrappedLines = [];
  let currentLine = "";
  for (const word of words) {
    if (currentLine && visibleLength(currentLine) + word.length + 1 > width) {
      wrappedLines.push(currentLine);
      currentLine = word;
    } else {
      currentLine = currentLine ? currentLine + " " + word : word;
    }
  }
  if (currentLine) wrappedLines.push(currentLine);
  return wrappedLines;
}

// 16 identical "skipped: size (path)" lines are noise; paths stay in --format json.
function collapseNotes(notes) {
  const groups = new Map();
  for (const n of notes) {
    const key = n.replace(/\s*\(.*\)\s*$/, "");
    groups.set(key, (groups.get(key) ?? 0) + 1);
  }
  return [...groups].map(([key, n]) => (n === 1 ? key : `${key} × ${n}`));
}

// Progress on stderr (replaces ora / cli-progress). TTY only, so piped output
// and CI logs stay clean. Erases itself before the report is written.
export function makeProgress(stream = process.stderr) {
  if (!stream.isTTY || process.env.NO_COLOR) return { tick() {}, done() {} };
  let last = 0;
  return {
    tick(done, total, label) {
      const now = Date.now();
      if (now - last < 80) return; // ponytail: fixed throttle, adaptive if it ever flickers
      last = now;
      const pct = total ? Math.floor((done / total) * 100) : 0;
      const line = `  scanning ${String(pct).padStart(3)}%  ${done}/${total}  ${label ?? ""}`;
      stream.write("\r" + line.slice(0, (stream.columns || 80) - 1) + "\x1b[K");
    },
    done() { stream.write("\r\x1b[K"); },
  };
}

const SEV_DOT = { critical: "●", high: "●", medium: "◆", low: "○", info: "·" };

function scoreBar(score) {
  const filled = Math.round(score / 5);
  const barColor = score >= 90 ? c.green : score >= 70 ? c.yellow : c.red;
  return barColor("█".repeat(filled)) + c.gray("░".repeat(20 - filled));
}

// Contextual hints — only suggest flags this run did not already use.
function nextSteps(result, opts) {
  const steps = [];
  if (!opts.history) steps.push(["--history", "also scan git history, including unreachable objects"]);
  if (result.findings.length && !opts.remediate) steps.push(["--remediate", "write an ordered fix plan and .env.example keys"]);
  if (result.findings.length && !opts.showSecrets) steps.push(["--unsafe-show-secrets", "reveal full values (redacted above)"]);
  if (result.findings.length) steps.push(["--format json", "machine-readable, keeps every skipped-file path"]);
  return steps.slice(0, 3);
}

function renderTty(result, opts) {
  const { findings, filesScanned, objectsScanned, notes, elapsedMs, suppressed } = result;
  const W = termWidth();
  const outputLines = [];

  outputLines.push("");
  outputLines.push("  " + c.bold(c.magenta("LeakLens")) + c.gray(` v${VERSION}`) + c.gray("  ·  ") + c.gray(result.root));
  const scanned = [`${filesScanned} files`];
  if (opts.history) scanned.push(`${objectsScanned} git objects`);
  scanned.push(`${(elapsedMs / 1000).toFixed(1)}s`);
  outputLines.push("  " + c.gray(scanned.join(" · ")));
  outputLines.push("");

  if (findings.length === 0) {
    outputLines.push("  " + c.green("✔ No findings."));
    outputLines.push("  " + c.gray("A clean scan is not proof of absence — detection is heuristic."));
    if (!opts.history) outputLines.push("  " + c.gray("Secrets deleted from HEAD still live in .git — try --history."));
    outputLines.push("");
  }

  // findings grouped by file; columns aligned within each group
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }
  for (const [file, group] of byFile) {
    outputLines.push("  " + c.bold(c.cyan(file)));
    const rows = columns(group.map((finding) => [
      SEV_COLOR[finding.severity](`${SEV_DOT[finding.severity]} ${finding.severity}`),
      c.gray(`${finding.line}:${finding.col}`),
      finding.rule,
      opts.showSecrets ? finding.value : finding.redacted,
    ]));
    group.forEach((f, i) => {
      outputLines.push("    " + rows[i].join("  ") + "  " + c.gray(findingTag(f)));
      const detail = [];
      if (f.note) detail.push(f.note);
      if (f.author) detail.push(`committed by ${f.author}${f.date ? " on " + f.date : ""}`);
      for (const d of detail) {
        wrap("↳ " + d, W - 10).forEach((line, li) =>
          outputLines.push((li === 0 ? "      " : "        ") + c.gray(line)));
      }
    });
    outputLines.push("");
  }

  // summary
  const counts = severityCounts(findings);
  const severityParts = SEVERITIES.filter((severity) => counts[severity]).reverse()
    .map((severity) => SEV_COLOR[severity](`${counts[severity]} ${severity}`));
  const score = securityScore(findings);
  outputLines.push("  " + c.gray("─".repeat(W - 4)));
  outputLines.push("  " + c.bold(`Score ${score}/100`) + "  " + scoreBar(score));
  if (findings.length) outputLines.push("  " + `${findings.length} finding(s)` + c.gray(" · ") + severityParts.join(c.gray(" · ")));
  if (suppressed) outputLines.push("  " + c.gray(`${suppressed} suppressed by baseline`));

  const collapsed = collapseNotes(notes);
  if (collapsed.length) {
    outputLines.push("");
    for (const n of collapsed) outputLines.push("  " + c.gray("note: " + n));
  }

  const steps = nextSteps(result, opts);
  if (steps.length) {
    outputLines.push("");
    outputLines.push("  " + c.bold("Next"));
    for (const row of columns(steps.map(([flag, why]) => [c.cyan(flag), c.gray(why)]))) {
      outputLines.push("    " + row.join("  "));
    }
  }
  outputLines.push("");
  return outputLines.join("\n");
}

function jsonReport(result, opts) {
  return JSON.stringify({
    tool: "LeakLens", version: VERSION,
    root: result.root, scannedAt: new Date().toISOString(),
    summary: {
      files: result.filesScanned, objects: result.objectsScanned,
      historyScanned: !!opts.history,
      score: securityScore(result.findings),
      counts: severityCounts(result.findings),
      suppressed: result.suppressed,
      notes: result.notes,
    },
    findings: result.findings.map((finding) => ({
      fingerprint: finding.fingerprint, rule: finding.rule, severity: finding.severity,
      file: finding.file, line: finding.line, col: finding.col, source: finding.source,
      secret: opts.showSecrets ? finding.value : finding.redacted,
      note: finding.note, envName: finding.envName,
      commit: finding.commit ?? null, author: finding.author ?? null, date: finding.date ?? null,
      reachable: finding.reachable ?? null, atHead: finding.atHead ?? null,
      blobSha: finding.blobSha ?? null,
    })),
  }, null, 2);
}

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

function sarifReport(result, opts) {
  const usedRules = [...new Set(result.findings.map((finding) => finding.rule))];
  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "LeakLens", version: VERSION,
        informationUri: "https://github.com/", // FILL at submission
        rules: usedRules.map((ruleId) => {
          const rule = RULES.find((candidate) => candidate.id === ruleId);
          return { id: ruleId, name: rule?.name ?? ruleId, shortDescription: { text: rule?.name ?? ruleId } };
        }),
      } },
      results: result.findings.map((finding) => ({
        ruleId: finding.rule,
        level: SARIF_LEVEL[finding.severity] ?? "warning",
        message: { text: `${finding.ruleName ?? finding.rule}: ${opts.showSecrets ? finding.value : finding.redacted}${finding.note ? ` (${finding.note})` : ""}` },
        partialFingerprints: { primaryLocationLineHash: finding.fingerprint },
        locations: [{ physicalLocation: {
          artifactLocation: { uri: finding.file },
          region: { startLine: finding.line, startColumn: finding.col },
        } }],
      })),
    }],
  }, null, 2);
}

// ===== REMEDIATE =====

// Remediation advice lives on the rule record, so no rule can ship without a
// fix path. Findings from the entropy layer fall back to generic triage steps.
function adviceFor(finding) {
  const rule = RULES.find((candidate) => candidate.id === finding.rule);
  return rule?.advice
    ? { advice: rule.advice, envName: rule.envName, reference: rule.reference }
    : GENERIC_ADVICE;
}

// Markdown fix plan. Values are redacted, so this file is safe to share and
// safe to commit — unlike the patch, which is not.
function remediationPlan(result) {
  const planLines = [
    "# LeakLens remediation plan", "",
    `Generated for \`${result.root}\`. Values are redacted — this file is safe to share.`,
    "",
    "> Rotation happens at the provider and cannot be verified offline.",
    "> Deleting a literal from the repo does **not** un-leak it: anything that reached",
    "> a remote must be rotated regardless.", "",
  ];

  for (const finding of result.findings) {
    const { advice, envName, reference } = adviceFor(finding);
    planLines.push(`## ${finding.severity.toUpperCase()} · ${finding.ruleName ?? finding.rule} — \`${finding.file}:${finding.line}\``);
    planLines.push("");
    planLines.push(`Found: \`${finding.redacted}\` (${findingTag(finding)})`);
    if (finding.note) planLines.push(`Note: ${finding.note}`);

    if (finding.source === "history" && finding.reachable === false) {
      planLines.push("This blob is **unreachable from any ref** — `git log -p` cannot show it, but anyone with a clone of `.git` can read it. Rotation is mandatory.");
    } else if (finding.source === "history") {
      planLines.push("This secret lives in git history. Removing it from the working tree is not enough — rotate it, then optionally rewrite history.");
    }

    planLines.push("");
    advice.forEach((step, stepIndex) => planLines.push(`${stepIndex + 1}. ${step}`));
    if (envName) planLines.push(`\nSuggested replacement: \`process.env.${envName}\``);
    if (reference) planLines.push(`Reference: ${reference}`);
    planLines.push("");
  }

  const historyFindingCount = result.findings.filter((finding) => finding.source === "history").length;
  if (historyFindingCount) {
    planLines.push("## Cleaning git history (printed, never executed by LeakLens)", "");
    planLines.push("After rotating, if you also want the bytes gone from `.git`:", "");
    planLines.push("```sh");
    planLines.push("# coordinate with everyone who has a clone first — this rewrites history");
    planLines.push("git filter-repo --replace-text <(echo 'THE_SECRET==>REDACTED')  # or BFG");
    planLines.push("git reflog expire --expire=now --all && git gc --prune=now --aggressive");
    planLines.push("```", "");
  }

  return planLines.join("\n");
}

// Just the env var names, so the developer has somewhere to put the new values.
function envExample(result) {
  const envNames = [...new Set(result.findings.map((finding) => finding.envName).filter(Boolean))];
  if (!envNames.length) return "";
  return "# Generated by LeakLens — fill locally, never commit real values\n" +
    envNames.map((envName) => `${envName}=`).join("\n") + "\n";
}

// Rewrites one source line, preferring to swap the whole quoted literal so the
// surrounding quotes go with it.
function replaceLine(lineText, finding) {
  const envReference = `process.env.${finding.envName}`;
  for (const quote of ['"', "'", "`"]) {
    const quotedValue = quote + finding.value + quote;
    if (lineText.includes(quotedValue)) return lineText.replace(quotedValue, envReference);
  }
  return lineText.replace(finding.value, envReference);
}

// Unified diff replacing literals with process.env references. Working-tree
// findings only — a historical blob has no file on disk left to patch.
// The output contains the secrets in cleartext; the caller guards where it lands.
function emitPatch(root, findings) {
  const findingsByFile = new Map();
  for (const finding of findings) {
    if (finding.source !== "tree" || !finding.envName) continue;
    if (!findingsByFile.has(finding.file)) findingsByFile.set(finding.file, []);
    findingsByFile.get(finding.file).push(finding);
  }

  const patchLines = [];
  for (const [file, fileFindings] of findingsByFile) {
    let fileText;
    try { fileText = fs.readFileSync(path.join(root, file), "utf8"); } catch { continue; }
    const sourceLines = fileText.split("\n");

    for (const finding of fileFindings.sort((a, b) => a.line - b.line)) {
      const originalLine = sourceLines[finding.line - 1];
      if (originalLine === undefined || !originalLine.includes(finding.value)) continue;
      patchLines.push(`--- a/${file}`);
      patchLines.push(`+++ b/${file}`);
      patchLines.push(`@@ -${finding.line},1 +${finding.line},1 @@`);
      patchLines.push(`-${originalLine}`);
      patchLines.push(`+${replaceLine(originalLine, finding)}`);
    }
  }
  return patchLines.length ? patchLines.join("\n") + "\n" : "";
}

// ===== BUILD & PROOF =====
// The build lives inside the single file on purpose: adding build.mjs would
// make the project two source files and forfeit the Single File claim.
// `node leaklens.mjs --build` is the one documented build command.

const SELF_PATH = fileURLToPath(import.meta.url);

// Nearest ancestor directory containing `fileName`, or null.
function findUpwards(startDir, fileName) {
  let currentDir = path.resolve(startDir);
  for (let depth = 0; depth < 64; depth++) {
    const candidate = path.join(currentDir, fileName);
    if (fs.existsSync(candidate)) return candidate;
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) return null;
    currentDir = parentDir;
  }
  return null;
}

// Deterministic by construction: no timestamps, no hostname, no absolute paths,
// no environment data. Same input bytes in, same output bytes out, on any
// machine, forever. That is the whole requirement of a reproducible build.
export function buildSelf(outDirArg, { silent = false } = {}) {
  const outDir = path.resolve(outDirArg ?? "dist");
  const rawSource = fs.readFileSync(SELF_PATH, "utf8");

  const normalizedSource = rawSource
    .replace(/^﻿/, "")      // strip a BOM if an editor added one
    .replace(/\r\n/g, "\n")      // LF only, so Windows and Linux agree
    .replace(/[ \t]+$/gm, "")    // no trailing whitespace
    .replace(/\n*$/, "\n");      // exactly one final newline

  const banner =
    `// LeakLens v${VERSION} — built artifact\n` +
    "// Built by: node leaklens.mjs --build\n" +
    "// This header is fixed text; the build embeds no timestamp, path, or host,\n" +
    "// so two builds of the same source are byte-identical.\n";
  const artifact = banner + normalizedSource;

  fs.mkdirSync(outDir, { recursive: true });
  const artifactPath = path.join(outDir, "leaklens.mjs");
  fs.writeFileSync(artifactPath, artifact);

  const digest = crypto.createHash("sha256").update(artifact).digest("hex");
  // sha256sum format: hash, two spaces, filename
  fs.writeFileSync(path.join(outDir, "SHA256SUMS"), `${digest}  leaklens.mjs\n`);

  if (silent) return { artifactPath, digest };
  process.stdout.write(
    `\n  ${c.bold("Build complete")}\n` +
    `    ${artifactPath}\n` +
    `    ${Buffer.byteLength(artifact)} bytes\n\n` +
    `  ${c.bold("SHA-256")}\n` +
    `    ${digest}\n\n` +
    `  Reproduce: run this command twice and compare dist/SHA256SUMS.\n\n`,
  );
  return { artifactPath, digest };
}

// Static proof of the two claims the README makes: zero third-party code, and
// no way to reach the network or another process. Deliberately reads the source
// rather than executing anything — LeakLens never spawns a subprocess, so it
// cannot run `npm ls` on its own behalf. Run that separately; see README.
export function proveDependencies({ silent = false } = {}) {
  const source = fs.readFileSync(SELF_PATH, "utf8");
  const checks = [];

  // The built artifact in dist/ has no manifest beside it, so search upward and
  // report honestly when there is none rather than crashing.
  const manifestPath = findUpwards(path.dirname(SELF_PATH), "package.json");
  if (manifestPath) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const dependencyCount = Object.keys(manifest.dependencies ?? {}).length;
    const devDependencyCount = Object.keys(manifest.devDependencies ?? {}).length;
    checks.push(["manifest dependencies", dependencyCount === 0, `${dependencyCount} found`]);
    checks.push(["manifest devDependencies", devDependencyCount === 0, `${devDependencyCount} found`]);
  } else {
    checks.push(["manifest dependencies", true, "no package.json found — skipped"]);
  }

  const importSpecifiers = [...source.matchAll(/^import\s+.*?from\s+["']([^"']+)["']/gm)].map((m) => m[1]);
  const thirdPartyImports = importSpecifiers.filter((specifier) => !specifier.startsWith("node:"));
  checks.push([
    `every import is node: (${importSpecifiers.length} total)`,
    thirdPartyImports.length === 0,
    thirdPartyImports.join(", ") || "none",
  ]);

  // The needles are assembled from fragments, and the labels avoid the literal
  // tokens, so this checker does not flag its own source. Spelling any of them out
  // here would make the file fail its own audit and break the proof test in tests/.
  const needle = (...fragments) => new RegExp(fragments.join(""));
  const forbidden = [
    ["no subprocess module", needle("child", "_pro", "cess")],
    ["no CommonJS loader", needle("\\b", "requ", "ire\\s*\\(")],
    ["no dynamic module load", needle("\\b", "imp", "ort\\s*\\(")],
    ["no socket modules", /node:(https?|net|dgram|tls)/],
    ["no network client API", needle("\\b", "fet", "ch\\s*\\(|Web", "Sock", "et|XML", "HttpRequest")],
  ];
  for (const [label, pattern] of forbidden) {
    checks.push([label, !pattern.test(source), pattern.test(source) ? "found" : "clean"]);
  }

  const allPassed = checks.every(([, passed]) => passed);
  const lines = ["", `  ${c.bold("Dependency proof")}  ${c.gray(path.basename(SELF_PATH))}`, ""];
  for (const [label, passed, detail] of checks) {
    lines.push(`    ${passed ? c.green("✔") : c.red("✘")} ${label.padEnd(38)} ${c.gray(detail)}`);
  }
  lines.push("");
  lines.push(`  ${allPassed ? c.green("All checks passed.") : c.red("FAILED.")}`);
  lines.push(c.gray("  Complete the proof with:  npm ls --all   (expects an empty tree)"));
  lines.push("");
  if (!silent) process.stdout.write(lines.join("\n"));
  return allPassed;
}

// ===== MAIN =====

// Top-level orchestration: walk the working tree, optionally read git history,
// apply the baseline, then classify. Pure — writes nothing, exits nothing.
export function scan(rootArg, opts, progress = { tick() {}, done() {} }) {
  const root = path.resolve(rootArg);
  const notes = [];
  const startedAt = Date.now();
  const rawFindings = [];

  const filePaths = walkFiles(root, opts, notes);
  let filesRead = 0;
  for (const relPath of filePaths) {
    progress.tick(++filesRead, filePaths.length, relPath);
    let fileBuf;
    try { fileBuf = fs.readFileSync(path.join(root, relPath)); }
    catch (err) { notes.push(`unreadable file: ${relPath} (${err.code})`); continue; }
    // Skipping is recorded, never silent: a scanner that quietly skips is lying.
    if (fileBuf.length > CONFIG.maxFileBytes) { notes.push(`skipped: size (${relPath})`); continue; }
    if (looksBinary(fileBuf)) continue;
    rawFindings.push(...scanText(fileBuf.toString("utf8"), { file: relPath, source: "tree" }));
  }

  let objectsScanned = 0;
  if (opts.history) {
    progress.tick(filePaths.length, filePaths.length, "reading .git objects");
    const historyResult = scanHistory(root, opts, notes);
    rawFindings.push(...historyResult.findings);
    objectsScanned = historyResult.objects;
  }

  let baselineFingerprints = new Set();
  if (opts.baseline) {
    try {
      const baselineFile = readJson(opts.baseline);
      baselineFingerprints = new Set(
        baselineFile.fingerprints ?? (baselineFile.findings ?? []).map((finding) => finding.fingerprint));
    } catch (err) { notes.push(`baseline unreadable: ${err.message}`); }
  }

  progress.done();
  const { findings, suppressed } = classify(rawFindings, opts, baselineFingerprints);
  return {
    root, findings, suppressed,
    filesScanned: filePaths.length, objectsScanned, notes,
    elapsedMs: Date.now() - startedAt,
  };
}

// Tolerates the UTF-8 BOM that PowerShell redirection prepends to a saved report.
const readJson = (filePath) => JSON.parse(fs.readFileSync(filePath, "utf8").replace(/^﻿/, ""));

// Nearest enclosing git repository, or null. Keeps secret-bearing patches out
// of anything under version control — the CWD is a repo more often than not.
function enclosingGitRepo(startDir) {
  let currentDir = path.resolve(startDir);
  for (let depth = 0; depth < 64; depth++) {
    if (fs.existsSync(path.join(currentDir, ".git"))) return currentDir;
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) return null;
    currentDir = parentDir;
  }
  return null;
}

const systemTempDir = () => process.env.TMPDIR || process.env.TEMP || "/tmp";

function writeArtifact(filePath, content, mode) {
  fs.writeFileSync(filePath, content, mode ? { mode } : undefined);
  return filePath;
}

// Rescans and diffs against a previous report. Reports three separate facts and
// refuses to merge them, because only two of the three are knowable offline.
function runVerify(result, opts) {
  let previousReport;
  try { previousReport = readJson(opts.verify); }
  catch (err) {
    process.stderr.write(`cannot read verify report: ${err.message}\n`);
    process.exit(CONFIG.exit.usage);
  }

  const previousFingerprints = new Set((previousReport.findings ?? []).map((finding) => finding.fingerprint));
  const currentFingerprints = new Set(result.findings.map((finding) => finding.fingerprint));
  const resolvedFingerprints = [...previousFingerprints].filter((fp) => !currentFingerprints.has(fp));
  const remainingFingerprints = [...previousFingerprints].filter((fp) => currentFingerprints.has(fp));
  const newFingerprints = [...currentFingerprints].filter((fp) => !previousFingerprints.has(fp));

  const treeFindingCount = result.findings.filter((finding) => finding.source === "tree").length;
  const historyFindingCount = result.findings.filter((finding) => finding.source === "history").length;

  const outputLines = [];
  outputLines.push(c.bold(`Verify against ${opts.verify}`));
  outputLines.push(`  resolved:  ${c.green(String(resolvedFingerprints.length))}`);
  outputLines.push(`  remaining: ${(remainingFingerprints.length ? c.red : c.green)(String(remainingFingerprints.length))}`);
  outputLines.push(`  new:       ${(newFingerprints.length ? c.red : c.green)(String(newFingerprints.length))}`);
  outputLines.push("");
  outputLines.push(`  working tree: ${treeFindingCount === 0
    ? c.green("clean")
    : c.red(`${treeFindingCount} finding(s)`)}`);
  outputLines.push(`  history:      ${historyFindingCount === 0
    ? c.green("no secret-bearing objects found")
    : c.red(`${historyFindingCount} secret-bearing object(s) still in the object database`)}`);
  // Never claim a clean bill of health: rotation happens at the provider, and we
  // make no network calls, so we cannot know whether it happened.
  outputLines.push(`  rotation:     ${c.yellow("cannot be verified offline — confirm with your provider")}`);

  process.stdout.write(outputLines.join("\n") + "\n");
  const unresolvedCount = remainingFingerprints.length + newFingerprints.length;
  process.exit(unresolvedCount > 0 ? CONFIG.exit.findings : CONFIG.exit.ok);
}

async function main() {
  const opts = parseArgv(process.argv.slice(2));
  if (opts.help) { process.stdout.write(USAGE + "\n"); process.exit(CONFIG.exit.ok); }
  if (opts.error) { process.stderr.write(opts.error + "\n\n" + USAGE + "\n"); process.exit(CONFIG.exit.usage); }
  // These two commands operate on LeakLens itself, so they take no scan path.
  if (opts.build) { buildSelf(opts.buildDir); process.exit(CONFIG.exit.ok); }
  if (opts.prove) { process.exit(proveDependencies() ? CONFIG.exit.ok : CONFIG.exit.findings); }
  if (!opts.path) { process.stderr.write("missing <path>\n\n" + USAGE + "\n"); process.exit(CONFIG.exit.usage); }
  const root = path.resolve(opts.path);
  let rootStat;
  try { rootStat = fs.statSync(root); } catch { rootStat = null; }
  if (!rootStat?.isDirectory()) { process.stderr.write(`not a directory: ${root}\n`); process.exit(CONFIG.exit.usage); }

  let result;
  try {
    if (opts.verify) {
      // rescan the same surface the previous report covered
      let previousSummary = {};
      try { previousSummary = readJson(opts.verify).summary ?? {}; } catch {}
      if (previousSummary.historyScanned) opts.history = true;
    }
    result = scan(root, opts, makeProgress());
  } catch (e) {
    process.stderr.write(`scan error: ${e.message}\n`);
    process.exit(CONFIG.exit.error);
  }

  if (opts.verify) return runVerify(result, opts);

  // Remediation artifacts are written now but REPORTED after the findings table,
  // so the scan result is the first thing on screen.
  const artifacts = [];
  if (opts.remediate) {
    let outDir = path.resolve(opts.out ?? ".");
    let patchPath = null;
    if (opts.out && opts.out.endsWith(".patch")) { patchPath = path.resolve(opts.out); outDir = path.dirname(patchPath); }
    fs.mkdirSync(outDir, { recursive: true });
    const planPath = writeArtifact(path.join(outDir, "leaklens-remediation.md"), remediationPlan(result));
    artifacts.push([c.green("✔"), planPath, "redacted — safe to share"]);
    const envTemplate = envExample(result);
    if (envTemplate) {
      const envPath = writeArtifact(path.join(outDir, "leaklens.env.example"), envTemplate);
      artifacts.push([c.green("✔"), envPath, "env var names only, no values"]);
    }
    if (opts.remediatePatch) {
      patchPath ??= path.join(outDir, "leaklens-fix.patch");
      // A patch contains the secret in cleartext. Refuse to drop it into ANY git
      // repository — not just the scanned one. The CWD is a repo more often than not,
      // and "outside the scan root" is not the same as "safe to write".
      const enclosingRepo = enclosingGitRepo(path.dirname(patchPath));
      if (enclosingRepo) {
        process.stderr.write(
          `\n  ${c.red(c.bold("refusing to write the patch"))}\n` +
          `  ${patchPath}\n` +
          `  is inside a git repository (${repo}).\n` +
          `  The patch contains cleartext secrets and must not be committed.\n` +
          `  Pass --out with a directory outside any repository, e.g. --out ${path.join(systemTempDir(), "leaklens")}\n\n`,
        );
        process.exit(CONFIG.exit.usage);
      }
      const patchText = emitPatch(root, result.findings);
      if (patchText) {
        writeArtifact(patchPath, patchText, 0o600);
        artifacts.push([c.red("!"), patchPath,
          c.red("CLEARTEXT SECRETS — do not commit; delete after applying")]);
      } else {
        artifacts.push([c.gray("–"), "(no patch)", "no patchable working-tree findings"]);
      }
    }
  }

  const renderReport = { tty: renderTty, json: jsonReport, sarif: sarifReport }[opts.format];
  process.stdout.write(renderReport(result, opts) + "\n");
  if (artifacts.length) {
    const artifactLines = ["", "  " + c.bold("Wrote")];
    for (const [mark, artifactPath, note] of artifacts) {
      artifactLines.push("    " + mark + " " + artifactPath + "  " + c.gray(note));
    }
    process.stderr.write(artifactLines.join("\n") + "\n\n");
  }
  process.exit(result.findings.length > 0 ? CONFIG.exit.findings : CONFIG.exit.ok);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
