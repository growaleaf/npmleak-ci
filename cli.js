#!/usr/bin/env node
'use strict';

// npmleak-ci — self-contained, dependency-free (Node 18+, no npm install).
// Simulates what `npm pack`/`npm publish` would actually put in the tarball, by applying
// npm's own documented file-inclusion precedence (verified against docs.npmjs.com/cli/v10/
// configuring-npm/package-json#files, fetched directly, not assumed from training knowledge):
//   - If package.json has a "files" field: that whitelist decides inclusion. A root-level
//     .npmignore/.gitignore does NOT override it (npm's own docs: "At the root of your
//     package it will not override the files field").
//   - Otherwise: .npmignore decides inclusion if present, else .gitignore if present, else
//     everything is included.
//   - Regardless of either: package.json, README*, LICENSE*/LICENCE*, the "main" file, and
//     every "bin" file are ALWAYS included; .git, .npmrc, node_modules, package-lock.json,
//     pnpm-lock.yaml, and yarn.lock are ALWAYS excluded — neither can be changed by whitelist
//     or ignore file. Known limitation (documented, not implemented): an .npmignore inside a
//     SUBDIRECTORY can override the files field there — this tool only models root-level
//     precedence, the common case, same disclosure style as this lane's dockleak-ci.
// Then flags whatever ends up included that should never leave a developer's machine: a
// live .env file, private key / certificate material, or an SSH private key.
//
// FREE: one check, no key needed — is a top-level .env file present AND would it actually
//       ship in the computed package contents? (The single most expensive possible miss:
//       a real `npm publish` of a live secret, permanent on the registry within minutes.)
// PRO: computes the full inclusion set, reports total package size and largest included
//      files, and flags every secret-shaped included path. Unlocked by a valid offline
//      license key — no network call, no account, no phone-home.
//
// Usage:
//   node cli.js check [--dir <path>] [--json]
//
// Exit codes:
//   0 - no package.json found, or the computed package contents are clean
//   1 - a risk finding exists (any rule)
//   2 - configuration/usage error (--dir does not exist or is not a directory)

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// ---------------------------------------------------------------------------------------
// License (BP-001 offline ECDSA-P256 verify) — same chassis as every other D-lane standalone
// CLI, including the canonical-base64url round-trip check from the first line (the tamper-
// bypass coin-flip bug this lane found and fixed 2026-09-07, then re-introduced once in
// localbolt-ci before being caught 2026-10-13 — ported in from day one here, not bolted on).
// ---------------------------------------------------------------------------------------
const PUBLIC_KEY_PEM = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE584Tqdr9OA+mKsAIFl0w8DiBeRGfaE9RKlJ3FcIuLsje5t9JYibres+vyMxOzcFgPp2eKJ9lamqeUd1DdITGzw==\n-----END PUBLIC KEY-----';
const LICENSE_PRODUCT = 'npmleak-pro';

function b64urlToBuf(s) {
  const buf = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const canonical = buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (canonical !== s) throw new Error('non-canonical base64url');
  return buf;
}

function verifyLicenseWith(key, pubPem) {
  try {
    if (typeof key !== 'string') return false;
    const parts = key.trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'NL1') return false;
    const signedData = `NL1.${parts[1]}`;
    const payload = JSON.parse(b64urlToBuf(parts[1]).toString('utf8'));
    if (payload.product !== LICENSE_PRODUCT) return false;
    if (payload.exp && Date.now() > payload.exp) return false;
    const v = crypto.createVerify('SHA256');
    v.update(signedData); v.end();
    return v.verify(pubPem, b64urlToBuf(parts[2]));
  } catch (e) { return false; }
}

function verifyLicense(key) {
  if (PUBLIC_KEY_PEM.includes('PLACEHOLDER')) return false;
  return verifyLicenseWith(key, PUBLIC_KEY_PEM);
}

function readLicenseKey() {
  if (process.env.NPMLEAK_KEY) return process.env.NPMLEAK_KEY.trim();
  try {
    return fs.readFileSync(path.join(os.homedir(), '.npmleak', 'license'), 'utf8').trim();
  } catch (e) {
    return null;
  }
}

function hasPro() {
  const key = readLicenseKey();
  return !!(key && verifyLicense(key));
}

// ---------------------------------------------------------------------------------------
// gitignore/npmignore-style pattern matching (same algorithm as this lane's dockleak-ci:
// comments, negation, directory-only trailing slash, leading-slash root anchor, **, *, ?,
// any-depth basename matching for a pattern with no slash at all).
// ---------------------------------------------------------------------------------------
function compilePattern(rawLine) {
  let line = rawLine;
  let negate = false;
  if (line.startsWith('!')) { negate = true; line = line.slice(1); }
  let dirOnly = false;
  if (line.endsWith('/')) { dirOnly = true; line = line.slice(0, -1); }
  let anchored = false;
  if (line.startsWith('/')) { anchored = true; line = line.slice(1); }
  const hasInnerSlash = line.includes('/');

  let re = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '*' && line[i + 1] === '*') {
      re += '.*';
      i++;
      if (line[i + 1] === '/') i++;
    } else if (c === '*') {
      re += '[^/]*';
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  const prefix = (anchored || hasInnerSlash) ? '' : '(?:.*/)?';
  const regex = new RegExp(`^${prefix}${re}$`);
  return { regex, negate, dirOnly };
}

function parseIgnoreFile(text) {
  const patterns = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    patterns.push(compilePattern(line));
  }
  return patterns;
}

function compileMatcher(patterns) {
  return function isMatched(relPath, isDir) {
    let matched = false;
    for (const p of patterns) {
      if (p.dirOnly && !isDir) continue;
      if (p.regex.test(relPath)) matched = !p.negate;
    }
    return matched;
  };
}

// npm's "files" field uses the same glob vocabulary as .gitignore, but a bare directory name
// (or any pattern) matched by it means "include everything under here", not "exclude".
function compileFilesWhitelist(filesField) {
  const patterns = (filesField || []).map(compilePattern);
  return function isWhitelisted(relPath) {
    for (const p of patterns) {
      if (p.regex.test(relPath)) return true;
      // A pattern that names a directory also whitelists everything inside it.
      const prefix = relPath.split('/')[0];
      if (p.regex.test(prefix) && relPath !== prefix) return true;
    }
    return false;
  };
}

// ---------------------------------------------------------------------------------------
// npm's own hardcoded rules (docs.npmjs.com/cli/v10/configuring-npm/package-json#files,
// fetched and quoted directly before writing this, not assumed): some paths are ALWAYS
// included and some are ALWAYS excluded, regardless of "files"/.npmignore/.gitignore.
// ---------------------------------------------------------------------------------------
const HARD_EXCLUDE_NAMES = new Set(['.git', '.npmrc', 'node_modules', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock']);
function isHardExcluded(relPath) {
  const base = path.basename(relPath);
  return HARD_EXCLUDE_NAMES.has(base);
}
function isAlwaysIncludedTop(relPath, pkg) {
  if (relPath === 'package.json') return true;
  if (/^(readme|license|licence)(\..+)?$/i.test(relPath)) return true;
  if (pkg.main && path.normalize(pkg.main) === relPath) return true;
  const bins = pkg.bin ? (typeof pkg.bin === 'string' ? [pkg.bin] : Object.values(pkg.bin)) : [];
  if (bins.some((b) => path.normalize(b) === relPath)) return true;
  return false;
}

// ---------------------------------------------------------------------------------------
// Risk classification — same taxonomy as this lane's dockleak-ci, applied to a package
// tarball instead of a Docker build context.
// ---------------------------------------------------------------------------------------
function riskDirKind(name) {
  if (name === '.aws') return 'aws-credentials-dir';
  if (name === '.ssh') return 'ssh-dir';
  return null;
}
const ENV_SAFE_SUFFIX = /\.(example|sample|template|defaults)$/i;
function riskFileKind(name) {
  if (/^\.env(\..+)?$/.test(name) && !ENV_SAFE_SUFFIX.test(name)) return 'env-file';
  if (/\.(pem|key|pfx|p12)$/i.test(name)) return 'key-material';
  if (/^id_(rsa|dsa|ecdsa|ed25519)$/.test(name)) return 'ssh-private-key';
  return null;
}

// Flat walk used by the "files" field branch: whitelisting is opt-in and monotonic (naming a
// deep file does not require its parent directory to also be named), so every file can be
// decided independently.
function walkTree(rootDir) {
  const entries = [];
  function recurse(absDir, relDir) {
    let names;
    try { names = fs.readdirSync(absDir); } catch (e) { return; }
    for (const name of names) {
      if (name === 'node_modules' || name === '.git') continue; // hard-excluded, never worth descending
      const absPath = path.join(absDir, name);
      const relPath = relDir ? `${relDir}/${name}` : name;
      let st;
      try { st = fs.lstatSync(absPath); } catch (e) { continue; }
      if (st.isSymbolicLink()) continue;
      const isDir = st.isDirectory();
      entries.push({ rel: relPath, abs: absPath, isDir, size: isDir ? 0 : st.size });
      if (isDir) recurse(absPath, relPath);
    }
  }
  recurse(rootDir, '');
  return entries;
}

// Recursive walk used by the .npmignore/.gitignore branch: once a DIRECTORY matches the
// ignore patterns, nothing inside it is inspected at all — the same "stop descending" rule
// real gitignore/npm use. Checking each file independently against a directory-only pattern
// (as a flat walk would) is wrong: a dirOnly pattern only ever matches when tested against a
// directory path, so a flat per-file check can never see that a FILE sits inside an excluded
// directory, and would wrongly include it. Known limitation, documented in the README (same
// disclosure style as this lane's dockleak-ci): this does not model a subdirectory .npmignore
// overriding an ignored ancestor, only the common top-level case.
function walkWithIgnorePruning(rootDir, isIgnored, pkg) {
  const included = [];
  function recurse(absDir, relDir) {
    let names;
    try { names = fs.readdirSync(absDir); } catch (e) { return; }
    for (const name of names) {
      if (name === 'node_modules' || name === '.git') continue;
      const absPath = path.join(absDir, name);
      const relPath = relDir ? `${relDir}/${name}` : name;
      let st;
      try { st = fs.lstatSync(absPath); } catch (e) { continue; }
      if (st.isSymbolicLink()) continue;
      const isDir = st.isDirectory();
      const ignored = isIgnored(relPath, isDir);
      if (isDir) {
        if (ignored) continue; // prune the whole subtree
        recurse(absPath, relPath);
      } else {
        if (isHardExcluded(relPath)) continue;
        if (ignored && !isAlwaysIncludedTop(relPath, pkg)) continue;
        included.push({ rel: relPath, abs: absPath, size: st.size });
      }
    }
  }
  recurse(rootDir, '');
  return included;
}

// Computes the set of entries npm would actually put in the tarball.
function computeIncludedSet(rootDir, pkg) {
  const hasFilesField = Array.isArray(pkg.files) && pkg.files.length > 0;
  let included;
  let ignoreSource;

  if (hasFilesField) {
    const isWhitelisted = compileFilesWhitelist(pkg.files);
    const decide = (relPath) => isWhitelisted(relPath) || isAlwaysIncludedTop(relPath, pkg);
    included = walkTree(rootDir).filter((e) => !e.isDir && !isHardExcluded(e.rel) && decide(e.rel));
    ignoreSource = 'files field';
  } else {
    const npmignorePath = path.join(rootDir, '.npmignore');
    const gitignorePath = path.join(rootDir, '.gitignore');
    let patterns = [];
    if (fs.existsSync(npmignorePath)) {
      patterns = parseIgnoreFile(fs.readFileSync(npmignorePath, 'utf8'));
      ignoreSource = '.npmignore';
    } else if (fs.existsSync(gitignorePath)) {
      patterns = parseIgnoreFile(fs.readFileSync(gitignorePath, 'utf8'));
      ignoreSource = '.gitignore (no .npmignore)';
    } else {
      ignoreSource = 'none';
    }
    const isIgnored = compileMatcher(patterns);
    included = walkWithIgnorePruning(rootDir, isIgnored, pkg);
  }
  return { included, ignoreSource, hasFilesField };
}

// Free-tier check: a single, cheap check — does a top-level .env (or .env.* minus the safe
// suffixes) file exist AND would it be included in the computed package contents? No key
// needed, same "one narrow comparison" shape as this lane's other free tiers.
function freeCheckTopLevelEnv(rootDir, pkg) {
  let names;
  try { names = fs.readdirSync(rootDir); } catch (e) { return null; }
  const envNames = names.filter((n) => riskFileKind(n) === 'env-file');
  if (!envNames.length) return null;
  const { included } = computeIncludedSet(rootDir, pkg);
  const includedRel = new Set(included.map((e) => e.rel));
  for (const name of envNames) {
    if (includedRel.has(name)) return { rel: name, kind: 'env-file' };
  }
  return null;
}

// ---------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------
class ConfigError extends Error {}

function buildReport(rootDir, opts) {
  opts = opts || {};
  if (!fs.existsSync(rootDir) || !fs.statSync(rootDir).isDirectory()) {
    throw new ConfigError(`${rootDir} is not a directory`);
  }
  const pkgPath = path.join(rootDir, 'package.json');
  const hasPackageJson = fs.existsSync(pkgPath);
  const pkg = hasPackageJson ? JSON.parse(fs.readFileSync(pkgPath, 'utf8')) : {};

  const pro = !!opts.pro;
  const findings = [];
  let totalBytes = null;
  let topLargest = null;
  let ignoreSource = null;
  let fileCount = null;

  const envFree = hasPackageJson ? freeCheckTopLevelEnv(rootDir, pkg) : null;
  if (envFree) {
    findings.push({
      rule: 'envFileIncluded',
      message: `${envFree.rel} would be included in the published package (not excluded by files/.npmignore/.gitignore).`,
      path: envFree.rel, kind: envFree.kind,
    });
  }

  if (pro && hasPackageJson) {
    const { included, ignoreSource: src } = computeIncludedSet(rootDir, pkg);
    ignoreSource = src;
    fileCount = included.length;
    totalBytes = included.reduce((sum, e) => sum + e.size, 0);
    topLargest = included.slice().sort((a, b) => b.size - a.size).slice(0, 5);
    for (const e of included) {
      if (findings.some((f) => f.path === e.rel)) continue;
      const base = path.basename(e.rel);
      const fileKind = riskFileKind(base);
      if (fileKind) {
        findings.push({ rule: 'secretPathIncluded', message: `${e.rel} (${fileKind}) would be included in the published package.`, path: e.rel, kind: fileKind });
        continue;
      }
      const riskSeg = e.rel.split('/').find((seg) => riskDirKind(seg));
      if (riskSeg) {
        const kind = riskDirKind(riskSeg);
        findings.push({ rule: 'secretPathIncluded', message: `${e.rel} (under ${kind}) would be included in the published package.`, path: e.rel, kind });
      }
    }
  }

  return {
    breach: hasPackageJson && findings.length > 0,
    pro,
    hasPackageJson,
    ignoreSource,
    fileCount,
    totalBytes,
    topLargest,
    findings,
  };
}

// ---------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------
function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') args.dir = argv[++i];
    else if (a === '--json') args.json = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else args._.push(a);
  }
  return args;
}

function fmtBytes(n) {
  if (n == null) return '';
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)}${units[i]}`;
}

function printHumanReport(result) {
  if (!result.hasPackageJson) {
    console.log('npmleak-ci — no package.json found under this directory, nothing to check.');
    return;
  }
  console.log(`npmleak-ci — mode: ${result.pro ? 'Pro (full package contents)' : 'free (.env check only)'}`);
  if (result.pro) {
    console.log(`  resolved via: ${result.ignoreSource}`);
    console.log(`  package would contain ${result.fileCount} files, ${fmtBytes(result.totalBytes)} (${result.totalBytes} bytes)`);
    if (result.topLargest && result.topLargest.length) {
      console.log('  largest included files:');
      for (const f of result.topLargest) console.log(`    ${fmtBytes(f.size).padStart(8)}  ${f.rel}`);
    }
  }
  if (!result.findings.length) {
    console.log('  clean — nothing risky found in the computed package contents.');
  } else {
    for (const f of result.findings) console.log(`  RISK  [${f.rule}]  ${f.message}`);
  }
  if (!result.pro) {
    console.log('  (free mode checked top-level .env files only — Pro computes the full package contents and also flags key material, SSH keys, and .aws/.ssh: https://npmleak-ci.madeforthisday.com)');
  }
}

function main() {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);
  const command = args._[0];

  if (args.help || !command) {
    console.log('Usage: node cli.js check [--dir <path>] [--json]');
    process.exit(command ? 0 : 2);
    return;
  }
  if (command !== 'check') {
    console.error(`Unknown command "${command}". Only "check" is supported.`);
    process.exit(2);
    return;
  }

  const dir = args.dir ? path.resolve(process.cwd(), args.dir) : process.cwd();
  let result;
  try {
    result = buildReport(dir, { pro: hasPro() });
  } catch (e) {
    if (e instanceof ConfigError) {
      console.error(`npmleak-ci config error: ${e.message}`);
      process.exit(2);
      return;
    }
    throw e;
  }

  if (args.json) console.log(JSON.stringify(result, null, 2));
  else printHumanReport(result);

  process.exit(result.breach ? 1 : 0);
}

if (require.main === module) main();

module.exports = {
  buildReport, verifyLicense, verifyLicenseWith, compilePattern, compileMatcher,
  parseIgnoreFile, compileFilesWhitelist, computeIncludedSet, riskDirKind, riskFileKind,
  isHardExcluded, isAlwaysIncludedTop,
};
