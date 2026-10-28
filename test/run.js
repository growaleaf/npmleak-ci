'use strict';
// Standalone-package test suite for npmleak-ci. Exercises the exact exported functions the
// shipped cli.js ships against real fixture trees on disk (package.json with/without a
// files field, .gitignore, .env, id_rsa, server.pem, .aws/credentials, node_modules) — never
// a mocked file tree.
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const {
  buildReport, verifyLicenseWith, compilePattern, compileMatcher, parseIgnoreFile,
  compileFilesWhitelist, computeIncludedSet, riskDirKind, riskFileKind,
  isHardExcluded, isAlwaysIncludedTop,
} = require('../cli.js');

let passed = 0;
const failures = [];
function check(name, fn) {
  return Promise.resolve().then(fn).then(() => {
    passed++;
    console.log('  ok -', name);
  }).catch((err) => {
    failures.push({ name, err });
    console.log('FAIL -', name, '\n       ', err.message);
  });
}

const FIXTURES = path.join(__dirname, 'fixtures');
const rel = (fixture) => path.join(FIXTURES, fixture);
const pkgOf = (fixture) => JSON.parse(fs.readFileSync(path.join(rel(fixture), 'package.json'), 'utf8'));

async function main() {
  await check('compilePattern: a bare pattern with no slash matches at any depth', () => {
    const p = compilePattern('node_modules');
    assert.equal(p.regex.test('node_modules'), true);
    assert.equal(p.regex.test('packages/api/node_modules'), true);
  });

  await check('compileMatcher: negation re-includes a path an earlier pattern excluded, last match wins', () => {
    const patterns = parseIgnoreFile('.env*\n!.env.example\n');
    const isIgnored = compileMatcher(patterns);
    assert.equal(isIgnored('.env', false), true);
    assert.equal(isIgnored('.env.example', false), false);
  });

  await check('compileFilesWhitelist: a bare file name whitelists exactly that file, not others', () => {
    const w = compileFilesWhitelist(['index.js']);
    assert.equal(w('index.js'), true);
    assert.equal(w('.env'), false);
  });

  await check('compileFilesWhitelist: a directory name whitelists everything inside it', () => {
    const w = compileFilesWhitelist(['src']);
    assert.equal(w('src/app.js'), true);
    assert.equal(w('src/deep/nested.js'), true);
    assert.equal(w('other.js'), false);
  });

  await check('riskDirKind / riskFileKind classify the canonical danger set, and leave safe lookalikes alone', () => {
    assert.equal(riskDirKind('.aws'), 'aws-credentials-dir');
    assert.equal(riskDirKind('.ssh'), 'ssh-dir');
    assert.equal(riskDirKind('src'), null);
    assert.equal(riskFileKind('.env'), 'env-file');
    assert.equal(riskFileKind('.env.production'), 'env-file');
    assert.equal(riskFileKind('.env.example'), null); // safe, meant to be committed
    assert.equal(riskFileKind('server.pem'), 'key-material');
    assert.equal(riskFileKind('id_rsa'), 'ssh-private-key');
    assert.equal(riskFileKind('id_rsa.pub'), null); // public half, not sensitive
    assert.equal(riskFileKind('README.md'), null);
  });

  await check('isHardExcluded: .git/.npmrc/node_modules/lockfiles can never be included, by basename', () => {
    assert.equal(isHardExcluded('node_modules/somepkg/index.js'.split('/').slice(0, 1).join('/')), true);
    assert.equal(isHardExcluded('.npmrc'), true);
    assert.equal(isHardExcluded('package-lock.json'), true);
    assert.equal(isHardExcluded('pnpm-lock.yaml'), true);
    assert.equal(isHardExcluded('yarn.lock'), true);
    assert.equal(isHardExcluded('src/index.js'), false);
  });

  await check('isAlwaysIncludedTop: package.json/README/LICENSE/main/bin are always included regardless of files', () => {
    const pkg = { main: 'index.js', bin: { foo: 'bin/foo.js' } };
    assert.equal(isAlwaysIncludedTop('package.json', pkg), true);
    assert.equal(isAlwaysIncludedTop('README.md', pkg), true);
    assert.equal(isAlwaysIncludedTop('LICENSE', pkg), true);
    assert.equal(isAlwaysIncludedTop('index.js', pkg), true);
    assert.equal(isAlwaysIncludedTop('bin/foo.js', pkg), true);
    assert.equal(isAlwaysIncludedTop('src/other.js', pkg), false);
  });

  await check('computeIncludedSet: no files field, no ignore file at all -> everything ships, including every secret', () => {
    const { included, ignoreSource, hasFilesField } = computeIncludedSet(rel('no-files-leaky'), pkgOf('no-files-leaky'));
    assert.equal(hasFilesField, false);
    assert.equal(ignoreSource, 'none');
    const rels = included.map((e) => e.rel);
    assert.ok(rels.includes('.env'));
    assert.ok(rels.includes('id_rsa'));
    assert.ok(rels.includes('server.pem'));
    assert.ok(rels.includes('.aws/credentials'));
    assert.ok(rels.includes('.env.example')); // included, just not risky
  });

  await check('computeIncludedSet: no files field, .gitignore fallback excludes every secret, negation keeps .env.example', () => {
    const { included, ignoreSource } = computeIncludedSet(rel('no-files-clean'), pkgOf('no-files-clean'));
    assert.equal(ignoreSource, '.gitignore (no .npmignore)');
    const rels = included.map((e) => e.rel);
    assert.ok(!rels.includes('.env'));
    assert.ok(!rels.includes('id_rsa'));
    assert.ok(!rels.includes('server.pem'));
    assert.ok(!rels.includes('.aws/credentials'));
    assert.ok(rels.includes('.env.example'));
  });

  await check('computeIncludedSet: a files whitelist that never mentions .env keeps it out, with zero ignore files needed', () => {
    const { included, hasFilesField } = computeIncludedSet(rel('files-field-safe'), pkgOf('files-field-safe'));
    assert.equal(hasFilesField, true);
    const rels = included.map((e) => e.rel);
    assert.ok(!rels.includes('.env'));
    assert.ok(rels.includes('src/app.js'));
  });

  await check('computeIncludedSet: a files whitelist that DOES name .env ships it even though a root .gitignore tries to exclude it (npm docs: root .npmignore/.gitignore does not override files)', () => {
    const { included } = computeIncludedSet(rel('files-field-leaky'), pkgOf('files-field-leaky'));
    const rels = included.map((e) => e.rel);
    assert.ok(rels.includes('.env'));
  });

  await check('computeIncludedSet: node_modules named in the files field is still hard-excluded, never ships', () => {
    const { included } = computeIncludedSet(rel('files-field-leaky'), pkgOf('files-field-leaky'));
    const rels = included.map((e) => e.rel);
    assert.ok(!rels.some((r) => r.startsWith('node_modules')));
  });

  await check('buildReport free mode: a top-level .env present and included is flagged with no key', () => {
    const result = buildReport(rel('no-files-leaky'), { pro: false });
    assert.equal(result.breach, true);
    assert.equal(result.pro, false);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].rule, 'envFileIncluded');
    // free mode never computes the full set for the report fields, only for its own internal check.
    assert.equal(result.totalBytes, null);
  });

  await check('buildReport free mode: a top-level .env present but excluded by .gitignore is NOT flagged', () => {
    const result = buildReport(rel('no-files-clean'), { pro: false });
    assert.equal(result.breach, false);
    assert.equal(result.findings.length, 0);
  });

  await check('buildReport Pro mode: no-files-leaky flags env/ssh-key/cert/aws, reports a real size and file list', () => {
    const result = buildReport(rel('no-files-leaky'), { pro: true });
    assert.equal(result.breach, true);
    const kinds = result.findings.map((f) => f.kind);
    assert.ok(kinds.includes('env-file'));
    assert.ok(kinds.includes('ssh-private-key'));
    assert.ok(kinds.includes('key-material'));
    assert.ok(kinds.includes('aws-credentials-dir'));
    assert.ok(result.fileCount > 0);
    assert.ok(result.totalBytes > 0);
    assert.ok(Array.isArray(result.topLargest));
  });

  await check('buildReport Pro mode: no-files-clean (.gitignore excludes every secret) is breach-free', () => {
    const result = buildReport(rel('no-files-clean'), { pro: true });
    assert.equal(result.breach, false);
    assert.equal(result.findings.length, 0);
  });

  await check('buildReport Pro mode: files-field-leaky still flags the whitelisted .env (files field overrides a root .gitignore)', () => {
    const result = buildReport(rel('files-field-leaky'), { pro: true });
    assert.equal(result.breach, true);
    assert.ok(result.findings.some((f) => f.kind === 'env-file'));
  });

  await check('buildReport: no package.json anywhere is a clean no-op, not an error', () => {
    const result = buildReport(rel('no-package-json'), { pro: true });
    assert.equal(result.breach, false);
    assert.equal(result.hasPackageJson, false);
    assert.equal(result.findings.length, 0);
  });

  await check('buildReport throws ConfigError when --dir does not exist', () => {
    assert.throws(() => buildReport(rel('does-not-exist'), {}), /is not a directory/);
  });

  await check('CLI end-to-end via real subprocess: free mode runs with no key, Pro mode engages with a real minted key', () => {
    const cliPath = path.join(__dirname, '..', 'cli.js');

    const runCli = (args, cwd, env) => {
      try {
        const out = execFileSync('node', [cliPath, ...args], { encoding: 'utf8', cwd, env: { ...process.env, ...env } });
        return { code: 0, out };
      } catch (e) {
        return { code: e.status, out: (e.stdout || '') + (e.stderr || '') };
      }
    };

    // Free mode, no key at all: the clean fixture passes (exit 0).
    const freeRun = runCli(['check'], rel('no-files-clean'), { NPMLEAK_KEY: '' });
    assert.equal(freeRun.code, 0);
    assert.ok(freeRun.out.includes('free'));

    // Free mode, no key, leaky .env present: exit 1 even without Pro.
    const freeLeaky = runCli(['check'], rel('no-files-leaky'), { NPMLEAK_KEY: '' });
    assert.equal(freeLeaky.code, 1);

    // Pro mode with a real minted key: the leaky fixture now fails on secrets free mode alone
    // could not see (SSH key, cert, .aws dir).
    const devVarsPath = path.join(os.homedir(), '.hive_devtools_license_keys', 'npmleak.dev.vars');
    const devVars = fs.readFileSync(devVarsPath, 'utf8');
    const privB64 = devVars.match(/LICENSE_PRIVATE_KEY=(\S+)/)[1];
    const privateKey = crypto.createPrivateKey({ key: Buffer.from(privB64, 'base64'), format: 'der', type: 'pkcs8' });
    const payload = Buffer.from(JSON.stringify({ product: 'npmleak-pro', iat: Date.now() })).toString('base64url');
    const sig = crypto.createSign('SHA256').update(`NL1.${payload}`).end().sign(privateKey).toString('base64url');
    const realKey = `NL1.${payload}.${sig}`;

    const proRun = runCli(['check'], rel('no-files-leaky'), { NPMLEAK_KEY: realKey });
    assert.equal(proRun.code, 1);
    assert.ok(proRun.out.includes('Pro'));

    const proCleanRun = runCli(['check'], rel('no-files-clean'), { NPMLEAK_KEY: realKey });
    assert.equal(proCleanRun.code, 0);
  });

  await check('license: a key signed by the real private key verifies true against the matching public key', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
    const payload = Buffer.from(JSON.stringify({ product: 'npmleak-pro', iat: Date.now() })).toString('base64url');
    const sig = crypto.createSign('SHA256').update(`NL1.${payload}`).end().sign(privateKey).toString('base64url');
    assert.equal(verifyLicenseWith(`NL1.${payload}.${sig}`, pubPem), true);
  });

  await check('license: a tampered key is rejected', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
    const payload = Buffer.from(JSON.stringify({ product: 'npmleak-pro', iat: Date.now() })).toString('base64url');
    const sig = crypto.createSign('SHA256').update(`NL1.${payload}`).end().sign(privateKey).toString('base64url');
    const tamperedPayload = Buffer.from(JSON.stringify({ product: 'npmleak-pro', iat: 0 })).toString('base64url');
    assert.equal(verifyLicenseWith(`NL1.${tamperedPayload}.${sig}`, pubPem), false);
  });

  await check('license: non-canonical base64url (coin-flip tamper-bypass shape) is rejected, not accepted by luck', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
    const payload = Buffer.from(JSON.stringify({ product: 'npmleak-pro', iat: Date.now() })).toString('base64url');
    const sig = crypto.createSign('SHA256').update(`NL1.${payload}`).end().sign(privateKey).toString('base64url');
    assert.equal(verifyLicenseWith(`NL1.${payload}.${sig}AB`, pubPem), false);
  });

  await check('license: a key signed by a DIFFERENT private key is rejected by this public key', () => {
    const { publicKey: pubA } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const { privateKey: privB } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pubPemA = pubA.export({ type: 'spki', format: 'pem' });
    const payload = Buffer.from(JSON.stringify({ product: 'npmleak-pro', iat: Date.now() })).toString('base64url');
    const sig = crypto.createSign('SHA256').update(`NL1.${payload}`).end().sign(privB).toString('base64url');
    assert.equal(verifyLicenseWith(`NL1.${payload}.${sig}`, pubPemA), false);
  });

  await check('license: wrong product in the payload is rejected even with a valid signature', () => {
    const devVarsPath = path.join(os.homedir(), '.hive_devtools_license_keys', 'npmleak.dev.vars');
    const devVars = fs.readFileSync(devVarsPath, 'utf8');
    const privB64 = devVars.match(/LICENSE_PRIVATE_KEY=(\S+)/)[1];
    const privateKey = crypto.createPrivateKey({ key: Buffer.from(privB64, 'base64'), format: 'der', type: 'pkcs8' });
    const payload = Buffer.from(JSON.stringify({ product: 'some-other-product', iat: Date.now() })).toString('base64url');
    const sig = crypto.createSign('SHA256').update(`NL1.${payload}`).end().sign(privateKey).toString('base64url');
    const { verifyLicense } = require('../cli.js');
    assert.equal(verifyLicense(`NL1.${payload}.${sig}`), false);
  });

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) process.exitCode = 1;
  else console.log('All npmleak-ci standalone test groups passed.');
}

main();
