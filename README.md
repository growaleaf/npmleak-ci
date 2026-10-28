# npmleak-ci

Simulates what `npm pack`/`npm publish` actually ships, and flags a `.env` file, key material,
or an SSH private key your `files`/`.npmignore`/`.gitignore` config is failing to exclude —
before you run `npm publish` and it's permanent. Unlike a `.git` leak you can at least rewrite
history on, a published npm tarball is cached by registry mirrors within minutes; there is no
un-publishing a secret once it's out.

```
$ npmleak-ci check
npmleak-ci — mode: Pro (full package contents)
  resolved via: .gitignore (no .npmignore)
  package would contain 14 files, 212.0KB (217,088 bytes)
  largest included files:
       180.0KB  dist/bundle.js
  RISK  [secretPathIncluded]  .env (env-file) would be included in the published package.
```

## Install

```
npm install github:growaleaf/npmleak-ci
```

No npm registry account needed. Zero runtime dependencies — one `.js` file, Node 18+ built-ins
only (`fs`/`path`/`os`/`crypto`).

## Usage

```
npmleak-ci check [--dir <path>] [--json]
```

**Free, no key needed:** one check — is a top-level `.env` (or `.env.*`, excluding
`.example`/`.sample`/`.template`/`.defaults`) file present *and* would it actually be included
in the computed package contents? This is the single most expensive possible miss: a live
secret, permanently public, indexed by every registry mirror within minutes of `npm publish`.

**Pro ($9, one-time):** computes the full set of files npm would actually tar up — applying
npm's own documented precedence (verified against `docs.npmjs.com/cli/v10/configuring-npm/
package-json#files` directly, not assumed): if `package.json` has a `files` field, that
whitelist decides inclusion and a root-level `.npmignore`/`.gitignore` does **not** override
it; otherwise `.npmignore` decides if present, else `.gitignore`, else everything ships.
`package.json`, `README*`, `LICENSE*`, the `main` file and every `bin` file are always
included; `.git`, `.npmrc`, `node_modules`, `package-lock.json`, `pnpm-lock.yaml` and
`yarn.lock` can never be included, even if named in `files` — these two rules apply regardless
of any setting. Reports the total package size, the largest included files, and flags every
one of these if your config fails to keep it out:

| Finding | Why it matters |
|---|---|
| `.env`, `.env.*` (not `.example`/`.sample`/`.template`/`.defaults`) | Live secrets, permanently public the moment you publish |
| `*.pem`, `*.key`, `*.pfx`, `*.p12` | Certificate / private key material |
| `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` | SSH private keys (the `.pub` half is fine) |
| `.aws/`, `.ssh/` | Cloud credentials, SSH config and known_hosts |

Exit codes: `0` clean (or no `package.json` found — nothing to check), `1` a finding exists,
`2` `--dir` doesn't exist.

Set your key via `NPMLEAK_KEY` (CI secret) or `~/.npmleak/license` (local machine). Get one at
[npmleak-ci.madeforthisday.com](https://npmleak-ci.madeforthisday.com).

## Known limitation

Models root-level precedence only. npm's own docs note that a `.npmignore` placed *inside a
subdirectory* can override the `files` field for that subdirectory specifically — a narrow
edge case this tool does not model. The common case (root `files` field, or root
`.npmignore`/`.gitignore` with no `files` field) is handled exactly as npm itself applies it.

## Why this, and not an existing tool

Searched `registry.npmjs.org` and GitHub directly before building: `npm pack --dry-run`
already lists what npm would include — but it does not classify *which* included files are
dangerous, which is the actual job here. `publint` lints packaging correctness (broken
`exports`/`main`/`types` resolution), a different problem entirely. General secret scanners
(`gitleaks`, `@visulima/secret-scanner`) scan arbitrary trees or git history for secret
*patterns*; none of them specifically simulate npm's own publish-inclusion algorithm first and
then classify what's left in. Nothing found does both steps together.

## License

Free tier: use for any purpose, commercial or otherwise. Pro tier: one license per purchase,
works offline, no subscription. See [LICENSE](./LICENSE). Refunds within 14 days, no questions
asked — email greenboxhydro@gmail.com.
