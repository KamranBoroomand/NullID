# NullID Terminal-First Architecture Audit

Date: 2026-04-08

Audit basis:
- The active workspace path (`/Users/kamran/Documents/GitHub/NullID Terminal`) was empty.
- This audit was performed against the actual NullID repo at `/Users/kamran/Documents/GitHub/NullID`.

## Executive Summary

NullID already has the right raw ingredients for a terminal-first product:

- a broad offline security feature set in `src/utils`
- strong schema and parity tests
- a local CLI surface that already reaches beyond the browser app
- an optional desktop wrapper path

The main architectural problem is not missing capability. It is duplication.

The browser app and CLI currently share contracts, tests, and some specs, but they do not share one executable runtime core. The clearest sign is the existing CLI: `scripts/nullid-local.mjs` is a single 4,858-line Node script that reimplements a large amount of logic already present in `src/utils`.

That means the best migration path is not a rewrite. It is:

1. extract a real shared core from the existing repo
2. move the CLI onto that core first
3. add an optional TUI only after the CLI/core boundary is stable
4. keep the browser app as another adapter over the same core

## Current Repo Audit

### Browser app

Primary browser shell:
- `src/App.tsx`
- `src/views/*`
- `src/components/*`
- `src/hooks/*`

Characteristics:
- Vite + React SPA
- local-only by policy
- heavy use of browser APIs for file handling, downloads, local storage, IndexedDB, clipboard, canvas-based image cleanup, WebAuthn, and runtime diagnostics

### CLI

Primary CLI entry:
- `scripts/nullid-local.mjs`

Current commands:
- `hash`
- `sanitize`
- `sanitize-dir`
- `bundle`
- `package-inspect`
- `redact`
- `enc`
- `dec`
- `pwgen`
- `pw-hash`
- `pw-verify`
- `meta`
- `pdf-clean`
- `office-clean`
- `archive-sanitize`
- `archive-inspect`
- `wizard`
- `precommit`
- `policy-init`

Characteristics:
- rich local automation surface
- already more operationally capable than the browser app
- directly uses `fs`, `path`, `crypto`, `child_process`, `os`, `zlib`, `git`, `zip`, and `unzip`
- largely duplicates browser-side logic instead of importing it

### Scripts and release path

Current support scripts are healthy for build/release/testing, but they mostly assume a web-first artifact:
- `scripts/package-release.mjs`
- `scripts/generate-build-manifest.mjs`
- `scripts/verify-release-bundle.mjs`
- `scripts/run-e2e.mjs`
- `scripts/desktop-smoke.mjs`

There is no real installable terminal package yet:
- no `bin` entry in `package.json`
- no compiled CLI distribution path
- no terminal-first app layout under `src/cli`

### Desktop path

Current desktop path:
- `desktop/tauri/src-tauri/*`

Status:
- this is a thin Tauri shell around the web build
- bundling is disabled
- there is no desktop-native local runtime yet
- it should be treated as optional packaging, not as the foundation of the terminal migration

## What Can Become A Shared Core

The strongest reuse opportunity is the existing domain logic in `src/utils`.

### Extract largely as-is

These modules are already data-first or very close to it:

- `src/utils/sanitizeEngine.ts`
- `src/utils/financialReview.ts`
- `src/utils/incidentWorkflow.ts`
- `src/utils/passwordToolkit.ts`
- `src/utils/pathPrivacy.ts`
- `src/utils/policyBaseline.ts`
- `src/utils/policyPack.ts`
- `src/utils/reporting.ts`
- `src/utils/reviewChecklist.ts`
- `src/utils/secretScanner.ts`
- `src/utils/sharedPassphraseTrustState.ts`
- `src/utils/snapshotIntegrity.ts`
- `src/utils/unlockHardening.ts`
- `src/utils/vaultStorageKeys.ts`
- `src/utils/workflowPackage.ts`
- `src/utils/workflowReview.ts`

These should become the first wave of shared core modules.

### Extract after small runtime decoupling

These are strategically important and should still live in the shared core, but they need adapters or API cleanup first:

- `src/utils/hash.ts`
  - split into text/bytes hashing core and browser `File` hashing adapter
- `src/utils/cryptoEnvelope.ts`
  - keep the format and logic, but inject crypto/random sources instead of assuming browser globals
- `src/utils/passwordHashing.ts`
  - same pattern as envelope logic; keep algorithms and record format, move runtime-specific crypto behind an adapter
- `src/utils/packageVerification.ts`
  - already mostly shared, but it depends on modules that still touch browser runtime
- `src/utils/redaction.ts`
  - fundamentally core logic; needs minor cleanup because it is currently mixed into browser-oriented import paths
- `src/utils/structuredTextAnalyzer.ts`
- `src/utils/safeShareAssistant.ts`
- `src/utils/archiveInspection.ts`
  - move ZIP inflate/hash work behind a cross-runtime archive adapter
- `src/utils/metadataAdvanced.ts`
  - buffer inspection logic is reusable; cleanup operations are not
- `src/utils/vault.ts`
  - crypto and record model are reusable; storage backend is not

### Strong evidence that this reuse is viable

The repo already tests browser/CLI parity rather than treating them as different products:

- `src/__tests__/nullidLocalCli.test.ts`
- `tsconfig.test.json`

That is a strong signal that the domain contracts are already stable enough to share as executable code instead of only sharing tests/specs.

## What Is Browser-Coupled Today

These areas should stay browser adapters or be rewritten for terminal use:

### Pure browser UI

- `src/App.tsx`
- `src/views/*`
- `src/components/*`
- `src/hooks/*`
- `src/theme/*`
- `src/i18n.tsx`

### Browser-only platform services

- `src/utils/storage.ts`
  - IndexedDB + localStorage
- `src/utils/profile.ts`
  - localStorage snapshot/export download flow
- `src/utils/clipboard.ts`
  - browser clipboard API
- `src/utils/localMfa.ts`
  - WebAuthn
- `src/utils/sessionSecurity.ts`
  - document cookies / secure context checks
- `src/utils/keyHintProfiles.ts`
  - localStorage-backed persistence

### Browser-only file/media handling

- `src/utils/imageFormats.ts`
  - canvas encode probes
- `src/utils/metadataCleaning.ts`
  - canvas image re-encode
- `src/utils/localArtifactPreparation.ts`
  - currently orchestrates browser-only cleanup paths

### Browser-shaped APIs that should be normalized

- `File`
- `Blob`
- `URL.createObjectURL`
- `navigator.clipboard`
- `window`, `document`, `localStorage`, `indexedDB`

The shared core should not accept these types. It should operate on:

- `string`
- `Uint8Array`
- plain JSON objects
- explicit runtime/service interfaces

## Proposed Terminal-First Architecture

## Design principles

- local-only by default
- no required backend
- one shared core used by browser and terminal surfaces
- terminal is the richer local operations surface
- device and OS awareness lives in one platform service, not scattered through domain code
- external tools are optional capabilities, not hard dependencies unless a specific command needs them

### Recommended in-repo module structure

For Phase 1, keep a single package and create clean boundaries inside the existing repo:

```text
src/
  core/
    archive/
    crypto/
    inspect/
    sanitize/
    share/
    text/
    vault/
    index.ts
  platform/
    browser/
    node/
    types.ts
  cli/
    commands/
    format/
    services/
    index.ts
  tui/
    app/
    screens/
    widgets/
    index.ts
  views/
  components/
  hooks/
```

Why this shape:
- minimal repo disruption
- lets the browser keep working during extraction
- avoids premature workspace/package-manager complexity
- still gives us a path to split into workspaces later if needed

If the terminal app grows substantially later, this structure can be promoted into:
- `packages/core`
- `packages/platform-node`
- `packages/platform-browser`
- `packages/cli`
- `packages/tui`
- `apps/web`

without changing the architectural boundaries.

### Shared core

The shared core should own:

- schemas and artifact contracts
- hashing
- redact/sanitize/inspect transforms
- workflow package creation and verification
- password hashing and verification
- envelope encryption/decryption
- vault record formats and serialization
- structured text, financial, secret, and path analysis

Rules for the core:

- no DOM types
- no direct filesystem access
- no direct process spawning
- no direct `localStorage` or IndexedDB
- no direct clipboard, WebAuthn, cookie, or canvas calls

### CLI layer

The CLI should become a thin command dispatcher over the shared core.

Responsibilities:
- parse args
- read/write files
- format output for human or JSON mode
- surface local environment facts
- call external tools only through a runner service

Recommended CLI shape:

- `nullid <command> ...`
- human-readable output by default
- `--json` for scripting
- `--quiet` and proper exit codes
- core commands first, richer operational commands second

### Optional interactive TUI layer

Recommendation:
- treat the TUI as optional and build it after CLI/core extraction
- use Node/TypeScript, not a second runtime
- prefer `Ink` for the first TUI iteration because the team already works in React/TypeScript

TUI scope should be:
- guided workflow wizard
- vault browsing
- review dashboards
- job history
- configuration and permissions prompts

The TUI must call the same command/core services as the non-interactive CLI. It should not become its own logic layer.

### Local storage model

Do not carry the browser storage model into terminal code.

Use OS-native app directories:

- macOS:
  - config: `~/Library/Application Support/NullID/config`
  - state: `~/Library/Application Support/NullID/state`
- Linux:
  - config: `$XDG_CONFIG_HOME/nullid` or `~/.config/nullid`
  - state: `$XDG_STATE_HOME/nullid` or `~/.local/state/nullid`
- Windows:
  - config: `%APPDATA%\\NullID\\config`
  - state: `%LOCALAPPDATA%\\NullID\\state`

Recommended storage split:

- `config/`
  - preferences
  - named policy packs
  - key-hint profiles
  - permission grants
- `state/`
  - vault data
  - job history
  - temp staging metadata
  - lock/session state
- `plugins/`
  - optional local plugins
- `logs/`
  - structured local execution logs

MVP storage format:
- JSON files for preferences/config
- atomic file writes for state manifests
- encrypted file-backed vault records

Avoid SQLite in Phase 1 unless it becomes necessary. It adds install friction and native packaging complexity that the repo does not need yet.

### Job/process runner

The terminal app should include a local runner abstraction, not ad hoc `execFileSync` calls throughout commands.

Runner responsibilities:
- foreground command execution
- optional background job execution later
- stdout/stderr capture
- exit-code handling
- temp workspace management
- explicit capability checks for external tools

Initial external-tool capability buckets:
- archive: `zip`, `unzip`, `tar`
- vcs: `git`
- metadata/media: `mat2`, `ffmpeg`, `exiftool`

Phase 1 runner recommendation:
- synchronous/foreground only
- no daemon
- jobs recorded as structured local execution reports

### Plugin/tool structure

NullID should start with built-in tools, but the architecture should leave room for local plugins.

Recommended model:

- built-in commands live in `src/cli/commands`
- each command exports:
  - name
  - summary
  - argument schema
  - required permissions/capabilities
  - execute function

Later plugin shape:

- local manifest per plugin
- plugin commands discovered from a local directory
- no network installation required for core usage

Important boundary:
- plugin registration is a command/tool concern
- transform logic still belongs in `src/core`

### Permissions and sandbox model

NullID should stay local-first and capability-explicit.

Recommended permission model:

- default deny network
- default allow read/write only to user-requested paths and NullID state dirs
- external tool execution requires explicit command capability
- env passthrough should be allowlisted, not ambient
- path-sensitive commands should report exactly what they will read/write

Suggested capability groups:

- `fs.read`
- `fs.write`
- `fs.walk`
- `process.spawn.archive`
- `process.spawn.vcs`
- `process.spawn.metadata`
- `clipboard.write`
- `device.auth.local`

Browser and terminal should each implement these through adapters:
- browser adapter may support `clipboard.write` and `device.auth.local`
- terminal adapter may support `fs.*` and `process.spawn.*`

## Installable Terminal App Strategy

### Command name

Use:

- `nullid`

Why:
- matches the repo and package name
- simple to type
- works across shell docs, scripts, and future package managers

### Package/bin strategy

Phase 1 should add a real bin entry:

- `package.json`
  - `"bin": { "nullid": "./dist/cli/index.js" }`

Recommended source/build shape:

- source entry: `src/cli/index.ts`
- tiny launcher: `bin/nullid.js` with shebang if needed for local dev
- preserve `npm run cli` as a compatibility alias to the same compiled entry

This gives:

- `npm install -g`
- `npx nullid`
- local dev with one canonical CLI implementation

### Cross-platform distribution

Recommended rollout:

1. Phase 1:
   - npm package with `bin`
   - global install: `npm install -g nullid`
   - ephemeral use: `npx nullid`
2. Phase 2:
   - Homebrew tap
   - Scoop or winget package
   - optional Linux package wrapper
3. Only if later required:
   - standalone bundled binaries that include Node runtime

Do not make standalone native binaries a Phase 1 requirement. They are useful, but they are not required to make NullID a real installable terminal app.

## Runtime Recommendation

Stay on Node + TypeScript for the terminal app.

Reasons:

- the repo is already Node/TypeScript end to end
- the browser app, tests, scripts, and CLI can share types and contracts immediately
- Node 20 already gives the terminal app what it needs:
  - filesystem
  - process control
  - streams
  - WebCrypto via `crypto.webcrypto`
  - good cross-platform path/process behavior
- introducing Rust, Go, or Python now would increase risk and duplicate core logic

Use another runtime only when one of these becomes unavoidable:

- zero-Node-distribution is a hard product requirement
- performance bottlenecks are proven in practice
- a specific native OS capability is central to the product

Today, none of those justify a runtime switch.

## Phase 1 MVP Plan

Goal:
- create a true shared executable core
- ship a real installable `nullid` command
- preserve the current browser app
- avoid touching the desktop wrapper except to keep it working

### Scope

Include in Phase 1:

- shared core extraction for the safest high-value modules
- new TypeScript CLI entrypoint
- `package.json` bin support
- filesystem-backed terminal config/state skeleton
- migration of the current CLI to shared core for the commands with the best reuse/payoff

Explicitly defer:

- full TUI
- terminal vault UI
- native desktop runtime changes
- browser storage migration
- external plugin loading
- background job daemon

### Phase 1 command priority

Migrate these first:

- `hash`
- `sanitize`
- `sanitize-dir`
- `package-inspect`
- `pw-hash`
- `pw-verify`
- `enc`
- `dec`

Why these first:
- they are already heavily tested
- they are central to the terminal story
- they have the clearest overlap with existing browser logic
- they let us prove the shared-core boundary before tackling archive, office, vault, and workflow wizard complexity

### First implementation step

First step:
- extract the safest shared core slice and move the CLI entrypoint onto it without changing browser behavior

Create:

- `src/core/encoding.ts`
- `src/core/sanitizeEngine.ts`
- `src/core/workflowPackage.ts`
- `src/core/packageVerification.ts`
- `src/core/passwordHashing.ts`
- `src/core/cryptoEnvelope.ts`
- `src/platform/node/crypto.ts`
- `src/platform/browser/crypto.ts`
- `src/cli/index.ts`
- `src/cli/commands/hash.ts`
- `src/cli/commands/sanitize.ts`
- `src/cli/commands/sanitizeDir.ts`
- `src/cli/commands/packageInspect.ts`
- `src/cli/commands/passwordHash.ts`
- `src/cli/commands/passwordVerify.ts`
- `src/cli/commands/encrypt.ts`
- `src/cli/commands/decrypt.ts`
- `bin/nullid.js`

Refactor:

- `src/utils/encoding.ts`
- `src/utils/sanitizeEngine.ts`
- `src/utils/workflowPackage.ts`
- `src/utils/packageVerification.ts`
- `src/utils/passwordHashing.ts`
- `src/utils/cryptoEnvelope.ts`

Refactor those utility files into thin re-exports or imports from `src/core/*` so the browser app keeps compiling while the new core becomes canonical.

Then refactor:

- `scripts/nullid-local.mjs`

into a compatibility shim that forwards to the new CLI entry instead of remaining the primary implementation.

Then update:

- `package.json`

to add:

- real `bin` mapping
- a canonical CLI build target
- a compatibility `npm run cli` alias that calls the new entry

### Why this is the right first step

It solves the biggest structural problem first:

- one executable core instead of browser logic plus CLI duplication

It also creates the foundation for everything else:

- installable terminal command
- browser/core reuse
- future TUI
- future plugin registry
- future desktop integration if still wanted

And it avoids the highest-risk areas for now:

- vault storage migration
- browser-only cleanup adapters
- Tauri changes

## Final Recommendation

NullID should become:

- a shared local security core
- an installable `nullid` CLI as the primary local operations surface
- an optional TUI for guided workflows
- a preserved browser UI for existing flows and file-oriented interactions
- an optional desktop wrapper only after the terminal architecture is stable

The repo does not need a rewrite. It needs a disciplined extraction of the logic it already has.
