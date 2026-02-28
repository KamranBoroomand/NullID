# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added
- Guarded wipe flow with explicit confirmation and backup/export prompts.
- i18n coverage check script (`npm run i18n:check`) and CI integration.
- Expanded sanitization/redaction coverage for GitHub tokens, Slack tokens, and private key blocks.
- Governance docs and collaboration templates (`SECURITY`, `CONTRIBUTING`, `CODE_OF_CONDUCT`, `SUPPORT`, issue/PR templates).

### Changed
- Offline linting upgraded from simple regex checks to AST-based source scanning.
- Security-header audit upgraded to strict directive/value validation.
- Guide content updated to remove testimonial-style claims and provide operational notes.

### Fixed
- CSS token mismatch in redaction preview border styling (`--border` -> `--border-subtle`).

## [0.1.0] - 2026-02-28

### Added
- Initial release candidate baseline.
