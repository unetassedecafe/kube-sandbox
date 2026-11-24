# Changelog

All notable changes to the kube-sandbox Hermes terminal backend plugin.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-24

### Added
- CI workflow running the offline protocol tests and compiling all sources on push/PR.
- Renovate config and a release workflow publishing a GitHub Release on `v*` tags.
- This changelog; the plugin manifest version is now released via annotated tags.

### Fixed
- `plugin/__init__.py` now exposes `register(ctx)`, which registers the
  `kube-sandbox` terminal backend. Without it the loader dropped the plugin
  ("no register() function") and `terminal.backend: kube-sandbox` failed with
  "Unknown environment type".

### Changed
- Deployments should pin a release tag (e.g. `v0.2.0`) instead of a commit SHA.

## [0.1.0] - 2026-11-24

### Added
- Initial backend: claim a gVisor micro-VM from the cluster warm pool, run every
  command through the exec websocket stream, opt-in secret files seeded
  file-only (never into the sandbox environment), claim deleted on cleanup.
