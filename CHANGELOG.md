# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.3.0] - 2026-07-19

### Chores
- **deps:** Adopt dig-rpc-protocol v0.3, drop yanked dig-rpc-types (#2)

## [0.2.1] - 2026-07-12

### CI
- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)- Add flaky-test management (#489) (#1)

## [0.2.0] - 2026-07-04

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

### CI
- Authenticate the dig-rpc-types sibling checkout (private repo)

## [0.1.0] - 2026-04-22

### Features
- Initial dig-rpc v0.1.0

### Documentation
- Comprehensive README with full public API reference


