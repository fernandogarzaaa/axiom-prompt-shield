# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-13

First tagged release.

### Added
- `axiom-prompt-shield` CLI: tests a system prompt against 7 known prompt-injection
  attacks (direct override, roleplay jailbreak, encoded payload, delimiter escape,
  multi-turn manipulation, authority impersonation, hypothetical framing).
- Local heuristic resistance scorer (`src/scorer.rs`), per attack.
- Hardening loop that drives the real `axiom-agent-task` binary (propose, score,
  commit or roll back) with an integration test (`tests/axiom_integration.rs`).
- CI on stable Rust with `--locked` builds (Cargo.lock committed).

### Documentation
- "Honest limitations" section, including the substring-marker gaming caveat
  (negation and parroting can fool the heuristic scorer).
