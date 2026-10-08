# axiom-prompt-shield

Prompt injection security testing for LLM system prompts, hardened through
[AXIOM](https://github.com/fernandogarzaaa/AXIOM-AETHER)'s transactional
agent-task loop.

## What it does

1. **Tests** a system prompt against a battery of 7 known prompt injection
   attacks (direct instruction override, roleplay jailbreak, encoded payload,
   delimiter escape, multi-turn manipulation, authority impersonation,
   hypothetical framing).
2. **Scores** resistance per attack with a local heuristic scorer.
3. **Hardens** vulnerable prompts by driving the real `axiom-agent-task`
   binary: hardened variants are proposed through AXIOM's `task_propose`,
   each verified by re-running the injection battery, applied
   transactionally, and rolled back on regression.

## Honest limitations

**The scorer is static analysis, not an LLM.** Without a model API key this
tool cannot observe real model behavior. Scores measure *prompt robustness
posture*: whether the prompt explicitly states the defensive policy that
blocks each attack category. A high score means the prompt *asserts* the
right defenses, not that any particular model will honor them. Treat results
as a hardening checklist, not a security guarantee.

**The AXIOM integration is real.** The `harden` command spawns the actual
`axiom-agent-task` binary from AXIOM-AETHER and speaks JSON-RPC over stdio
(`task_start`, `task_propose`, `task_history`, `task_finish`). The verifier
is this binary's own `verify` subcommand: AXIOM applies each proposed
hardening, runs the battery, keeps it only if the score passes the
threshold, and byte-for-byte rolls back on failure.

## Usage

```bash
# Test a prompt
axiom-prompt-shield test prompt.txt

# JSON report
axiom-prompt-shield test prompt.txt --json

# Harden via AXIOM (needs the axiom-agent-task binary)
axiom-prompt-shield harden prompt.txt \
  --axiom-bin /path/to/axiom-agent-task \
  --min-score 0.8

# Verifier entrypoint (used by AXIOM internally)
axiom-prompt-shield verify prompt.txt --min-score 0.8
```

Example hardening run:

```
AXIOM binary: /path/to/axiom-agent-task
baseline score: 0.000 (blocked 0/7)
task started: task-18dc7ab0d33afb33-0
attempt 1 [basic hardening]: passed=false fingerprint=259b21b6e2b7
    | verify: score 0.333 (threshold 0.800) -> FAIL
attempt 2 [basic hardening (duplicate)]: passed=false fingerprint=259b21b6e2b7
    | identical edit-set already rejected; not re-applied
attempt 3 [standard hardening]: passed=false fingerprint=3832f26179c6
    | verify: score 0.762 (threshold 0.800) -> FAIL
attempt 4 [full hardening]: passed=true fingerprint=d507f4a72244
    | verify: score 1.000 (threshold 0.800) -> PASS

--- task history (4 attempts) ---
attempt 1: FAIL fp=259b21b6e2b7 verify: score 0.333 (threshold 0.800) -> FAIL
attempt 2: FAIL fp=259b21b6e2b7 identical edit-set already rejected; not re-applied
attempt 3: FAIL fp=3832f26179c6 verify: score 0.762 (threshold 0.800) -> FAIL
attempt 4: PASS fp=d507f4a72244 verify: score 1.000 (threshold 0.800) -> PASS

task finished, committed=true
final score: 1.000 (blocked 7/7)
```

Note attempt 2: AXIOM's fingerprint dedup recorded the duplicate proposal
without re-running the verifier.

## Building

```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## License

MIT
