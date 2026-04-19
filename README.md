# cctx — Claude Code Context Switcher

`cctx` switches Claude Code authentication identities (OAuth subscription and API-key accounts) from the command line — no manual `/logout` / `/login`. Store each identity under a short name, then `cctx <name>` to activate it; the next `claude` launch picks it up automatically. Secrets live in the macOS Keychain; config files are mode 0600. **Platform:** macOS (Keychain-backed). Linux/Windows: P2 backlog. Not to be confused with [nwiizo/cctx](https://github.com/nwiizo/cctx), a different tool for switching Claude Code settings and MCP servers — see "Name collision" below.

---

## Install

### Homebrew (recommended, v1+)

```sh
brew install rootwarp/tap/cctx
```

### Cargo

```sh
cargo install claude-code-context-switcher
```

---

## Quickstart

```sh
# 1. Log in to the first account in Claude Code
claude /login

# 2. Snapshot the active identity as "personal"
cctx add personal

# 3. Later, switch to a different stored context
cctx work
```

Repeat step 1–2 for each account. Use `cctx` (no arguments) to list all stored contexts.

---

## Commands

| Command | What it does | Example |
|---|---|---|
| `cctx` | List all stored contexts (`*` marks the active one) | `cctx` |
| `cctx <name>` | Switch to a stored context | `cctx work` |
| `cctx -c` / `cctx current` | Print the currently-active context name (v1.1) | `cctx -c` |
| `cctx add <name>` | Capture the live identity as a new context | `cctx add personal` |
| `cctx delete <name>` | Remove a stored context | `cctx delete staging` |
| `cctx rename <old> <new>` | Rename a context (v1.1) | `cctx rename old new` |
| `cctx doctor` | Inspect and repair incomplete switch state | `cctx doctor --dry-run` |
| `cctx completions <shell>` | Emit a shell completion script | `cctx completions zsh` |

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (including NoOp — context already active) |
| 1 | Unexpected error |
| 2 | Argument parse error (clap) |
| 3 | Not found / not implemented (`ContextNotFound`, `KeychainItemMissing`, `Unimplemented`) |
| 4 | Config / parse error (`ContextsParseError`, `ClaudeStateParseError`, `.credentials.json` fallback) |
| 5 | Doctor-recoverable (`PartiallyAppliedState`, `ConcurrentAccess`, `VerifyFailed`) |
| 6 | Manual restore required (`RollbackFailed`) |

---

## Environment variables

| Variable | Purpose |
|---|---|
| `CCTX_HOME` | Override cctx config dir (default `~/.config/cctx`). Unstable — primarily for tests. |
| `CLAUDE_CONFIG_DIR` | Override Claude Code config dir (default `~/.claude`). Mirrors the Claude Code env knob. |
| `CCTX_REAL_KEYCHAIN=1` | Unlocks real-Keychain integration tests (requires macOS Keychain access). |

---

## Why not `cctx exec`?

API-key-only `exec` is a P2 backlog item. OAuth-based exec is blocked upstream on [issue #37512](https://github.com/anthropics/claude-code/issues/37512), which silently purges the Keychain entry when `CLAUDE_CODE_OAUTH_TOKEN` is set in a child process.

---

## What "(unmanaged)" means

When `cctx` lists contexts, it auto-detects which stored context matches the live Claude Code identity by fingerprint. If the active identity was not captured with `cctx add`, the list shows `(unmanaged)` — the identity is live but not tracked by cctx.

---

## Name collision

An unrelated tool [nwiizo/cctx](https://github.com/nwiizo/cctx) exists with the same binary name. That tool switches Claude Code *settings and MCP servers*; this tool switches *authentication identities* (OAuth / API key). If both are installed, the last one on `$PATH` wins.

---

## Security model

`Secret<T>` wraps sensitive strings and calls `zeroize` on drop so key material is cleared from memory when it goes out of scope. OAuth credential blobs are stored only in the macOS Keychain — they are never written to disk by cctx. Backup snapshots written during a switch and the `contexts.yaml` config file are both created with mode 0600.

---

## Claude Code version policy

cctx is validated against Claude Code **`2.1.114`** (the version observed during Phase-0 research). This pin lives in `src/lib.rs::CLAUDE_CODE_PINNED_VERSION`.

```sh
claude --version        # verify your local version
```

If your version differs, cctx may still work, but the Keychain attribute schema, `~/.claude.json` identity-block layout, and `~/.claude/settings.json` env keys have not been re-validated against that version.

### Bumping the pin

1. Re-run the Phase-0 spikes against the new version:
   - **0.1** — inspect the Keychain `Claude Code-credentials` attribute set.
   - **0.2** — re-verify `userID` stability across logout/login.
   - **0.3** — re-check `.credentials.json` fallback conditions.
2. Update `CLAUDE_CODE_PINNED_VERSION` in `src/lib.rs`.
3. Update this README.

Disable Claude Code auto-update on the dev machine during active cctx development to avoid mid-sprint schema surprises.

## Running the stress suite

Requires two OAuth contexts (`personal`, `work`) and one API-key context (`console-key`) pre-seeded via `cctx add`.

```bash
# 20-switch Keychain orphan test (macOS, requires real Keychain)
CCTX_REAL_KEYCHAIN=1 cargo test --test stress_keychain -- --ignored --test-threads=1

# Performance benchmarks (requires hyperfine)
CCTX_BENCH=1 cargo test --test bench_hyperfine -- --ignored --test-threads=1
```
