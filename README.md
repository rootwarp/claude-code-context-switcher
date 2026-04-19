# cctx — Claude Code Context Switcher

Switch Claude Code authentication identities (OAuth subscription and API-key)
from the command line — no manual `/logout` / `/login`.

**Platform:** macOS (Keychain-backed). Linux/Windows: P2 backlog.  
**Status:** Phase 3 in progress — OAuth switching end-to-end is wired; `cctx add`
OAuth capture and the release-gate runbook are the remaining Phase-3 items.

---

## Installation

```sh
cargo install --path .
```

Homebrew tap (`brew install rootwarp/tap/cctx`) ships with v1. Until then, use
`cargo install`.

---

## How to use

### Add a context

Log in to a Claude account first, then capture it:

```sh
claude /login           # authenticate in Claude Code as usual
cctx add work           # snapshot the active identity as "work"
```

Repeat for each identity you want to manage. For an API-key context, set the key
in `~/.claude/settings.json` before running `cctx add`.

> `cctx add --oauth` (interactive guided capture) is a P1 item landing in v1.1.
> In v1, run `claude /login` manually first, then `cctx add <name>`.

### List contexts

```sh
cctx
```

Prints all stored contexts with `*` marking the currently-active one. If the
live identity was not added with `cctx add`, it shows as `(unmanaged)`.

### Switch

```sh
cctx work               # switch to "work"
cctx personal           # switch to "personal"
cctx switch work        # explicit subcommand form; identical behaviour
```

The next `claude` launch picks up the new identity with no additional steps.

### Print active context

```sh
cctx -c
cctx current            # alias
```

Exits 3 (`ContextNotFound`) if the live identity is not in `contexts.yaml`.

### Delete a context

```sh
cctx delete staging
cctx delete staging --force   # skip active-context guard
```

Removes the entry from `contexts.yaml` and sweeps any cctx-owned Keychain items
for that context.

### Rename a context

```sh
cctx rename old-name new-name
```

Updates the YAML entry and renames cctx-owned Keychain items. (v1.1 P1 item;
currently a stub in v1.)

### Recover from a crashed switch

If cctx is interrupted mid-switch (power loss, `kill -9`), the journal records
the partial state. On the next run cctx auto-detects it and prints a recovery
hint. You can also run doctor directly:

```sh
cctx doctor             # inspect journal state
cctx doctor --dry-run   # show what rollback/commit would do, without acting
cctx doctor --rollback  # restore the pre-switch snapshot
cctx doctor --commit    # mark an incomplete switch as committed
```

Exit 5 means doctor can recover the state. Exit 6 means the rollback itself
failed — the snapshot path is printed; restore manually.

### Shell completions

```sh
cctx completions zsh    # or bash / fish
```

---

## Environment variables

| Variable | Purpose |
|---|---|
| `CCTX_HOME` | Override cctx config dir (default `~/.config/cctx`). Primarily for tests. |
| `CLAUDE_CONFIG_DIR` | Override Claude Code config dir (default `~/.claude`). Mirrors the Claude Code env knob. |

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

## Known limitations (v1)

- **`cctx add` OAuth capture** — the Keychain mirror path (`cctx-oauth-<name>`)
  is not yet written in `handle_add`; switching to OAuth contexts captured in
  Phase 3 requires the blob already present in `Claude Code-credentials` at add
  time. Full OAuth capture lands before the Phase-3 exit gate.
- **`cctx add --oauth`** — interactive guided capture is a P1 item (v1.1).
  Run `claude /login` manually first.
- **`cctx rename`** — stub; Keychain rename lands in Phase 6 (v1.1).
- **`cctx exec`** — P2 backlog. API-key exec via child env can ship
  independently; OAuth exec is blocked on upstream
  [#37512](https://github.com/anthropics/claude-code/issues/37512).
- **Name collision** — an unrelated `nwiizo/cctx` exists; this project's binary
  is also named `cctx`. If both are installed, the last one on `$PATH` wins.

---

## Claude Code version policy

cctx is validated against Claude Code **`2.1.114`** (the version observed during
Phase-0 research). This pin lives in `src/lib.rs::CLAUDE_CODE_PINNED_VERSION`.

```sh
claude --version        # verify your local version
```

If your version differs, cctx may still work, but the Keychain attribute schema,
`~/.claude.json` identity-block layout, and `~/.claude/settings.json` env keys
have not been re-validated against that version.

### Bumping the pin

1. Re-run the Phase-0 spikes against the new version:
   - **0.1** — inspect the Keychain `Claude Code-credentials` attribute set.
   - **0.2** — re-verify `userID` stability across logout/login.
   - **0.3** — re-check `.credentials.json` fallback conditions.
2. Update `CLAUDE_CODE_PINNED_VERSION` in `src/lib.rs`.
3. Update this README.

Disable Claude Code auto-update on the dev machine during active cctx development
to avoid mid-sprint schema surprises.
