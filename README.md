# cctx — Claude Code Context Switcher

Switch Claude Code authentication identities (OAuth subscription and API-key)
from the command line. macOS-first. See [PRD and architecture docs](https://github.com/rootwarp/claude-code-context-switcher)
for scope.

Status: in development (Phase 0 foundations).

## Claude Code version policy

cctx is known to interoperate with Claude Code **`2.1.114`** (the version
observed during Phase-0 research). This pin lives in
`src/lib.rs::CLAUDE_CODE_PINNED_VERSION`.

### Verifying your local version

```
claude --version
```

If this reports a different version, cctx may still work — but the attribute
schemas cctx depends on (macOS Keychain `Claude Code-credentials` item format,
`~/.claude.json` identity-block layout, `~/.claude/settings.json` env keys)
have not been re-validated against that version.

### Bumping the pin

Before adopting a newer Claude Code version:

1. Re-run the Phase-0 research spikes against the new version:
   - **0.1** — inspect the Keychain `Claude Code-credentials` attribute set.
   - **0.2** — re-verify `userID` stability across logout/login.
   - **0.3** — re-check `.credentials.json` fallback conditions.
2. Update `CLAUDE_CODE_PINNED_VERSION` in `src/lib.rs`.
3. Update this README.

The developer should also disable Claude Code auto-update on the dev laptop
during active cctx development to avoid mid-sprint surprises. Native install
method (`~/.local/share/claude/versions/`) supports this by not auto-pulling
newer versions unless explicitly invoked.
