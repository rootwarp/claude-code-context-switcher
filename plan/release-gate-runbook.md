# Release Gate Runbook — Phase 3 Exit

Perform on a macOS laptop with two real Claude OAuth subscriptions.
CCTX binary: install via `cargo install --path .` from the repo root.

## Preconditions

- `cctx` binary installed (`cargo install --path .`)
- `claude /login` done twice (once as each account), with `cctx add personal` and `cctx add work` in between
- `cctx list` shows both contexts
- `cctx -c` shows one of them as active
- When running the automated scaffold: `CCTX_RELEASE_GATE=1 CCTX_REAL_KEYCHAIN=1 cargo test --test release_gate -- --ignored --test-threads=1`

## Test 1: OAuth → OAuth

1. Run `cctx work`.
2. Launch `claude` (interactive).
3. Issue `/status` inside the Claude session, or check the subscription email shown at startup.
4. Verify the identity shown matches the **work** account.
5. Exit `claude`.
6. Run `cctx personal`.
7. Launch `claude` again.
8. Verify the identity shown matches the **personal** account.
9. Exit `claude`.

**Expected outcome:** Each `cctx <name>` exits 0 and emits "switched to <name>" on stderr. The `claude` session reports the correct account identity in both cases with no authentication errors.

## Test 2: OAuth → API-key → OAuth

1. Ensure an API-key context `console-key` exists. If not, place an Anthropic API key in `~/.claude/settings.json` under `env.ANTHROPIC_API_KEY`, then run `cctx add console-key`.
2. Run `cctx console-key`.
3. Run `claude -p "ping"` (non-interactive prompt).
4. Verify the response is returned via the API key (no OAuth browser redirect; response comes back promptly).
5. Run `cctx personal`.
6. Launch `claude` (interactive).
7. Issue `/status` or observe the startup banner.
8. Verify the identity returned matches the **personal** OAuth account.

**Expected outcome:** Step 3 uses the API key path (no OAuth flow). Step 6–8 correctly restores the personal OAuth credential — `settings.json` has no `ANTHROPIC_API_KEY`, the keychain holds the personal OAuth blob, and `~/.claude.json` identifies the personal account.

## Test 3: 20-switch stress test

```bash
for i in $(seq 1 10); do cctx work; cctx personal; done
count=$(security dump-keychain 2>/dev/null | grep -c '"Claude Code-credentials"' || true)
echo "Keychain item count: $count"
[ "$count" -eq 1 ] || echo "FAIL: expected 1, got $count (orphaned entries present?)"
```

**Expected outcome:** All 20 `cctx` invocations exit 0. `$count` equals `1` — confirming only one `Claude Code-credentials` item exists in the Keychain with no orphaned entries. Run tests with `--test-threads=1` to avoid keychain races between concurrent test functions.

## Performance spot-check

Run on a warm system (at least one prior `cctx` invocation since boot):

```bash
time cctx
time cctx -c
time cctx work
```

**Expected outcome:** All three commands complete in under 100 ms wall-clock time.

## Sign-off

- Reviewer (must not be the commit author): _______________
- Date: _______________
- Test 1 passed: [ ]
- Test 2 passed: [ ]
- Test 3 passed: [ ]
- Performance spot-check passed: [ ]
- Notes: _______________
