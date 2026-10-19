---
key: DT-3-repo-issue
summary: "Repo issue from DT-3: correct DT-3's declared file scope so it includes clients/desktop-tauri/src-tauri/src/relay_config.rs and clients/desktop-tauri/src-tauri/src/relay_client.rs"
status: todo
risk: medium
backend: ollama
persona: null
dependencies: []
files:
  - clients/desktop-tauri/tauri.conf.json
  - clients/desktop-tauri/src-tauri/capabilities/default.json
  - clients/desktop-tauri/Cargo.toml
  - clients/desktop-tauri/src-tauri/src/lib.rs
  - Cargo.lock
  - clients/desktop-tauri/src-tauri/src/relay_config.rs
  - clients/desktop-tauri/src-tauri/src/relay_client.rs
---

# DT-3-repo-issue — correct DT-3's declared file scope

**Summary.** This follow-up story corrects DT-3's declared file scope. DT-3 ("Desktop: allow the
shell to reach the relay and let the relay URL be configured") declares five files, but two files
that its own title names — "let the relay URL be configured" and "allow the shell to reach the
relay" — are missing from that list, and the committed tests import/require them:

- `clients/desktop-tauri/src-tauri/src/relay_config.rs`
- `clients/desktop-tauri/src-tauri/src/relay_client.rs`

The committed tests that require them are `tests/relay_config.rs` and the
`should_refuse_to_dial_a_plain_ws_remote_host` test.

## Corrected file scope (union of DT-3's declared scope and the two missing files)

1. `clients/desktop-tauri/tauri.conf.json`
2. `clients/desktop-tauri/src-tauri/capabilities/default.json`
3. `clients/desktop-tauri/Cargo.toml`
4. `clients/desktop-tauri/src-tauri/src/lib.rs`
5. `Cargo.lock`
6. `clients/desktop-tauri/src-tauri/src/relay_config.rs`
7. `clients/desktop-tauri/src-tauri/src/relay_client.rs`

Seven entries: the five pre-existing entries are kept (no drops) and the two missing files are
appended once each (no duplicates). The correction lives in this new story record; DT-3's own
record is not rewritten in place.

## Status of DT-3 and PR #152

DT-3 stays **parked** for human merge review of PR #152 (open, green, `risk: medium` > threshold).
The PR is not MERGED, so `mark_done` fails closed — that is the intended behaviour, not a defect.

## Rationale

The recorded `parked_reason` on DT-3 is stale: live evidence shows commits on `agent/dt-3`, a full
suite passing at HEAD, and open PR #152. But the PR is not MERGED, so `mark_done` fails closed. The
real blocker is a scope-gate conflict: the reviewer's file-scope list omits two files the committed
tests import/require, so the scope gate cannot pass even though the work itself is green.

## Constraints (from the triage ruling)

- Do **NOT** revert the two files (`relay_config.rs`, `relay_client.rs`).
- Do **NOT** delete or edit the committed tests (`tests/relay_config.rs`, the
  `should_refuse_to_dial_a_plain_ws_remote_host` test).
- Do **NOT** mark DT-3 done.
- Leave DT-3 parked for human merge review of PR #152.
- Do not implement DT-3's own deliverable in this story; this story only corrects the declared
  file scope so the scope gate matches what the committed tests require.
