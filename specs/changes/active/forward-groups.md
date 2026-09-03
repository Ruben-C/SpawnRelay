# Forward groups

Status: Implementing

## Problem

A forward is exactly one public port. Games such as Dune Awakening need several
ports (a UDP range plus a few TCP ports) that belong together, so today the
operator creates and manages each one by hand and nothing ties them together
in the API or the UI. Enabling, editing or deleting "the Dune server" means
touching five or more records.

## Outcome

An operator creates one forward group with a port spec such as
`7780-7784/udp, 5673, 15673, 25673` and SpawnRelay expands it into ordinary
per-port forwards that share a group. The group is created, edited, enabled,
disabled and deleted as one unit in the API and the web UI, while each port
keeps its own listener, firewall rule, live stats and status. Existing
single-port forwards keep working unchanged and appear as groups of one.

## Users / Actors

- Operator using the web UI or the token API (`POST /api/v1/forward-groups`).
- Existing automation scripts using `/api/v1/forwards`, which must not break.
- The server on startup, which backfills group membership for pre-existing forwards.

## Requirements

Data model

R1. Every forward carries a `group_id`. Forwards loaded from a state file that lack one get `group_id = id` on load, and this is persisted on the next save. No separate group collection exists; a group is the set of forwards sharing a `group_id`.
R2. A group is derived from its members: `client_id`, `target_host`, `name` and default `protocol` are those of the lowest-port member; `enabled` is true only when every member is enabled; `ports` is the canonical spec (R6) of the members.

Port spec

R3. A port spec is a list of entries separated by commas and/or whitespace. An entry is `PORT` or `START-END` (inclusive, `START <= END`), optionally followed by `/tcp`, `/udp` or `/both`, optionally followed by `>TARGET` where `TARGET` is a port (for a range, the target of `START`; later ports shift by the same offset). Entries without a protocol suffix use the group's `protocol` field (default `tcp`). Entries without `>TARGET` target the same port number.
R4. A spec that expands to more than 64 public ports is rejected with `400` naming the limit. Ports outside 1–65535 (public or target, after offset), malformed entries, an empty spec, and two entries covering the same public port with an overlapping protocol are rejected with `400` naming the offending entry.
R5. Each expanded (public port, protocol, target port) becomes one member forward with the group's `client_id`, `name`, `target_host` and `enabled`.
R6. The canonical rendering of a group's members lists them sorted by public port, collapses contiguous runs with the same protocol and the same target offset into `START-END`, always includes the `/proto` suffix, and includes `>TARGET` only when the target differs from the public port. Parsing a canonical spec and re-rendering it yields the same string.

API

R7. `GET /api/v1/forward-groups` returns all groups sorted by lowest public port, filterable with `?client_id=`. `GET /api/v1/forward-groups/{id}` returns one group. A group object has `id` (the `group_id`), `client_id`, `client_name`, `name`, `protocol`, `ports`, `target_host`, `enabled`, `created_at`, `updated_at`, `public_host`, aggregated `stats` (sums of member counters, `listening` true only when every enabled member listens), a summary `firewall` (worst member state, with the first error message), and `forwards`: the full member forward objects sorted by public port.
R8. `POST /api/v1/forward-groups` takes `client_id` (required), `ports` (required), `name` (default: the canonical spec), `protocol` (default `tcp`), `target_host` (default `127.0.0.1`), `enabled` (default `true`). It validates the spec, reserved ports and conflicts, then binds every member. If any port is reserved, conflicts with a forward outside the group, or fails to bind, nothing is created and the response is `409` naming that port (and the conflicting forward's name where there is one). On success it returns `201` with the group object, the firewall is synced and the client is notified once.
R9. `PATCH /api/v1/forward-groups/{id}` accepts any subset of the create fields; an omitted `protocol` means `tcp` for suffix-less entries, as on create. Members are keyed by (public port, protocol): keys still present keep their forward `id` and stats (their target and group-level fields are updated in place), keys removed are deleted, keys added are created. The whole change is atomic: on any validation, conflict or bind failure no member changes and the response is `400`/`409` as in R8. Changing `client_id` moves every member and both old and new clients are notified.
R10. `DELETE /api/v1/forward-groups/{id}` removes every member, stops their listeners, syncs the firewall and notifies the client. `404` when no forward has that `group_id`.
R11. The existing `/api/v1/forwards` endpoints keep their documented behaviour. `POST /forwards` creates a group of one (`group_id = id`). The forward object gains `group_id`. `PATCH /forwards/{id}` on a member of a multi-port group rejects a `client_id` change with `400` ("move the group instead"); other fields change only that member. `DELETE /forwards/{id}` removes only that member; a group with no members ceases to exist.
R12. `GET /status` gains `forward_groups_total`; `forwards_total` still counts member forwards. Client objects gain `forward_group_count` alongside `forward_count`.
R13. `docs/API.md` documents the port spec grammar with the limit, the group object, the five endpoints, the `group_id` field on forwards, the new status/client fields, and a Dune Awakening style example.

Web UI

R14. The Forwards tab shows one row per group: name (with a disabled badge when not all members are enabled), client, ports summary (canonical spec), public host, target host, aggregated traffic, a group enable toggle, Edit and Delete. A group of one still shows its copyable `host:port` public address.
R15. A group row with more than one member can be expanded to a per-port list showing protocol, copyable public address, target port, listening state, firewall state and per-port stats. When any enabled member is not listening or has a firewall error, the collapsed group row shows a visible warning so the problem is not hidden behind a healthy-looking group.
R16. The New/Edit forward modal replaces the two port number inputs with a `Ports` text input that accepts the spec, keeps the protocol select as the default protocol, keeps target host and enabled, shows a one-line grammar hint with an example, and submits to the group endpoints. Edit pre-fills the canonical spec. Game presets fill the `Ports` field (presets become spec strings so multi-port games can be added later).
R17. The group toggle calls `PATCH /forward-groups/{id}` with `enabled`; group Delete confirms with the group name and its port count and calls `DELETE /forward-groups/{id}`. The dashboard "Port forwards" stat shows the group count with the port count as secondary text; the Clients table forwards column shows the group count.
R18. Spec validation errors from the API are shown verbatim in the modal so the operator sees which entry was rejected.

## Acceptance Scenarios

### A1 — Dune Awakening group
Given client `ai-max` exists and no forwards use ports 7780–7784, 5673, 15673, 25673
When the operator POSTs `{"client_id":"…","name":"Dune Awakening","protocol":"tcp","ports":"7780-7784/udp, 5673, 15673, 25673","target_host":"192.168.1.20"}`
Then `201` returns a group with 8 member forwards (5 UDP, 3 TCP), each targeting the same port on 192.168.1.20, all listening, firewall state `open` on a managed host, and the Forwards tab shows one row "Dune Awakening" with ports `5673/tcp, 7780-7784/udp, 15673/tcp, 25673/tcp` that expands to 8 port lines.

### A2 — Conflict creates nothing
Given a forward already uses 15673/tcp
When the same POST as A1 is sent
Then `409` names port 15673 and the existing forward, and `GET /forwards` shows no new forwards on 7780–7784, 5673 or 25673.

### A3 — Edit preserves stats for kept ports
Given the A1 group has relayed traffic on 7780/udp
When the operator PATCHes `ports` to `7780-7786/udp, 5673, 15673, 25673`
Then 7780–7784 keep their forward ids and counters, 7785 and 7786 are new members, and the group's `updated_at` changes.

### A4 — Group disable and delete
Given the A1 group is enabled
When the operator clicks the group toggle
Then every member becomes disabled, listeners stop, firewall state becomes `closed`, and the row shows the disabled badge.
When the operator clicks Delete and confirms
Then all 8 forwards are gone from `GET /forwards` and the client is notified once.

### A5 — Existing state file
Given a state file from the previous release with three forwards and no `group_id`
When the server starts
Then `GET /forward-groups` lists three groups of one whose ids equal the forward ids, and the Forwards tab looks as it did before apart from the new ports column.

### A6 — Oversized or malformed spec
When the operator submits `ports` of `1-65535` or `7780-7784/tcpp`
Then `400` is returned naming the 64-port limit or the malformed entry, nothing is created, and the modal shows that message.

## Edge Cases

- Same port listed as `/tcp` and `/udp` in one spec → two members, allowed (mirrors two atomic forwards today).
- Same port listed twice with overlapping protocol (e.g. `5673, 5673/both`) → `400` naming the entry.
- Spec includes the tunnel or admin port → `409` naming it, as for single forwards.
- `>TARGET` on a range that pushes a target above 65535 → `400`.
- Range written `END-START` → `400` (no silent swap).
- PATCH that removes every port (`ports: ""`) → `400`; use DELETE to remove a group.
- Member deleted via `DELETE /forwards/{id}` leaving one member → group of one; leaving none → group gone, `GET /forward-groups/{id}` is `404`.
- Startup with a member that fails to bind → that member reports `listening: false`, the group row shows the warning (R15); other members are unaffected, matching today's per-forward startup behaviour.
- Deleting a client → its groups vanish with its forwards (existing behaviour).

## Non-goals

- Collapsing contiguous ports into range rules in the firewall backends. Rules stay per port.
- Per-group target hosts differing between members (create separate groups).
- Changing what the tunnel client receives; it still gets one `ForwardInfo` per port.
- Adding new game presets (Dune Awakening included) beyond making the preset table spec-capable.
- Any change to the wire protocol or client binary.

## Constraints

- Standard library only, plus yamux; no cgo.
- Go 1.22 `ServeMux` patterns; JSON errors are `{"error": ...}`.
- Web UI stays vanilla JS with no inline handlers (CSP).
- The state file must remain loadable by this release from the previous release's format without manual migration.

## Design Notes

- Grouping layer over atomic forwards was chosen over widening the Forward record. The tunnel runner, firewall sync, stats and conflict detection stay per forward and untouched; groups are expansion and aggregation at the API/UI layer.
- No stored group record: group-level fields live on each member and are rewritten together. Avoids a second collection to keep in sync and makes the backfill a one-line load step.
- Group atomicity on create/update: bind all new listeners before committing; on failure remove the ones just started and restore any replaced listeners, then return the error. The existing single-forward `Apply` already restores a replaced listener on failure; group update needs the same guarantee across members.
- Spec parser and canonical renderer belong in `internal/store` next to `Forward.Validate`, so the UI, API and tests share one implementation.

## Verification

- `internal/store` tests: parse and expand (ranges, suffixes, `>TARGET`, whitespace/comma mix), rejection cases (R4, edge cases), canonical rendering round trip (R6), `group_id` backfill on `Open` (R1).
- `internal/server` tests with a real store and tunnel: A1 create, A2 conflict leaves nothing, A3 update keeps ids, A4 delete, R11 member `client_id` rejection, R12 status counts.
- `go vet ./...` and `go test ./...` green; `make build`.
- Manual probe with `make run-server`: create the Dune group in the UI, expand the row, toggle, edit the spec, delete; confirm docs/API.md examples run with curl.

## Progress

Now: implementation complete; awaiting verification and commit
Done:
  R1–R6 store: group_id + backfill, ForwardsInGroup/GroupIDs — internal/store/store.go; port spec parser/renderer — internal/store/portspec.go; 4 new tests green
  R7–R12 API: internal/server/groups.go (list/get/create/patch/delete, aggregation), ApplyGroup rollback — internal/server/tunnel.go; forwards gain group_id, member client move rejected, status/client counts — internal/server/api.go; TestForwardGroupLifecycle + TestForwardGroupMemberDeleteShrinksGroup green
  R13 docs/API.md: new "Forward groups" section, group_id/count fields, member-endpoint notes
  R14–R18 UI: internal/server/web/app.js (group rows, expand, warning badge, ports modal, presets as specs), style.css, index.html copy; rendered output checked against the dev server with a Node DOM stub (no headless browser on this machine)
Next: /ark:verify (or review the diff), then commit
Gotchas: forward names are not unique today, so no naming guard is needed; PATCH default protocol is tcp, not the lowest member's (a PATCH with suffix-less entries would otherwise flip protocol); canonical spec sorts by port, so the Dune example renders as 5673/tcp, 7780-7784/udp, …
Resume: /clear, then /ark:next → verify
