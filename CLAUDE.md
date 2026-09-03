# SpawnRelay

Open-source game relay: a server on a VPS accepts one outbound TLS tunnel per
client, exposes public TCP/UDP ports and relays them to game servers on the
client's machine, so users never expose their home network directly. Includes a
web management interface, one-line installers and a token-authenticated REST
API (documented in docs/API.md).

## Layout

- `cmd/spawnrelay` – single binary: `spawnrelay server`, `spawnrelay client` and `spawnrelay firewall-agent`
- `internal/protocol` – wire format (Hello handshake, stream headers, UDP framing)
- `internal/tlsutil` – self-signed certs and fingerprint pinning
- `internal/store` – JSON state file (clients, forwards, tokens, admin, settings); `portspec.go` parses/renders multi-port specs
- `internal/server` – tunnel manager (`tunnel.go`), client self-update push/download (`update.go`), HTTPS API (`api.go`, `auth.go`), forward groups (`groups.go`), embedded UI (`web/`), embedded client installers (`scripts/`)
- `internal/client` – outbound tunnel client; `update.go` installs binaries pushed by the server
- `internal/firewall` – host firewall management: backends (ufw, firewalld, nftables, iptables), the root `firewall-agent` (unix socket) and its client; `internal/server/firewall.go` drives it
- `scripts/install-server.sh` – VPS installer (systemd)
- `docs/API.md` – API reference; keep it in sync with `internal/server/api.go`

## Commands

```bash
make build        # bin/spawnrelay
make build-all    # cross-compile into dist/
go test ./...
go vet ./...
make run-server   # dev server on https://127.0.0.1:8443 with ./dev-data
```

## Conventions

- Standard library only, plus `hashicorp/yamux`. No cgo (must cross-compile).
- Routing uses Go 1.22 `ServeMux` method patterns; JSON errors are `{"error": ...}`.
- Credential-management endpoints (tokens, password, settings) are session-only.
- The web UI is vanilla JS with a CSP that forbids inline scripts: no inline handlers.
- Any API change must be reflected in `docs/API.md` and, if user-facing, the web UI.

# Project Working Rules

## Architecture

- Inspect existing patterns before introducing new ones.
- Prefer simple changes over new abstractions.
- Avoid adding dependencies unless they provide clear value.
- Preserve public behavior unless the task explicitly changes it.

## Development

- Read relevant code before editing.
- Fix root causes rather than symptoms.
- Keep changes scoped to the requested outcome.
- Do not rewrite unrelated code.

## Product decisions

- Ask when requirements materially affect behavior, permissions, data ownership, security, compatibility, or architecture.
- Make routine implementation decisions autonomously.
- Investigate before asking: check the repo always; add 1–2 quick web searches when the decision concerns methods or approaches that exist outside the developer's head, and a deeper multi-source pass only for significant decisions (auth, billing, schema, irreversible operations, architecture). Purely domain questions — facts only the developer knows — get no web pass.
- Present decision points with the `AskUserQuestion` tool: the recommended option first, labeled "(Recommended)" with a one-line reason; 1–3 researched alternatives, each with its trade-off; and a "Let's discuss" option that returns to conversation. Give every option a one-line evidence trace, naming the source when web-derived. With more than ~4 viable options, present the strongest 3 plus "Let's discuss" and name the cut ones in one line.
- If research is unavailable or finds no real alternatives, say so and ask from repo evidence and stated reasoning — never pad fake options. After "Let's discuss", share the research summary and converse; re-present a selector only if the discussion converges on a materially different option set.
- Open discovery questions ("walk me through…") stay conversational; the selector is for choosing among knowable options.

## Quality

Before declaring completion: run relevant tests and type/build checks, inspect the final diff, verify the requested behavior, and report unresolved risks.

## Specifications

Product context lives in `specs/PROJECT.md`. Meaningful behavior changes get a change spec in `specs/changes/active/` (archived to `specs/changes/archive/` when verified). Difficult bugs get `specs/bugs/<name>.md`. Specs describe WHAT must be true; implementation detail belongs in Design Notes only when it must outlive the conversation.

Every spec and bug file in flight ends with a short `## Progress` block (Now / Done with evidence / Next / Gotchas / Resume), overwritten by each phase and deleted when the change is verified. It is a handoff note for a context with no memory — routing still comes from `Status:` and the diff, and where the two disagree the code wins.

Workflow: `/ark:explore` → `/ark:spec` → `/ark:implement` → `/ark:verify`; `/ark:debug` for bugs. `/ark:next` resumes the change in flight by reading spec `Status:` and the diff, and runs the next phase. Run `/clear` between phases; the state is on disk. Plain language works for every phase; `/ark:next` is typed.
