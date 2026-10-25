# crakit CLI

Self-serve EU Cyber Resilience Act (Regulation (EU) 2024/2847) kit for small makers of software and firmware. Single static Go binary, standard library only.

**This is a checklist and drafting aid, not legal advice and not a guarantee of compliance with Regulation (EU) 2024/2847.**

## Build

```sh
cd cli && go build -o crakit .
```

## Commands

```sh
crakit scope --product-type firmware --connected yes --commercial yes --open-source no \
             --excluded-sector none --category router-modem-switch --role manufacturer [--json]
crakit scope                      # interactive questionnaire when run in a terminal
crakit scope --list-categories    # Annex III / IV category slugs

crakit sbom [path] [-o bom.cdx.json] [--name N] [--version V] [--include-indirect] [--tool auto|builtin|syft|cdxgen]
             # CycloneDX 1.6 from package-lock.json, pnpm-lock.yaml, go.mod, Cargo.lock, packages.lock.json

crakit vulns bom.cdx.json [--json] [--fail-on none|low|medium|high|critical] [--osv-url URL]
             # the only network call: package coordinates are sent to OSV.dev (env CRAKIT_OSV_URL overrides)

crakit policy --org "Acme" --contact mailto:security@acme.example [--contact ...] [--encryption URL] \
              [--languages en,de] [--expires 2027-10-24T00:00:00.000Z] [--ack-days 5] [--disclosure-days 90] [--out-dir .]
             # SECURITY.md (CVD policy) and .well-known/security.txt (RFC 9116)

crakit incident new --kind vulnerability|incident --product "Widget" --version 1.2 --title "..." [--aware-at RFC3339]
crakit incident status [id] [--now RFC3339]
crakit incident update <id> [--fix-available-at RFC3339] [--mark early_warning|notification|final_report [--at RFC3339]] [--note ...] [--status open|reported|closed]
crakit incident draft <id> --stage early_warning|notification|final_report
crakit incident list
             # local Art. 14 reporting clock; store at $XDG_CONFIG_HOME/crakit/incidents.json, --store FILE or env CRAKIT_STORE

crakit version
```

## Key dates encoded

- 10 Dec 2024: entry into force. 11 June 2026: Chapter IV (notified bodies). 11 Sept 2026: Art. 14 reporting obligations. 11 Dec 2027: full application (Art. 71(2)).

## Develop

```sh
go test ./...   # no network; OSV is mocked with httptest
go vet ./... && gofmt -l .
```
