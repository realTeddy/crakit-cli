# crakit CLI

Free, single-binary EU Cyber Resilience Act (Regulation (EU) 2024/2847) kit: `scope`, `sbom`, `vulns`, `policy`, `incident`. Go, standard library only.

## Rules

- Never claim or imply compliance. Every verdict, policy and draft carries the disclaimer in `internal/cra` (`Disclaimer`).
- Every regulatory statement cites an article, annex or recital of Regulation (EU) 2024/2847 from `internal/cra`. Do not invent citations.
- No network except `crakit vulns`, which sends package coordinates (purl, or ecosystem + name + version) to OSV.dev and nothing else. Tests make no network calls (OSV is mocked with httptest).
- Standard library only; no third-party modules.
- Fixtures in `testdata/` are hand-written with public package names. No real SBOMs.
- crakit never files anything with ENISA or a CSIRT.
- Commits use the GitHub no-reply address (set in this clone's git config).

## Commands

```
gofmt -l . && go vet ./... && go test ./...           # quality gate, also run by .github/workflows/ci.yml
go build -o crakit . && ./crakit --help
go run ./scripts/release -version X.Y.Z -out dist      # six platform archives plus SHA256SUMS
git tag vX.Y.Z && git push origin vX.Y.Z               # GitHub release via .github/workflows/release.yml
```

The Annex III/IV category slugs here differ from the hosted app's for ten categories; the hosted scope checker accepts these spellings as aliases.
