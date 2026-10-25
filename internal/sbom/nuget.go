package sbom

import (
	"encoding/json"
	"os"
)

type nugetLock struct {
	Version      int                            `json:"version"`
	Dependencies map[string]map[string]nugetDep `json:"dependencies"`
}

type nugetDep struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

// ParseNuGetLock parses packages.lock.json. Entries of type "Direct" are
// direct; "Transitive" are indirect; "Project" references are skipped.
func ParseNuGetLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock nugetLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var pkgs []Package
	for _, fw := range lock.Dependencies {
		for name, d := range fw {
			if d.Type == "Project" || d.Resolved == "" {
				continue
			}
			key := name + "@" + d.Resolved
			if seen[key] {
				continue
			}
			seen[key] = true
			pkgs = append(pkgs, Package{Ecosystem: "nuget", Name: name, Version: d.Resolved, Direct: d.Type == "Direct"})
		}
	}
	return pkgs, nil
}
