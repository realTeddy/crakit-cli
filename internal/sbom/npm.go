package sbom

import (
	"encoding/json"
	"os"
	"strings"
)

type npmLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
	Dependencies    map[string]npmV1Dep       `json:"dependencies"`
}

type npmLockPackage struct {
	Version      string            `json:"version"`
	Dev          bool              `json:"dev"`
	Dependencies map[string]string `json:"dependencies"`
	Link         bool              `json:"link"`
}

type npmV1Dep struct {
	Version  string            `json:"version"`
	Dev      bool              `json:"dev"`
	Requires map[string]string `json:"requires"`
}

// ParseNpmLock parses package-lock.json v2/v3 ("packages") with a v1
// ("dependencies") fallback.
func ParseNpmLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var pkgs []Package
	if len(lock.Packages) > 0 {
		root := lock.Packages[""]
		direct := map[string]bool{}
		for n := range root.Dependencies {
			direct[n] = true
		}
		for key, p := range lock.Packages {
			if key == "" || p.Link || p.Version == "" {
				continue
			}
			idx := strings.LastIndex(key, "node_modules/")
			if idx < 0 {
				continue
			}
			full := key[idx+len("node_modules/"):]
			// Nested entries (node_modules/a/node_modules/b) are never direct.
			nested := strings.Contains(key[:idx], "node_modules/")
			pk := npmPackage(full, p.Version)
			pk.Direct = !nested && direct[full]
			pkgs = append(pkgs, pk)
		}
		return pkgs, nil
	}
	for name, d := range lock.Dependencies {
		pk := npmPackage(name, d.Version)
		pk.Direct = true // v1 top-level entries are the hoisted tree; treat as direct
		pkgs = append(pkgs, pk)
	}
	return pkgs, nil
}

func npmPackage(full, version string) Package {
	p := Package{Ecosystem: "npm", Version: version}
	if strings.HasPrefix(full, "@") {
		if i := strings.Index(full, "/"); i > 0 {
			p.Group = full[1:i]
			p.Name = full[i+1:]
			return p
		}
	}
	p.Name = full
	return p
}
