package sbom

import (
	"bufio"
	"os"
	"strings"
)

// ParseCargoLock parses [[package]] tables from Cargo.lock with a minimal
// TOML line reader. Packages without a `source` (the workspace crates
// themselves) are skipped; their dependencies are marked direct.
func ParseCargoLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type cp struct {
		name, version, source string
		deps                  []string
	}
	var all []cp
	var cur *cp
	inDeps := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[package]]" {
			all = append(all, cp{})
			cur = &all[len(all)-1]
			inDeps = false
			continue
		}
		if strings.HasPrefix(line, "[") {
			cur = nil
			inDeps = false
			continue
		}
		if cur == nil {
			continue
		}
		if inDeps {
			if line == "]" {
				inDeps = false
				continue
			}
			d := strings.Fields(unquote(strings.TrimSuffix(line, ",")))
			if len(d) > 0 {
				cur.deps = append(cur.deps, d[0])
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "name":
			cur.name = unquote(v)
		case "version":
			cur.version = unquote(v)
		case "source":
			cur.source = unquote(v)
		case "dependencies":
			if v == "[" {
				inDeps = true
			} else {
				// inline array
				v = strings.Trim(v, "[]")
				for _, d := range strings.Split(v, ",") {
					if f := strings.Fields(unquote(strings.TrimSpace(d))); len(f) > 0 {
						cur.deps = append(cur.deps, f[0])
					}
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	direct := map[string]bool{}
	for _, p := range all {
		if p.source == "" {
			for _, d := range p.deps {
				direct[d] = true
			}
		}
	}
	var pkgs []Package
	for _, p := range all {
		if p.source == "" || p.name == "" {
			continue
		}
		pkgs = append(pkgs, Package{Ecosystem: "cargo", Name: p.name, Version: p.version, Direct: direct[p.name]})
	}
	return pkgs, nil
}
