package sbom

import (
	"bufio"
	"os"
	"strings"
)

// ParsePnpmLock parses the `packages:` section of pnpm-lock.yaml
// (lockfileVersion 6 and 9) and the root `importers:` / `dependencies:`
// sections to mark direct dependencies. It is a minimal line parser.
func ParsePnpmLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	direct := map[string]bool{}
	var pkgs []Package
	seen := map[string]bool{}

	section := ""    // top-level key
	inDeps := false  // inside a dependencies/devDependencies block of an importer
	depsIndent := -1 // indentation of the dependency entries
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		raw := sc.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		line := strings.TrimSpace(raw)
		if indent == 0 {
			section = strings.TrimSuffix(line, ":")
			inDeps = false
			continue
		}
		switch section {
		case "importers", "dependencies", "devDependencies", "optionalDependencies":
			key := strings.TrimSuffix(line, ":")
			if section != "importers" && indent == 2 {
				// lockfileVersion 5/6 single-project: top-level dependencies map
				direct[unquote(key)] = true
				continue
			}
			if key == "dependencies" || key == "devDependencies" || key == "optionalDependencies" {
				inDeps = true
				depsIndent = indent + 2
				continue
			}
			if inDeps && indent == depsIndent && strings.HasSuffix(line, ":") {
				direct[unquote(key)] = true
				continue
			}
			if inDeps && indent < depsIndent {
				inDeps = false
			}
		case "packages", "snapshots":
			if section == "snapshots" {
				continue
			}
			if indent != 2 || !strings.HasSuffix(line, ":") {
				continue
			}
			key := unquote(strings.TrimSuffix(line, ":"))
			key = strings.TrimPrefix(key, "/")
			// strip peer suffix like (react@18.2.0) or _react@18.2.0
			if i := strings.Index(key, "("); i > 0 {
				key = key[:i]
			}
			if i := strings.Index(key, "_"); i > 0 && strings.Contains(key[i:], "@") {
				key = key[:i]
			}
			at := strings.LastIndex(key, "@")
			if at <= 0 {
				continue
			}
			name, ver := key[:at], key[at+1:]
			if seen[name+"@"+ver] {
				continue
			}
			seen[name+"@"+ver] = true
			pk := npmPackage(name, ver)
			pk.Direct = direct[name]
			pkgs = append(pkgs, pk)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// Second pass for Direct in case packages: preceded importers:.
	for i := range pkgs {
		full := pkgs[i].Name
		if pkgs[i].Group != "" {
			full = "@" + pkgs[i].Group + "/" + pkgs[i].Name
		}
		if direct[full] {
			pkgs[i].Direct = true
		}
	}
	return pkgs, nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
