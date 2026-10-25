package sbom

import (
	"bufio"
	"os"
	"strings"
)

// ParseGoMod parses require directives from go.mod. Indirect requirements
// are returned with Direct=false.
func ParseGoMod(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pkgs []Package
	inBlock := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			if p, ok := goRequireLine(line); ok {
				pkgs = append(pkgs, p)
			}
			continue
		}
		if line == "require (" {
			inBlock = true
			continue
		}
		if strings.HasPrefix(line, "require ") {
			if p, ok := goRequireLine(strings.TrimPrefix(line, "require ")); ok {
				pkgs = append(pkgs, p)
			}
		}
	}
	return pkgs, sc.Err()
}

func goRequireLine(line string) (Package, bool) {
	indirect := strings.Contains(line, "// indirect")
	if i := strings.Index(line, "//"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Package{}, false
	}
	return Package{Ecosystem: "golang", Name: fields[0], Version: fields[1], Direct: !indirect}, true
}
