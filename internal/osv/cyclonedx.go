// Package osv queries OSV.dev for known vulnerabilities in the components of
// a CycloneDX SBOM. This is the only crakit feature that sends data off the
// machine, and it only sends package coordinates (purl, or name + version).
//
// Findings help with Annex I Part II (1)-(2) of Regulation (EU) 2024/2847
// (identify and remediate vulnerabilities). They are not a determination
// that a vulnerability is "actively exploited" under Art. 14(1).
package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Package is a component to query.
type Package struct {
	Name      string
	Version   string
	PURL      string
	Ecosystem string // OSV ecosystem name, inferred from purl type if absent
}

// Label is a human-readable component label.
func (p Package) Label() string {
	if p.PURL != "" {
		return p.PURL
	}
	return p.Name + "@" + p.Version
}

type cdxDoc struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Components  []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type       string         `json:"type"`
	Group      string         `json:"group"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
}

var supportedSpec = map[string]bool{"1.4": true, "1.5": true, "1.6": true, "1.7": true}

// ParseCycloneDX reads a CycloneDX JSON document (specVersion 1.4-1.7) and
// returns the packages to query. Components without a purl or a version are
// skipped.
func ParseCycloneDX(r io.Reader) ([]Package, error) {
	var doc cdxDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse CycloneDX JSON: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("not a CycloneDX document (bomFormat=%q)", doc.BOMFormat)
	}
	if !supportedSpec[doc.SpecVersion] {
		return nil, fmt.Errorf("unsupported CycloneDX specVersion %q (want 1.4-1.7)", doc.SpecVersion)
	}
	var pkgs []Package
	seen := map[string]bool{}
	var walk func(cs []cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			if c.PURL != "" {
				if !seen[c.PURL] {
					seen[c.PURL] = true
					pkgs = append(pkgs, Package{Name: c.Name, Version: c.Version, PURL: c.PURL, Ecosystem: EcosystemFromPURL(c.PURL)})
				}
			} else if c.Name != "" && c.Version != "" {
				key := c.Group + "/" + c.Name + "@" + c.Version
				if !seen[key] {
					seen[key] = true
					name := c.Name
					if c.Group != "" {
						name = c.Group + "/" + c.Name
					}
					pkgs = append(pkgs, Package{Name: name, Version: c.Version})
				}
			}
			walk(c.Components)
		}
	}
	walk(doc.Components)
	return pkgs, nil
}

// EcosystemFromPURL maps a purl type to an OSV ecosystem name.
func EcosystemFromPURL(purl string) string {
	rest := strings.TrimPrefix(purl, "pkg:")
	typ, _, _ := strings.Cut(rest, "/")
	switch typ {
	case "npm":
		return "npm"
	case "golang":
		return "Go"
	case "cargo":
		return "crates.io"
	case "nuget":
		return "NuGet"
	case "pypi":
		return "PyPI"
	case "maven":
		return "Maven"
	case "gem":
		return "RubyGems"
	case "composer":
		return "Packagist"
	case "hex":
		return "Hex"
	case "pub":
		return "Pub"
	case "swift":
		return "SwiftURL"
	case "cran":
		return "CRAN"
	case "deb":
		return "Debian"
	case "alpine", "apk":
		return "Alpine"
	}
	return ""
}
