// Package sbom generates CycloneDX 1.6 software bills of materials from
// common lockfiles, or passes through the output of syft/cdxgen when
// available. An SBOM covering at least the top-level dependencies is part of
// the vulnerability handling requirements (Annex I Part II (1) of Regulation
// (EU) 2024/2847) and of the technical documentation (Annex VII (2)(b)).
package sbom

// SpecVersion is the CycloneDX specification version produced.
const SpecVersion = "1.6"

// BOM is a minimal CycloneDX JSON document.
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     *Metadata    `json:"metadata,omitempty"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Metadata is CycloneDX metadata.
type Metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     *Tools     `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

// Tools is the CycloneDX 1.5+ tools object.
type Tools struct {
	Components []Component `json:"components"`
}

// Component is a CycloneDX component.
type Component struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Group   string `json:"group,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// Dependency is a CycloneDX dependency graph entry.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// Package is an ecosystem-neutral parsed package.
type Package struct {
	Ecosystem string // npm, golang, cargo, nuget
	Group     string // npm scope without '@', if any
	Name      string
	Version   string
	Direct    bool
}

// PURL returns the package-url for the package.
func (p Package) PURL() string {
	switch p.Ecosystem {
	case "npm":
		if p.Group != "" {
			return "pkg:npm/%40" + p.Group + "/" + p.Name + "@" + p.Version
		}
		return "pkg:npm/" + p.Name + "@" + p.Version
	case "golang":
		return "pkg:golang/" + p.Name + "@" + p.Version
	case "cargo":
		return "pkg:cargo/" + p.Name + "@" + p.Version
	case "nuget":
		return "pkg:nuget/" + p.Name + "@" + p.Version
	}
	return "pkg:generic/" + p.Name + "@" + p.Version
}
