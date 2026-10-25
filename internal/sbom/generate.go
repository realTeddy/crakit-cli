package sbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ToolVersion is set by the cmd package so the metadata.tools entry matches
// the binary version.
var ToolVersion = "dev"

// Lockfile describes a supported lockfile.
type Lockfile struct {
	File      string
	Ecosystem string
	Parse     func(path string) ([]Package, error)
}

// Lockfiles lists supported lockfiles in detection order.
var Lockfiles = []Lockfile{
	{"package-lock.json", "npm", ParseNpmLock},
	{"pnpm-lock.yaml", "npm", ParsePnpmLock},
	{"go.mod", "golang", ParseGoMod},
	{"Cargo.lock", "cargo", ParseCargoLock},
	{"packages.lock.json", "nuget", ParseNuGetLock},
}

// Detect returns the lockfiles present in dir.
func Detect(dir string) []Lockfile {
	var found []Lockfile
	for _, lf := range Lockfiles {
		if st, err := os.Stat(filepath.Join(dir, lf.File)); err == nil && !st.IsDir() {
			found = append(found, lf)
		}
	}
	return found
}

// Options controls generation.
type Options struct {
	Name            string
	Version         string
	IncludeIndirect bool
	// SerialNumber and Timestamp override the generated values (for tests).
	SerialNumber string
	Timestamp    time.Time
}

// Generate builds a CycloneDX BOM from the lockfiles found in dir.
func Generate(dir string, opts Options) (*BOM, error) {
	found := Detect(dir)
	if len(found) == 0 {
		return nil, fmt.Errorf("no supported lockfile found in %s (looked for package-lock.json, pnpm-lock.yaml, go.mod, Cargo.lock, packages.lock.json)", dir)
	}
	var pkgs []Package
	for _, lf := range found {
		ps, err := lf.Parse(filepath.Join(dir, lf.File))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", lf.File, err)
		}
		pkgs = append(pkgs, ps...)
	}
	return Build(dir, pkgs, opts), nil
}

// Build assembles a BOM from parsed packages. Output is deterministic:
// components are sorted by purl and deduplicated.
func Build(dir string, pkgs []Package, opts Options) *BOM {
	name := opts.Name
	if name == "" {
		abs, err := filepath.Abs(dir)
		if err == nil {
			name = filepath.Base(abs)
		} else {
			name = filepath.Base(dir)
		}
	}
	serial := opts.SerialNumber
	if serial == "" {
		serial = "urn:uuid:" + newUUID()
	}
	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	rootRef := "pkg:generic/" + name
	if opts.Version != "" {
		rootRef += "@" + opts.Version
	}
	root := Component{Type: "application", BOMRef: rootRef, Name: name, Version: opts.Version}

	byPurl := map[string]Component{}
	direct := map[string]bool{}
	for _, p := range pkgs {
		if !p.Direct && !opts.IncludeIndirect {
			continue
		}
		purl := p.PURL()
		c := Component{Type: "library", BOMRef: purl, Group: p.Group, Name: p.Name, Version: p.Version, PURL: purl}
		if p.Group != "" {
			c.Group = "@" + p.Group
		}
		byPurl[purl] = c
		if p.Direct {
			direct[purl] = true
		}
	}
	comps := make([]Component, 0, len(byPurl))
	for _, c := range byPurl {
		comps = append(comps, c)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	deps := make([]string, 0, len(direct))
	for p := range direct {
		deps = append(deps, p)
	}
	sort.Strings(deps)

	return &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: serial,
		Version:      1,
		Metadata: &Metadata{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Tools:     &Tools{Components: []Component{{Type: "application", Name: "crakit", Version: ToolVersion}}},
			Component: &root,
		},
		Components:   comps,
		Dependencies: []Dependency{{Ref: rootRef, DependsOn: deps}},
	}
}

// JSON renders the BOM as indented JSON.
func (b *BOM) JSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

func newUUID() string {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		panic(err)
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
