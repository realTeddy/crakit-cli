package sbom

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtures = "../../testdata"

func purls(b *BOM) []string {
	var out []string
	for _, c := range b.Components {
		out = append(out, c.PURL)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestNpmLockV3ScopedPurl(t *testing.T) {
	b, err := Generate(filepath.Join(fixtures, "npm"), Options{IncludeIndirect: true})
	if err != nil {
		t.Fatal(err)
	}
	ps := purls(b)
	if !contains(ps, "pkg:npm/%40scope/pkg@2.1.0") {
		t.Fatalf("scoped purl not percent-encoded: %v", ps)
	}
	if !contains(ps, "pkg:npm/lodash@4.17.21") || !contains(ps, "pkg:npm/ms@2.1.3") || !contains(ps, "pkg:npm/typescript@5.4.5") {
		t.Fatalf("missing purls: %v", ps)
	}
	if len(b.Components) != 4 {
		t.Fatalf("want 4 components got %d", len(b.Components))
	}
	for _, c := range b.Components {
		if c.Name == "pkg" && c.Group != "@scope" {
			t.Fatalf("scoped group should be @scope, got %q", c.Group)
		}
	}
	// Direct only by default.
	b2, _ := Generate(filepath.Join(fixtures, "npm"), Options{})
	if len(b2.Components) != 2 {
		t.Fatalf("direct-only want 2 got %d: %v", len(b2.Components), purls(b2))
	}
	if len(b2.Dependencies) != 1 || len(b2.Dependencies[0].DependsOn) != 2 {
		t.Fatalf("dependencies block wrong: %+v", b2.Dependencies)
	}
	if b2.Dependencies[0].Ref != b2.Metadata.Component.BOMRef {
		t.Fatal("dependencies ref must be the root bom-ref")
	}
}

func TestNpmLockV1Fallback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":1,"dependencies":{"left-pad":{"version":"1.3.0"},"@types/node":{"version":"20.0.0"}}}`), 0o644)
	pkgs, err := ParseNpmLock(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 got %d", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Name == "node" && (p.Group != "types" || p.PURL() != "pkg:npm/%40types/node@20.0.0") {
			t.Fatalf("bad scoped v1 package: %+v", p)
		}
	}
}

func TestPnpmLockV9(t *testing.T) {
	pkgs, err := ParsePnpmLock(filepath.Join(fixtures, "pnpm", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("want 4 got %d: %+v", len(pkgs), pkgs)
	}
	direct := map[string]bool{}
	for _, p := range pkgs {
		direct[p.PURL()] = p.Direct
	}
	if !direct["pkg:npm/%40scope/pkg@2.1.0"] || !direct["pkg:npm/lodash@4.17.21"] || !direct["pkg:npm/typescript@5.4.5"] {
		t.Fatalf("direct flags wrong: %v", direct)
	}
	if direct["pkg:npm/ms@2.1.3"] {
		t.Fatal("ms should be indirect")
	}
}

func TestPnpmLockV6Format(t *testing.T) {
	dir := t.TempDir()
	content := "lockfileVersion: '6.0'\n\ndependencies:\n  react:\n    specifier: ^18.2.0\n    version: 18.2.0\n\npackages:\n\n  /react@18.2.0:\n    resolution: {integrity: sha512-x}\n\n  /loose-envify@1.4.0:\n    resolution: {integrity: sha512-y}\n"
	os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(content), 0o644)
	pkgs, err := ParsePnpmLock(filepath.Join(dir, "pnpm-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 got %d: %+v", len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		if p.Name == "react" && !p.Direct {
			t.Fatal("react should be direct")
		}
		if p.Name == "loose-envify" && p.Direct {
			t.Fatal("loose-envify should be indirect")
		}
	}
}

func TestGoMod(t *testing.T) {
	pkgs, err := ParseGoMod(filepath.Join(fixtures, "gomod", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("want 4 got %d", len(pkgs))
	}
	b := Build("x", pkgs, Options{})
	ps := purls(b)
	if len(ps) != 3 || !contains(ps, "pkg:golang/github.com/foo/bar@v1.2.3") || !contains(ps, "pkg:golang/github.com/baz/qux@v0.1.0") {
		t.Fatalf("direct purls wrong: %v", ps)
	}
	b = Build("x", pkgs, Options{IncludeIndirect: true})
	if !contains(purls(b), "pkg:golang/github.com/indirect/dep@v2.0.0+incompatible") {
		t.Fatalf("indirect missing with --include-indirect: %v", purls(b))
	}
	if len(b.Dependencies[0].DependsOn) != 3 {
		t.Fatalf("dependsOn should list only direct deps: %v", b.Dependencies[0].DependsOn)
	}
}

func TestCargoLock(t *testing.T) {
	pkgs, err := ParseCargoLock(filepath.Join(fixtures, "cargo", "Cargo.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("want 3 (workspace crate skipped) got %d: %+v", len(pkgs), pkgs)
	}
	b := Build("x", pkgs, Options{IncludeIndirect: true})
	ps := purls(b)
	if !contains(ps, "pkg:cargo/serde@1.0.197") || !contains(ps, "pkg:cargo/tokio@1.36.0") || !contains(ps, "pkg:cargo/serde_derive@1.0.197") {
		t.Fatalf("purls: %v", ps)
	}
	d := b.Dependencies[0].DependsOn
	if len(d) != 2 || contains(d, "pkg:cargo/serde_derive@1.0.197") {
		t.Fatalf("direct deps wrong: %v", d)
	}
}

func TestNuGetLock(t *testing.T) {
	pkgs, err := ParseNuGetLock(filepath.Join(fixtures, "nuget", "packages.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("want 3 got %d: %+v", len(pkgs), pkgs)
	}
	b := Build("x", pkgs, Options{})
	ps := purls(b)
	if len(ps) != 2 || !contains(ps, "pkg:nuget/Newtonsoft.Json@13.0.3") || !contains(ps, "pkg:nuget/Serilog@3.1.1") {
		t.Fatalf("purls: %v", ps)
	}
}

func TestDeterminismAndSpecVersion(t *testing.T) {
	opts := Options{Name: "demo", Version: "1.0.0", IncludeIndirect: true, SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000", Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	b1, err := Generate(filepath.Join(fixtures, "npm"), opts)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := Generate(filepath.Join(fixtures, "npm"), opts)
	j1, _ := b1.JSON()
	j2, _ := b2.JSON()
	if !bytes.Equal(j1, j2) {
		t.Fatal("two runs differ")
	}
	var m map[string]any
	if err := json.Unmarshal(j1, &m); err != nil {
		t.Fatal(err)
	}
	if m["specVersion"] != "1.6" || m["bomFormat"] != "CycloneDX" || m["serialNumber"] != opts.SerialNumber {
		t.Fatalf("header wrong: %v", m)
	}
	md := m["metadata"].(map[string]any)
	if md["timestamp"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("timestamp: %v", md["timestamp"])
	}
	tools := md["tools"].(map[string]any)["components"].([]any)[0].(map[string]any)
	if tools["name"] != "crakit" {
		t.Fatal("tools.components[0].name should be crakit")
	}
	root := md["component"].(map[string]any)
	if root["name"] != "demo" || root["version"] != "1.0.0" || root["type"] != "application" {
		t.Fatalf("root: %v", root)
	}
	// Sorted by purl.
	for i := 1; i < len(b1.Components); i++ {
		if b1.Components[i-1].PURL > b1.Components[i].PURL {
			t.Fatal("components not sorted by purl")
		}
	}
	// Without overrides, serial is a urn:uuid and timestamp is set.
	b3, _ := Generate(filepath.Join(fixtures, "npm"), Options{})
	if !strings.HasPrefix(b3.SerialNumber, "urn:uuid:") || len(b3.SerialNumber) != len("urn:uuid:")+36 || b3.Metadata.Timestamp == "" {
		t.Fatalf("serial/timestamp: %s %s", b3.SerialNumber, b3.Metadata.Timestamp)
	}
}

func TestDefaultNameIsDirName(t *testing.T) {
	b, err := Generate(filepath.Join(fixtures, "gomod"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Metadata.Component.Name != "gomod" {
		t.Fatalf("name: %s", b.Metadata.Component.Name)
	}
}

func TestNoLockfileError(t *testing.T) {
	if _, err := Generate(t.TempDir(), Options{}); err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestToolDetectionFallsBackToBuiltin(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	tool, err := DetectTool(ToolAuto)
	if err != nil || tool != ToolBuiltin {
		t.Fatalf("auto with empty PATH: %s %v", tool, err)
	}
	if _, err := DetectTool(ToolSyft); err == nil {
		t.Fatal("explicit syft should error when missing")
	}
	if tool, _ := DetectTool(ToolBuiltin); tool != ToolBuiltin {
		t.Fatal("builtin")
	}
	if _, err := DetectTool("bogus"); err == nil {
		t.Fatal("bogus tool accepted")
	}
}

func TestToolDetectionPrefersSyft(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"syft", "cdxgen"} {
		os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\n"), 0o755)
	}
	t.Setenv("PATH", dir)
	if tool, _ := DetectTool(ToolAuto); tool != ToolSyft {
		t.Fatalf("want syft got %s", tool)
	}
	os.Remove(filepath.Join(dir, "syft"))
	if tool, _ := DetectTool(ToolAuto); tool != ToolCdxgen {
		t.Fatalf("want cdxgen got %s", tool)
	}
}

func TestRunExternalWithFakeSyft(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho '{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[]}'\n"
	os.WriteFile(filepath.Join(dir, "syft"), []byte(script), 0o755)
	t.Setenv("PATH", dir)
	out, err := RunExternal(ToolSyft, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "CycloneDX") {
		t.Fatalf("passthrough output: %s", out)
	}
}
