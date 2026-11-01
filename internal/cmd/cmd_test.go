package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/realTeddy/crakit-cli/internal/cra"
)

func run(t *testing.T, env map[string]string, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(args, Env{
		Stdin:  strings.NewReader(stdin),
		Stdout: &out,
		Stderr: &errb,
		Getenv: func(k string) string { return env[k] },
	})
	return code, out.String(), errb.String()
}

func TestHelpListsCommandsAndDisclaimer(t *testing.T) {
	code, out, _ := run(t, nil, "", "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, c := range []string{"scope", "sbom", "vulns", "policy", "incident", "version", cra.Disclaimer} {
		if !strings.Contains(out, c) {
			t.Errorf("help missing %q", c)
		}
	}
	code, _, errOut := run(t, nil, "", "bogus")
	if code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("unknown command: %d %s", code, errOut)
	}
	code, out, _ = run(t, nil, "", "version")
	if code != 0 || !strings.Contains(out, "crakit "+Version) {
		t.Fatalf("version: %d %s", code, out)
	}
}

func TestScopeFlagsAndJSON(t *testing.T) {
	code, out, _ := run(t, nil, "", "scope", "--product-type", "firmware", "--connected", "yes", "--commercial", "yes", "--open-source", "no", "--excluded-sector", "none", "--category", "router-modem-switch", "--role", "manufacturer", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v["in_scope"] != "likely" || v["class"] != "important-I" || v["disclaimer"] != cra.Disclaimer {
		t.Fatalf("verdict: %v", v)
	}
	code, out, _ = run(t, nil, "", "scope", "--product-type", "software", "--connected", "no", "--commercial", "yes", "--open-source", "no", "--excluded-sector", "none", "--category", "none", "--role", "manufacturer")
	if code != 0 || !strings.Contains(out, "OUT OF SCOPE") || !strings.Contains(out, "Art. 2(1)") {
		t.Fatalf("text verdict: %d %s", code, out)
	}
}

func TestScopeMissingFlagsNonInteractive(t *testing.T) {
	code, _, errOut := run(t, nil, "", "scope", "--product-type", "software")
	if code != 1 || !strings.Contains(errOut, "--connected") || !strings.Contains(errOut, "--role") {
		t.Fatalf("missing flags: %d %s", code, errOut)
	}
}

func TestScopeInteractiveWhenTerminal(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"scope", "--role", "manufacturer"}, Env{
		Stdin:           strings.NewReader("1\n1\n1\n2\n1\n1\n"),
		Stdout:          &out,
		Stderr:          &errb,
		StdinIsTerminal: true,
	})
	if code != 0 || !strings.Contains(out.String(), "LIKELY IN SCOPE") {
		t.Fatalf("interactive: %d\n%s\n%s", code, out.String(), errb.String())
	}
}

func TestScopeListCategories(t *testing.T) {
	code, out, _ := run(t, nil, "", "scope", "--list-categories")
	if code != 0 || !strings.Contains(out, "operating-system") || !strings.Contains(out, "Annex IV") {
		t.Fatalf("list: %d %s", code, out)
	}
}

func TestSBOMCommandBuiltin(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	outFile := filepath.Join(dir, "bom.cdx.json")
	code, _, errOut := run(t, nil, "", "sbom", "../../testdata/npm", "--tool", "auto", "--name", "demo", "--version", "2.0", "-o", outFile)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["specVersion"] != "1.6" || !regexp.MustCompile(`^urn:uuid:[0-9a-f-]{36}$`).MatchString(m["serialNumber"].(string)) {
		t.Fatalf("bom header: %v", m)
	}
	if !strings.Contains(string(data), "pkg:npm/%40scope/pkg@2.1.0") {
		t.Fatal("scoped purl missing")
	}
	code, out, _ := run(t, nil, "", "sbom", "../../testdata/gomod")
	if code != 0 || !strings.Contains(out, "pkg:golang/github.com/foo/bar@v1.2.3") {
		t.Fatalf("stdout sbom: %d %s", code, out)
	}
	if code, _, _ := run(t, nil, "", "sbom", t.TempDir()); code != 1 {
		t.Fatal("empty dir should fail")
	}
	if code, _, _ := run(t, nil, "", "sbom", "--tool", "syft", "../../testdata/gomod"); code != 1 {
		t.Fatal("explicit missing tool should fail")
	}
}

func TestVulnsCommandAgainstHTTPTest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var body struct {
				Queries []struct {
					Package map[string]string `json:"package"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			results := []map[string]any{}
			for _, q := range body.Queries {
				if strings.Contains(q.Package["purl"], "lodash") {
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-lodash-1"}}})
				} else {
					results = append(results, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.URL.Path == "/v1/vulns/GHSA-lodash-1":
			data, _ := os.ReadFile("../../testdata/osv/GHSA-lodash-1.json")
			w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	env := map[string]string{"CRAKIT_OSV_URL": srv.URL}
	code, out, errOut := run(t, env, "", "vulns", "../../testdata/osv/sbom-1.6.cdx.json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"GHSA-lodash-1", "CVE-2021-23337", "high", "4.17.21", "Art. 14(1)", cra.Disclaimer} {
		if !strings.Contains(out, want) {
			t.Errorf("vulns output missing %q:\n%s", want, out)
		}
	}
	code, _, _ = run(t, env, "", "vulns", "--fail-on", "high", "../../testdata/osv/sbom-1.6.cdx.json")
	if code != 1 {
		t.Fatalf("--fail-on high should exit 1, got %d", code)
	}
	code, _, _ = run(t, env, "", "vulns", "--fail-on", "critical", "../../testdata/osv/sbom-1.6.cdx.json")
	if code != 0 {
		t.Fatalf("--fail-on critical should exit 0, got %d", code)
	}
	code, out, _ = run(t, nil, "", "vulns", "--osv-url", srv.URL, "--json", "../../testdata/osv/sbom-1.4.cdx.json")
	if code != 0 || !strings.Contains(out, `"id": "GHSA-lodash-1"`) {
		t.Fatalf("json: %d %s", code, out)
	}
	if code, _, _ := run(t, env, "", "vulns", "--fail-on", "bogus", "x.json"); code != 1 {
		t.Fatal("bogus fail-on accepted")
	}
	if code, _, _ := run(t, env, "", "vulns"); code != 1 {
		t.Fatal("missing arg accepted")
	}
}

func TestPolicyCommand(t *testing.T) {
	code, out, _ := run(t, nil, "", "policy", "--org", "Acme", "--contact", "mailto:sec@acme.example", "--contact", "https://acme.example/report", "--expires", "2027-01-01T00:00:00Z")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"# Coordinated Vulnerability Disclosure Policy - Acme", "Contact: mailto:sec@acme.example", "Expires: 2027-01-01T00:00:00.000Z", "Annex I Part II (5)", cra.Disclaimer} {
		if !strings.Contains(out, want) {
			t.Errorf("policy output missing %q", want)
		}
	}
	dir := t.TempDir()
	code, _, _ = run(t, nil, "", "policy", "--org", "Acme", "--contact", "mailto:sec@acme.example", "--out-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, f := range []string{"SECURITY.md", filepath.Join(".well-known", "security.txt")} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not written", f)
		}
	}
	if code, _, errOut := run(t, nil, "", "policy", "--org", "Acme"); code != 1 || !strings.Contains(errOut, "contact") {
		t.Fatalf("no contact: %d %s", code, errOut)
	}
	if code, _, _ := run(t, nil, "", "policy", "--contact", "mailto:a@b", "--expires", "tomorrow"); code != 1 {
		t.Fatal("bad expires accepted")
	}
}

func TestIncidentLifecycle(t *testing.T) {
	store := filepath.Join(t.TempDir(), "inc.json")
	env := map[string]string{"CRAKIT_STORE": store}
	code, out, errOut := run(t, env, "", "incident", "new", "--kind", "vulnerability", "--product", "Widget", "--version", "1.2", "--title", "RCE", "--aware-at", "2026-10-01T10:00:00Z")
	if code != 0 {
		t.Fatalf("new: %d %s", code, errOut)
	}
	m := regexp.MustCompile(`created incident ([0-9a-f]{8})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no id in output: %s", out)
	}
	id := m[1]

	code, out, _ = run(t, env, "", "incident", "status", id, "--now", "2026-10-02T12:00:00Z")
	if code != 0 || !strings.Contains(out, "overdue by 2h") || !strings.Contains(out, "Art. 14(8)") || !strings.Contains(out, "not yet determinable") {
		t.Fatalf("status: %d\n%s", code, out)
	}

	code, out, _ = run(t, env, "", "incident", "update", id, "--mark", "early_warning", "--at", "2026-10-01T20:00:00Z", "--fix-available-at", "2026-10-05T00:00:00Z", "--note", "patch shipped")
	if code != 0 || !strings.Contains(out, "submitted") {
		t.Fatalf("update: %d\n%s", code, out)
	}
	code, out, _ = run(t, env, "", "incident", "status", id, "--now", "2026-10-02T12:00:00Z")
	if !strings.Contains(out, "2026-10-19 00:00 UTC") {
		t.Fatalf("final report deadline not computed from fix date:\n%s", out)
	}

	code, out, _ = run(t, env, "", "incident", "draft", id, "--stage", "final_report")
	if code != 0 || !strings.Contains(out, "Art. 14(2)(c)") || !strings.Contains(out, "2026-10-05 00:00 UTC") || !strings.Contains(out, "Single Reporting Platform") || !strings.Contains(out, "patch shipped") {
		t.Fatalf("draft: %d\n%s", code, out)
	}

	code, out, _ = run(t, env, "", "incident", "new", "--kind", "incident", "--product", "Widget", "--title", "Breach", "--aware-at", "2026-10-10T00:00:00Z")
	if code != 0 {
		t.Fatal("second new failed")
	}
	code, out, _ = run(t, env, "", "incident", "list", "--now", "2026-10-10T01:00:00Z")
	if code != 0 || !strings.Contains(out, "RCE") || !strings.Contains(out, "Breach") {
		t.Fatalf("list: %d\n%s", code, out)
	}
	code, out, _ = run(t, env, "", "incident", "status", "--now", "2026-10-10T01:00:00Z")
	if code != 0 || strings.Count(out, "Incident ") != 2 {
		t.Fatalf("status all: %d\n%s", code, out)
	}

	// --store flag overrides env; errors
	code, _, _ = run(t, env, "", "incident", "update", id, "--store", filepath.Join(t.TempDir(), "other.json"), "--note", "x")
	if code != 1 {
		t.Fatal("update in empty store should fail")
	}
	if code, _, _ := run(t, env, "", "incident", "update", id); code != 1 {
		t.Fatal("no-op update should fail")
	}
	if code, _, _ := run(t, env, "", "incident", "update", id, "--status", "weird"); code != 1 {
		t.Fatal("bad status accepted")
	}
	if code, _, _ := run(t, env, "", "incident", "new", "--kind", "nope", "--product", "x"); code != 1 {
		t.Fatal("bad kind accepted")
	}
	if code, _, _ := run(t, env, "", "incident", "draft", id, "--stage", "nope"); code != 1 {
		t.Fatal("bad stage accepted")
	}
	if code, _, _ := run(t, env, "", "incident", "bogus"); code != 1 {
		t.Fatal("bad subcommand accepted")
	}
	if code, out, _ := run(t, env, "", "incident"); code != 0 || !strings.Contains(out, "Usage") {
		t.Fatal("incident help")
	}
	if code, _, _ := run(t, env, "", "incident", "update", id, "--status", "closed"); code != 0 {
		t.Fatal("close failed")
	}
}
