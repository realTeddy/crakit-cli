package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const fixtures = "../../testdata/osv"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newServer serves querybatch from a handler that pages the first result once,
// and /v1/vulns/{id} from fixtures.
func newServer(t *testing.T, calls *int32, batchSizes *[]int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "crakit/test" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		switch {
		case r.URL.Path == "/v1/querybatch" && r.Method == http.MethodPost:
			atomic.AddInt32(calls, 1)
			var body struct {
				Queries []struct {
					Package   map[string]string `json:"package"`
					Version   string            `json:"version"`
					PageToken string            `json:"page_token"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode: %v", err)
			}
			*batchSizes = append(*batchSizes, len(body.Queries))
			results := make([]map[string]any, 0, len(body.Queries))
			for _, q := range body.Queries {
				if q.Package["purl"] != "" && q.Version != "" {
					t.Errorf("query carries both purl and version: %+v", q)
				}
				switch {
				case strings.Contains(q.Package["purl"], "lodash") && q.PageToken == "":
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-lodash-1"}}, "next_page_token": "tok1"})
				case strings.Contains(q.Package["purl"], "lodash") && q.PageToken == "tok1":
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-lodash-2"}}})
				case strings.Contains(q.Package["purl"], "minimist") || q.Package["name"] == "minimist":
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-minimist-1"}}})
				default:
					results = append(results, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			p := filepath.Join(fixtures, id+".json")
			if _, err := os.Stat(p); err != nil {
				http.NotFound(w, r)
				return
			}
			w.Write(fixture(t, id+".json"))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestParseCycloneDX16And14(t *testing.T) {
	for _, f := range []string{"sbom-1.6.cdx.json", "sbom-1.4.cdx.json"} {
		pkgs, err := ParseCycloneDX(strings.NewReader(string(fixture(t, f))))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(pkgs) != 3 {
			t.Fatalf("%s: want 3 packages got %d: %+v", f, len(pkgs), pkgs)
		}
		if pkgs[0].Ecosystem != "npm" || !strings.HasPrefix(pkgs[0].PURL, "pkg:npm/") {
			t.Fatalf("%s: ecosystem inference: %+v", f, pkgs[0])
		}
	}
	// no purl -> name/version used
	pkgs, _ := ParseCycloneDX(strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"minimist","version":"1.2.5"}]}`))
	if len(pkgs) != 1 || pkgs[0].PURL != "" || pkgs[0].Name != "minimist" {
		t.Fatalf("name/version fallback: %+v", pkgs)
	}
	if _, err := ParseCycloneDX(strings.NewReader(`{"bomFormat":"SPDX","specVersion":"1.6"}`)); err == nil {
		t.Fatal("non-CycloneDX accepted")
	}
	if _, err := ParseCycloneDX(strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.2"}`)); err == nil {
		t.Fatal("spec 1.2 accepted")
	}
}

func TestEcosystemFromPURL(t *testing.T) {
	cases := map[string]string{"pkg:npm/a@1": "npm", "pkg:golang/x/y@v1": "Go", "pkg:cargo/s@1": "crates.io", "pkg:nuget/N@1": "NuGet", "pkg:pypi/r@1": "PyPI", "pkg:weird/x@1": ""}
	for in, want := range cases {
		if got := EcosystemFromPURL(in); got != want {
			t.Errorf("%s: want %q got %q", in, want, got)
		}
	}
}

func TestScanWithPaginationAndDetails(t *testing.T) {
	var calls int32
	var sizes []int
	srv := newServer(t, &calls, &sizes)
	defer srv.Close()
	c := New(srv.URL, "test")
	pkgs, _ := ParseCycloneDX(strings.NewReader(string(fixture(t, "sbom-1.6.cdx.json"))))
	findings, err := c.Scan(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("want 3 findings got %d: %+v", len(findings), findings)
	}
	ids := map[string]Finding{}
	for _, f := range findings {
		ids[f.ID] = f
	}
	if _, ok := ids["GHSA-lodash-2"]; !ok {
		t.Fatal("next_page_token not followed")
	}
	l1 := ids["GHSA-lodash-1"]
	if l1.Severity != SevHigh || l1.Summary == "" || len(l1.Aliases) == 0 || l1.Aliases[0] != "CVE-2021-23337" {
		t.Fatalf("lodash-1 finding: %+v", l1)
	}
	if len(l1.FixedIn) != 1 || l1.FixedIn[0] != "4.17.21" {
		t.Fatalf("fixed-in: %v", l1.FixedIn)
	}
	m := ids["GHSA-minimist-1"]
	if m.Severity != SevCritical {
		t.Fatalf("minimist severity from CVSS vector: %s (%s)", m.Severity, m.CVSS)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 querybatch calls (1 + 1 page), got %d", calls)
	}
	// stable ordering
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Component > findings[i].Component {
			t.Fatal("findings not sorted")
		}
	}
}

func TestQueryBatchChunking(t *testing.T) {
	var calls int32
	var sizes []int
	srv := newServer(t, &calls, &sizes)
	defer srv.Close()
	c := New(srv.URL, "test")
	c.ChunkSize = 2
	var pkgs []Package
	for i := 0; i < 5; i++ {
		pkgs = append(pkgs, Package{PURL: "pkg:npm/noop@1.0." + string(rune('0'+i))})
	}
	res, err := c.QueryBatch(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 5 {
		t.Fatalf("results len %d", len(res))
	}
	if len(sizes) != 3 || sizes[0] != 2 || sizes[1] != 2 || sizes[2] != 1 {
		t.Fatalf("chunk sizes: %v", sizes)
	}
}

func TestQueryBatchNameVersionQuery(t *testing.T) {
	var calls int32
	var sizes []int
	srv := newServer(t, &calls, &sizes)
	defer srv.Close()
	c := New(srv.URL, "test")
	res, err := c.QueryBatch(context.Background(), []Package{{Name: "minimist", Version: "1.2.5", Ecosystem: "npm"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res[0]) != 1 || res[0][0] != "GHSA-minimist-1" {
		t.Fatalf("name/version query: %v", res)
	}
}

func TestHTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(srv.URL, "test")
	if _, err := c.QueryBatch(context.Background(), []Package{{PURL: "pkg:npm/a@1"}}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want 500 error, got %v", err)
	}
}

func TestSeverityParsing(t *testing.T) {
	v := &Vuln{}
	v.DatabaseSpecific.Severity = "MODERATE"
	if s, _ := SeverityOf(v); s != SevMedium {
		t.Fatalf("database_specific: %s", s)
	}
	v = &Vuln{Severity: []Score{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}
	if s, vec := SeverityOf(v); s != SevCritical || vec == "" {
		t.Fatalf("cvss critical: %s %s", s, vec)
	}
	v = &Vuln{Severity: []Score{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"}}}
	if s, _ := SeverityOf(v); s != SevLow {
		t.Fatalf("cvss low: %s", s)
	}
	if s, _ := SeverityOf(&Vuln{}); s != SevUnknown {
		t.Fatal("empty should be unknown")
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Fatal("bogus severity accepted")
	}
}

func TestCVSS3BaseScore(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
	}
	for vec, want := range cases {
		got, ok := CVSS3BaseScore(vec)
		if !ok || got != want {
			t.Errorf("%s: want %.1f got %.1f (ok=%v)", vec, want, got, ok)
		}
	}
	if _, ok := CVSS3BaseScore("CVSS:4.0/AV:N"); ok {
		t.Fatal("v4 should not compute")
	}
}

func TestExitCodeThreshold(t *testing.T) {
	fs := []Finding{{Severity: SevLow}, {Severity: SevMedium}, {Severity: SevUnknown}}
	if ExitCode(fs, "") != 0 {
		t.Fatal("none threshold should pass")
	}
	if ExitCode(fs, SevMedium) != 1 || ExitCode(fs, SevLow) != 1 {
		t.Fatal("medium/low threshold should fail")
	}
	if ExitCode(fs, SevHigh) != 0 || ExitCode(fs, SevCritical) != 0 {
		t.Fatal("high/critical threshold should pass")
	}
	if ExitCode(nil, SevLow) != 0 {
		t.Fatal("no findings should pass")
	}
}
