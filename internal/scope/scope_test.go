package scope

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/realTeddy/crakit-cli/internal/cra"
)

func base() Input {
	return Input{
		ProductType:    TypeSoftware,
		Connected:      Yes,
		Commercial:     Yes,
		OpenSource:     No,
		ExcludedSector: SectorNone,
		Category:       "none",
		Role:           RoleManufacturer,
	}
}

func hasCitation(rs []Reason, cite string) bool {
	for _, r := range rs {
		if strings.Contains(r.Citation, cite) {
			return true
		}
	}
	return false
}

func TestOutOfScopeExcludedSector(t *testing.T) {
	for _, s := range []string{SectorMedical, SectorAutomotive, SectorAviation, SectorMarine, SectorDefence} {
		in := base()
		in.ExcludedSector = s
		v := Evaluate(in)
		if v.InScope != StatusOut {
			t.Errorf("%s: want out, got %s", s, v.InScope)
		}
		if !hasCitation(v.Reasons, "Art. 2(2)-(7)") {
			t.Errorf("%s: missing Art. 2(2)-(7) citation", s)
		}
		if len(v.Obligations) != 0 {
			t.Errorf("%s: out-of-scope should have no obligations", s)
		}
	}
}

func TestOutOfScopeSaaS(t *testing.T) {
	in := base()
	in.ProductType = TypeSaaS
	in.RemoteProcessingEssential = No
	v := Evaluate(in)
	if v.InScope != StatusOut {
		t.Fatalf("want out, got %s", v.InScope)
	}
	if !hasCitation(v.Reasons, "Recital 12") || !hasCitation(v.Reasons, "Art. 3(2)") {
		t.Fatalf("missing SaaS citations: %+v", v.Reasons)
	}
}

func TestSaaSEssentialRemoteProcessingInScope(t *testing.T) {
	in := base()
	in.ProductType = TypeSaaS
	in.RemoteProcessingEssential = Yes
	v := Evaluate(in)
	if v.InScope != StatusLikely {
		t.Fatalf("want likely, got %s", v.InScope)
	}
	if !hasCitation(v.Reasons, "Art. 3(2)") {
		t.Fatal("missing Art. 3(2)")
	}
}

func TestOutOfScopeNonCommercialOSS(t *testing.T) {
	in := base()
	in.OpenSource = Yes
	in.OSSMonetised = No
	in.Commercial = No
	v := Evaluate(in)
	if v.InScope != StatusOut {
		t.Fatalf("want out, got %s", v.InScope)
	}
	if !hasCitation(v.Reasons, "Recitals 18-19") || !hasCitation(v.Reasons, "Art. 24") {
		t.Fatalf("missing OSS citations: %+v", v.Reasons)
	}
}

func TestMonetisedOSSInScope(t *testing.T) {
	in := base()
	in.OpenSource = Yes
	in.OSSMonetised = Yes
	in.Commercial = No
	v := Evaluate(in)
	if v.InScope != StatusLikely {
		t.Fatalf("want likely, got %s", v.InScope)
	}
}

func TestOutOfScopeNotConnected(t *testing.T) {
	in := base()
	in.Connected = No
	v := Evaluate(in)
	if v.InScope != StatusOut {
		t.Fatalf("want out, got %s", v.InScope)
	}
	if !hasCitation(v.Reasons, "Art. 2(1)") {
		t.Fatal("missing Art. 2(1)")
	}
}

func TestClassFromCategory(t *testing.T) {
	cases := []struct {
		cat  string
		want cra.Class
	}{
		{"none", cra.ClassDefault},
		{"operating-system", cra.ClassImportantI},
		{"password-manager", cra.ClassImportantI},
		{"firewall-ids-ips", cra.ClassImportantII},
		{"hypervisor-container-runtime", cra.ClassImportantII},
		{"smartcard-secure-element", cra.ClassCritical},
		{"smart-meter-gateway", cra.ClassCritical},
	}
	for _, c := range cases {
		in := base()
		in.Category = c.cat
		v := Evaluate(in)
		if v.Class != c.want {
			t.Errorf("%s: want %s got %s", c.cat, c.want, v.Class)
		}
		if v.InScope != StatusLikely {
			t.Errorf("%s: want likely", c.cat)
		}
	}
}

func TestConformityRoutePerClass(t *testing.T) {
	cases := []struct {
		class cra.Class
		want  string
		cite  string
	}{
		{cra.ClassDefault, "Module A", "Art. 32(1)"},
		{cra.ClassImportantI, "Modules B+C", "Art. 32(2)"},
		{cra.ClassImportantII, "notified body", "Art. 32(3)"},
		{cra.ClassCritical, "certification scheme", "Art. 32(4)"},
	}
	for _, c := range cases {
		route, cite := ConformityRoute(c.class)
		if !strings.Contains(route, c.want) {
			t.Errorf("%s: route %q lacks %q", c.class, route, c.want)
		}
		if !strings.Contains(cite, c.cite) {
			t.Errorf("%s: citation %q lacks %q", c.class, cite, c.cite)
		}
	}
}

func TestObligationsIncludeArt14AndDates(t *testing.T) {
	v := Evaluate(base())
	var sawReporting, sawVuln, sawDoC, sawCE, sawSupport, sawTechDoc bool
	for _, o := range v.Obligations {
		if strings.HasPrefix(o.Citation, "Art. 14") && o.Deadline == "2026-09-11" {
			sawReporting = true
		}
		if strings.Contains(o.Citation, "Annex I Part II") && o.Deadline == "2027-12-11" && strings.Contains(o.Text, "SBOM") {
			sawVuln = true
		}
		if strings.Contains(o.Citation, "Art. 28") && strings.Contains(o.Citation, "Annex V") {
			sawDoC = true
		}
		if o.Citation == "Art. 30" {
			sawCE = true
		}
		if strings.Contains(o.Citation, "Art. 13(8)") {
			sawSupport = true
		}
		if strings.Contains(o.Citation, "Annex VII") {
			sawTechDoc = true
		}
		if o.Deadline == "" {
			t.Errorf("obligation without deadline: %s", o.Citation)
		}
	}
	if !sawReporting || !sawVuln || !sawDoC || !sawCE || !sawSupport || !sawTechDoc {
		t.Fatalf("missing obligations: reporting=%v vuln=%v doc=%v ce=%v support=%v techdoc=%v", sawReporting, sawVuln, sawDoC, sawCE, sawSupport, sawTechDoc)
	}
}

func TestImportantClassGetsNotifiedBodyDate(t *testing.T) {
	in := base()
	in.Category = "firewall-ids-ips"
	v := Evaluate(in)
	found := false
	for _, o := range v.Obligations {
		if o.Deadline == cra.NotifiedBodiesApply {
			found = true
		}
	}
	if !found {
		t.Fatal("Class II should list the 2026-06-11 notified body date")
	}
}

func TestRoleReasons(t *testing.T) {
	for role, cite := range map[string]string{RoleImporter: "Art. 19", RoleDistributor: "Art. 20", RoleModifier: "Art. 22"} {
		in := base()
		in.Role = role
		v := Evaluate(in)
		if !hasCitation(v.Reasons, cite) {
			t.Errorf("%s: missing %s", role, cite)
		}
		if v.Role != role {
			t.Errorf("role not echoed")
		}
	}
}

func TestVerdictJSONRoundTrip(t *testing.T) {
	in := base()
	in.Category = "router-modem-switch"
	v := Evaluate(in)
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var back Verdict
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.InScope != v.InScope || back.Class != v.Class || len(back.Obligations) != len(v.Obligations) || back.Disclaimer != cra.Disclaimer {
		t.Fatalf("round trip mismatch")
	}
	if back.Input != in {
		t.Fatalf("input not preserved")
	}
}

func TestTextOutputHasDisclaimer(t *testing.T) {
	out := Evaluate(base()).Text()
	if !strings.Contains(out, cra.Disclaimer) || !strings.Contains(out, "LIKELY IN SCOPE") {
		t.Fatalf("text output missing disclaimer or verdict:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "you are compliant") {
		t.Fatal("must never claim compliance")
	}
}

func TestMissingFlags(t *testing.T) {
	m := Input{}.Missing()
	for _, want := range []string{"product-type", "connected", "commercial", "open-source", "excluded-sector", "category", "role"} {
		found := false
		for _, g := range m {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing list lacks %s: %v", want, m)
		}
	}
	in := base()
	if len(in.Missing()) != 0 {
		t.Fatalf("complete input reported missing: %v", in.Missing())
	}
	in.OpenSource = Yes
	if m := in.Missing(); len(m) != 1 || m[0] != "oss-monetised" {
		t.Fatalf("expected oss-monetised, got %v", m)
	}
	in = base()
	in.ProductType = TypeSaaS
	if m := in.Missing(); len(m) != 1 || m[0] != "remote-processing-essential" {
		t.Fatalf("expected remote-processing-essential, got %v", m)
	}
	in = base()
	in.Category = "bogus"
	if m := in.Missing(); len(m) != 1 || m[0] != "category" {
		t.Fatalf("expected category invalid, got %v", m)
	}
	in = base()
	in.PlacedAfter = "2027-12-11"
	if len(in.Missing()) != 0 {
		t.Fatal("valid placed-after rejected")
	}
}

func TestInteractiveQuestionnaire(t *testing.T) {
	// software, connected yes, commercial yes, open-source no, sector none, category none(1), role manufacturer
	answers := "1\n1\n1\n2\n1\n1\n1\n"
	var out strings.Builder
	in, err := Interactive(Input{}, strings.NewReader(answers), &out)
	if err != nil {
		t.Fatal(err)
	}
	if in.ProductType != TypeSoftware || in.Connected != Yes || in.OpenSource != No || in.Role != RoleManufacturer || in.Category != "none" {
		t.Fatalf("unexpected answers: %+v", in)
	}
	if len(in.Missing()) != 0 {
		t.Fatalf("still missing: %v", in.Missing())
	}
	if !strings.Contains(out.String(), "Art. 2(1)") {
		t.Fatal("prompts should cite articles")
	}
	// Pre-filled fields are not asked; invalid input re-prompts; EOF errors.
	_, err = Interactive(base(), strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("fully pre-filled should not read: %v", err)
	}
	_, err = Interactive(Input{}, strings.NewReader("zzz\n"), &out)
	if err == nil {
		t.Fatal("expected EOF error")
	}
}
