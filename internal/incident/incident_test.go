package incident

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/realTeddy/crakit/cli/internal/cra"
)

var aware = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func byStage(ds []Deadline) map[Stage]Deadline {
	m := map[Stage]Deadline{}
	for _, d := range ds {
		m[d.Stage] = d
	}
	return m
}

func TestNewValidation(t *testing.T) {
	if _, err := New("bogus", "p", "1", "t", aware); err == nil {
		t.Fatal("bad kind accepted")
	}
	if _, err := New(KindIncident, "", "1", "t", aware); err == nil {
		t.Fatal("empty product accepted")
	}
	in, err := New(KindVulnerability, "Widget", "1.2", "RCE", aware)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.ID) != 8 || in.Status != StatusOpen || in.AwareAt.Location() != time.UTC {
		t.Fatalf("new incident: %+v", in)
	}
}

func TestVulnerabilityDeadlineMath(t *testing.T) {
	in, _ := New(KindVulnerability, "Widget", "1.2", "RCE", aware)
	ds := byStage(in.Deadlines(aware))
	if ds[StageEarlyWarning].Due == nil || !ds[StageEarlyWarning].Due.Equal(aware.Add(24*time.Hour)) {
		t.Fatalf("early warning: %+v", ds[StageEarlyWarning])
	}
	if ds[StageEarlyWarning].Citation != "Art. 14(2)(a)" {
		t.Fatalf("citation: %s", ds[StageEarlyWarning].Citation)
	}
	if !ds[StageNotification].Due.Equal(aware.Add(72*time.Hour)) || ds[StageNotification].Citation != "Art. 14(2)(b)" {
		t.Fatalf("notification: %+v", ds[StageNotification])
	}
	fr := ds[StageFinalReport]
	if fr.Due != nil || fr.State != StateNotYet || fr.Citation != "Art. 14(2)(c)" {
		t.Fatalf("final report before fix should be nil/not-yet: %+v", fr)
	}
	fix := aware.Add(5 * 24 * time.Hour)
	in.FixAvailableAt = &fix
	fr = byStage(in.Deadlines(aware))[StageFinalReport]
	if fr.Due == nil || !fr.Due.Equal(fix.AddDate(0, 0, 14)) || fr.State != StatePending {
		t.Fatalf("final report after fix: %+v", fr)
	}
}

func TestIncidentDeadlineMath(t *testing.T) {
	in, _ := New(KindIncident, "Widget", "1.2", "Breach", aware)
	ds := byStage(in.Deadlines(aware))
	if !ds[StageEarlyWarning].Due.Equal(aware.Add(24*time.Hour)) || ds[StageEarlyWarning].Citation != "Art. 14(4)(a)" {
		t.Fatalf("early warning: %+v", ds[StageEarlyWarning])
	}
	if !ds[StageNotification].Due.Equal(aware.Add(72*time.Hour)) || ds[StageNotification].Citation != "Art. 14(4)(b)" {
		t.Fatalf("notification: %+v", ds[StageNotification])
	}
	fr := ds[StageFinalReport]
	if !fr.Projected || !fr.Due.Equal(aware.Add(72*time.Hour).AddDate(0, 1, 0)) || fr.Citation != "Art. 14(4)(c)" {
		t.Fatalf("projected final: %+v", fr)
	}
	// Mark notification at a specific time -> final report is 1 month after it.
	sub := aware.Add(50 * time.Hour)
	if err := in.Mark(StageNotification, sub); err != nil {
		t.Fatal(err)
	}
	fr = byStage(in.Deadlines(aware))[StageFinalReport]
	if fr.Projected || !fr.Due.Equal(sub.AddDate(0, 1, 0)) {
		t.Fatalf("final after mark: %+v", fr)
	}
	if in.Status != StatusReported {
		t.Fatalf("status should move to reported, got %s", in.Status)
	}
}

func TestOverdueVsPending(t *testing.T) {
	in, _ := New(KindVulnerability, "Widget", "1.2", "RCE", aware)
	now := aware.Add(30 * time.Hour)
	ds := byStage(in.Deadlines(now))
	if ds[StageEarlyWarning].State != StateOverdue || !strings.Contains(ds[StageEarlyWarning].Remaining, "overdue by 6h") {
		t.Fatalf("early warning should be overdue: %+v", ds[StageEarlyWarning])
	}
	if ds[StageNotification].State != StatePending || !strings.Contains(ds[StageNotification].Remaining, "1d 18h") {
		t.Fatalf("notification should be pending: %+v", ds[StageNotification])
	}
	in.Mark(StageEarlyWarning, aware.Add(20*time.Hour))
	ds = byStage(in.Deadlines(now))
	if ds[StageEarlyWarning].State != StateSubmitted || ds[StageEarlyWarning].Remaining != "submitted" {
		t.Fatalf("submitted: %+v", ds[StageEarlyWarning])
	}
	in.Mark(StageNotification, aware.Add(80*time.Hour))
	ds = byStage(in.Deadlines(now))
	if ds[StageNotification].State != StateSubmitted || !strings.Contains(ds[StageNotification].Remaining, "late") {
		t.Fatalf("late submission: %+v", ds[StageNotification])
	}
	if err := in.Mark("bogus", now); err == nil {
		t.Fatal("bogus stage accepted")
	}
}

func TestStatusTextContents(t *testing.T) {
	in, _ := New(KindIncident, "Widget", "1.2", "Breach", aware)
	out := in.StatusText(aware.Add(time.Hour))
	for _, want := range []string{"Art. 14(8)", "Art. 14(7)", "Art. 64(10)(a)", "(projected)", "23h 0m left", cra.Disclaimer, cra.SRPPortalURL} {
		if !strings.Contains(out, want) {
			t.Errorf("status missing %q:\n%s", want, out)
		}
	}
	early, _ := New(KindIncident, "W", "1", "old", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if !strings.Contains(early.StatusText(aware), "predates 2026-09-11") {
		t.Fatal("pre-application note missing")
	}
}

func TestDraftsPerStage(t *testing.T) {
	v, _ := New(KindVulnerability, "Widget", "1.2", "RCE", aware)
	cases := []struct {
		kind  Kind
		stage Stage
		wants []string
	}{
		{KindVulnerability, StageEarlyWarning, []string{"Art. 14(2)(a)", "actively exploited", "Member States"}},
		{KindVulnerability, StageNotification, []string{"Art. 14(2)(b)", "nature of the exploit", "Severity and impact", "measures that users can take"}},
		{KindVulnerability, StageFinalReport, []string{"Art. 14(2)(c)", "malicious actor", "security update or other corrective measures", "Annex I Part II (4)"}},
		{KindIncident, StageEarlyWarning, []string{"Art. 14(4)(a)", "unlawful or malicious acts"}},
		{KindIncident, StageNotification, []string{"Art. 14(4)(b)", "nature of the incident", "Initial assessment", "Corrective or mitigating measures taken"}},
		{KindIncident, StageFinalReport, []string{"Art. 14(4)(c)", "root cause", "ongoing mitigation"}},
	}
	for _, c := range cases {
		in := v
		if c.kind == KindIncident {
			in, _ = New(KindIncident, "Widget", "1.2", "Breach", aware)
		}
		out, err := in.Draft(c.stage, aware)
		if err != nil {
			t.Fatalf("%s/%s: %v", c.kind, c.stage, err)
		}
		for _, w := range append(c.wants, DraftHeader, cra.Disclaimer, "Art. 14(8)", "Art. 14(7)", "[TODO]", "Widget", "1.2") {
			if !strings.Contains(out, w) {
				t.Errorf("%s/%s draft missing %q", c.kind, c.stage, w)
			}
		}
		if !strings.HasSuffix(strings.TrimSpace(out), cra.Disclaimer+"_") {
			t.Errorf("%s/%s draft must end with the disclaimer", c.kind, c.stage)
		}
	}
	if _, err := v.Draft("bogus", aware); err == nil {
		t.Fatal("bogus stage accepted")
	}
	fix := aware.Add(48 * time.Hour)
	v.FixAvailableAt = &fix
	v.Notes = append(v.Notes, Note{At: aware, Text: "internal note"})
	out, _ := v.Draft(StageFinalReport, aware)
	if !strings.Contains(out, "2026-10-03 10:00 UTC") || !strings.Contains(out, "internal note") {
		t.Fatalf("final draft should include fix time and notes:\n%s", out)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "incidents.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Incidents) != 0 {
		t.Fatal("missing file should be empty store")
	}
	in, _ := New(KindVulnerability, "Widget", "1.2", "RCE", aware)
	in.Mark(StageEarlyWarning, aware.Add(time.Hour))
	fix := aware.Add(24 * time.Hour)
	in.FixAvailableAt = &fix
	in.Notes = append(in.Notes, Note{At: aware, Text: "n1"})
	s.Add(in)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("store perms %o", st.Mode().Perm())
	}
	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Product != "Widget" || !got.AwareAt.Equal(aware) || got.FixAvailableAt == nil || !got.FixAvailableAt.Equal(fix) || len(got.Notes) != 1 {
		t.Fatalf("round trip: %+v", got)
	}
	if sub, ok := got.SubmittedAt(StageEarlyWarning); !ok || !sub.Equal(aware.Add(time.Hour)) {
		t.Fatalf("submitted lost: %v %v", sub, ok)
	}
	if _, err := s2.Get(in.ID[:3]); err != nil {
		t.Fatalf("prefix lookup: %v", err)
	}
	if _, err := s2.Get("zzzz"); err == nil {
		t.Fatal("unknown id found")
	}
}

func TestDefaultStorePath(t *testing.T) {
	t.Setenv("CRAKIT_STORE", "/tmp/x.json")
	if DefaultStorePath() != "/tmp/x.json" {
		t.Fatal("CRAKIT_STORE ignored")
	}
	t.Setenv("CRAKIT_STORE", "")
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	if DefaultStorePath() != "/tmp/xdg/crakit/incidents.json" {
		t.Fatalf("xdg path: %s", DefaultStorePath())
	}
}

func TestListText(t *testing.T) {
	a, _ := New(KindVulnerability, "A", "1", "first", aware)
	b, _ := New(KindIncident, "B", "1", "second", aware.Add(-time.Hour))
	out := ListText([]*Incident{a, b}, aware)
	if strings.Index(out, "second") > strings.Index(out, "first") {
		t.Fatal("list should sort by aware time")
	}
	if !strings.Contains(out, "early_warning:") || !strings.Contains(out, cra.Disclaimer) {
		t.Fatalf("list output:\n%s", out)
	}
}
