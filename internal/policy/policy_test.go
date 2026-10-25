package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/realTeddy/crakit/cli/internal/cra"
)

func opts() Options {
	return Options{
		Org:      "Acme GmbH",
		Contacts: []string{"mailto:security@acme.example", "https://acme.example/report"},
		Now:      time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
	}
}

func TestSecurityTxtRequiredFields(t *testing.T) {
	out, err := SecurityTxt(opts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Contact: mailto:security@acme.example\n") {
		t.Fatalf("missing Contact: %s", out)
	}
	if !strings.Contains(out, "Expires: 2027-10-24T12:00:00.000Z\n") {
		t.Fatalf("Expires default (1 year minus a day) wrong: %s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, ": ") {
			t.Fatalf("malformed line %q", line)
		}
	}
}

func TestSecurityTxtContactOrder(t *testing.T) {
	out, _ := SecurityTxt(opts())
	i := strings.Index(out, "Contact: mailto:security@acme.example")
	j := strings.Index(out, "Contact: https://acme.example/report")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("contacts out of order:\n%s", out)
	}
}

func TestSecurityTxtOptionalFields(t *testing.T) {
	o := opts()
	o.Encryption = "https://acme.example/pgp.asc"
	o.AcknowledgmentsURL = "https://acme.example/thanks"
	o.Languages = "en, de"
	o.Canonical = "https://acme.example/.well-known/security.txt"
	o.PolicyURL = "https://acme.example/security-policy"
	o.Hiring = "https://acme.example/jobs"
	o.Expires = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	out, err := SecurityTxt(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Encryption: https://acme.example/pgp.asc",
		"Acknowledgments: https://acme.example/thanks",
		"Preferred-Languages: en, de",
		"Canonical: https://acme.example/.well-known/security.txt",
		"Policy: https://acme.example/security-policy",
		"Hiring: https://acme.example/jobs",
		"Expires: 2027-01-01T00:00:00.000Z",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestSecurityTxtErrors(t *testing.T) {
	o := opts()
	o.Contacts = nil
	if _, err := SecurityTxt(o); err == nil {
		t.Fatal("no contact should error")
	}
	if _, err := Markdown(o); err == nil {
		t.Fatal("no contact should error for markdown too")
	}
	o = opts()
	o.Contacts = []string{"security@acme.example"}
	if _, err := SecurityTxt(o); err == nil {
		t.Fatal("bare email should be rejected (needs mailto:)")
	}
	o = opts()
	o.Canonical = "http://insecure"
	if _, err := SecurityTxt(o); err == nil {
		t.Fatal("http canonical should be rejected")
	}
}

func TestMarkdownCitationsAndDisclaimer(t *testing.T) {
	o := opts()
	o.AckDays = 3
	o.DisclosureDays = 60
	out, err := Markdown(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Annex I Part II (5)", "Annex I Part II (6)", "Annex I Part II (4)", "Art. 13(17)", "Art. 14(2)", "Art. 14(8)", "Art. 15",
		"within 3 business days", "up to 60 days", "Safe harbour", "mailto:security@acme.example", cra.Disclaimer,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(out), cra.Disclaimer+"_") {
		t.Fatal("disclaimer must end the document")
	}
	if strings.Contains(strings.ToLower(out), "guarantees compliance") {
		t.Fatal("must not claim compliance")
	}
}

func TestDefaults(t *testing.T) {
	var o Options
	o.Defaults()
	if o.AckDays != 5 || o.DisclosureDays != 90 || o.Expires.IsZero() || o.Org == "" {
		t.Fatalf("defaults: %+v", o)
	}
	if o.Expires.Sub(o.Now) >= 365*24*time.Hour {
		t.Fatal("default Expires should be less than a year away")
	}
}
