package cra

import (
	"strings"
	"testing"
)

func TestDateConstantsParse(t *testing.T) {
	for _, d := range []string{EntryIntoForce, NotifiedBodiesApply, ReportingApplies, FullApplication} {
		got := Date(d)
		if got.IsZero() {
			t.Fatalf("date %q parsed to zero", d)
		}
	}
	if Date(ReportingApplies).Format("2006-01-02") != "2026-09-11" {
		t.Fatalf("reporting date wrong: %s", ReportingApplies)
	}
	if Date(FullApplication).Format("2006-01-02") != "2027-12-11" {
		t.Fatalf("full application wrong: %s", FullApplication)
	}
	if !Date(ReportingApplies).Before(Date(FullApplication)) {
		t.Fatal("reporting must apply before full application")
	}
}

func TestArticleCitationsExist(t *testing.T) {
	cites := []string{ArtScope, ArtReportVulnEarlyWarning, ArtReportVulnNotification, ArtReportVulnFinalReport,
		ArtReportIncEarlyWarning, ArtReportIncNotification, ArtReportIncFinalReport, ArtInformUsers, ArtSRP,
		ArtSupportPeriod, ArtDoC, ArtCEMarking, ArtConformityAssessment, AnnexIPartIICVD, AnnexIPartIIContact,
		ArtSinglePointOfContact, ArtPenalties}
	for _, c := range cites {
		if !strings.HasPrefix(c, "Art.") && !strings.HasPrefix(c, "Annex") {
			t.Errorf("citation %q does not look like an article/annex reference", c)
		}
	}
	if ArtReportVulnEarlyWarning != "Art. 14(2)(a)" || ArtReportIncFinalReport != "Art. 14(4)(c)" {
		t.Fatal("Art. 14 citations wrong")
	}
}

func TestDisclaimerWording(t *testing.T) {
	if !strings.Contains(Disclaimer, "not legal advice") || !strings.Contains(Disclaimer, "Regulation (EU) 2024/2847") {
		t.Fatal("disclaimer wording changed")
	}
}

func TestCategories(t *testing.T) {
	if _, ok := FindCategory("operating-system"); !ok {
		t.Fatal("operating-system missing")
	}
	if c, _ := FindCategory("firewall-ids-ips"); c.Class != ClassImportantII {
		t.Fatalf("firewall should be Class II, got %s", c.Class)
	}
	if c, _ := FindCategory("smartcard-secure-element"); c.Class != ClassCritical {
		t.Fatalf("smartcard should be critical, got %s", c.Class)
	}
	if _, ok := FindCategory("nope"); ok {
		t.Fatal("unknown slug found")
	}
	seen := map[string]bool{}
	for _, s := range CategorySlugs() {
		if seen[s] {
			t.Fatalf("duplicate slug %s", s)
		}
		seen[s] = true
	}
	if len(EssentialRequirements) != 14 || len(VulnerabilityHandlingRequirements) != 8 {
		t.Fatalf("requirement counts: %d / %d", len(EssentialRequirements), len(VulnerabilityHandlingRequirements))
	}
}
