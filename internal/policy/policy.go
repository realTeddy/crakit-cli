// Package policy generates a coordinated vulnerability disclosure (CVD)
// policy in Markdown and an RFC 9116 security.txt. A CVD policy and a
// contact address for reporting are required by Annex I Part II (5)-(6) of
// Regulation (EU) 2024/2847; the single point of contact is Art. 13(17).
package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/realTeddy/crakit/cli/internal/cra"
)

// Options configures both documents.
type Options struct {
	Org                string
	Contacts           []string // in order of preference (RFC 9116 s2.5.3)
	URL                string
	PolicyURL          string
	Encryption         string
	Languages          string // comma-separated, e.g. "en,de"
	AcknowledgmentsURL string
	Expires            time.Time
	Canonical          string
	Hiring             string
	AckDays            int
	DisclosureDays     int
	Now                time.Time
}

// Defaults fills unset values.
func (o *Options) Defaults() {
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.Expires.IsZero() {
		// RFC 9116 s2.5.5 recommends less than a year: one year minus a day.
		o.Expires = o.Now.AddDate(1, 0, -1).UTC()
	}
	if o.AckDays <= 0 {
		o.AckDays = 5
	}
	if o.DisclosureDays <= 0 {
		o.DisclosureDays = 90
	}
	if o.Org == "" {
		o.Org = "[Organisation name]"
	}
}

// Validate checks RFC 9116 requirements.
func (o Options) Validate() error {
	if len(o.Contacts) == 0 {
		return errors.New("at least one --contact is required (RFC 9116 section 2.5.3: Contact is mandatory)")
	}
	for _, c := range o.Contacts {
		if !strings.HasPrefix(c, "mailto:") && !strings.HasPrefix(c, "https://") && !strings.HasPrefix(c, "tel:") {
			return fmt.Errorf("contact %q must be a mailto:, https:// or tel: URI (RFC 9116 section 2.5.3)", c)
		}
	}
	if o.Encryption != "" && !strings.HasPrefix(o.Encryption, "https://") && !strings.HasPrefix(o.Encryption, "dns:") && !strings.HasPrefix(o.Encryption, "openpgp4fpr:") {
		return fmt.Errorf("encryption %q should be an https://, dns: or openpgp4fpr: URI (RFC 9116 section 2.5.4)", o.Encryption)
	}
	if o.Canonical != "" && !strings.HasPrefix(o.Canonical, "https://") {
		return fmt.Errorf("canonical %q must be an https:// URI (RFC 9116 section 2.5.2)", o.Canonical)
	}
	return nil
}

// ExpiresFormat is the RFC 9116 / ISO 8601 UTC format used for Expires.
const ExpiresFormat = "2006-01-02T15:04:05.000Z"

// SecurityTxt renders the RFC 9116 file.
func SecurityTxt(o Options) (string, error) {
	o.Defaults()
	if err := o.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# security.txt for %s (RFC 9116). Serve at /.well-known/security.txt over HTTPS.\n", o.Org)
	b.WriteString("# Vulnerability reporting contact per Annex I Part II (6) and Art. 13(17) of Regulation (EU) 2024/2847.\n")
	for _, c := range o.Contacts {
		fmt.Fprintf(&b, "Contact: %s\n", c)
	}
	fmt.Fprintf(&b, "Expires: %s\n", o.Expires.UTC().Format(ExpiresFormat))
	if o.Encryption != "" {
		fmt.Fprintf(&b, "Encryption: %s\n", o.Encryption)
	}
	if o.AcknowledgmentsURL != "" {
		fmt.Fprintf(&b, "Acknowledgments: %s\n", o.AcknowledgmentsURL)
	}
	if o.Languages != "" {
		langs := strings.Split(o.Languages, ",")
		for i := range langs {
			langs[i] = strings.TrimSpace(langs[i])
		}
		fmt.Fprintf(&b, "Preferred-Languages: %s\n", strings.Join(langs, ", "))
	}
	if o.Canonical != "" {
		fmt.Fprintf(&b, "Canonical: %s\n", o.Canonical)
	}
	if o.PolicyURL != "" {
		fmt.Fprintf(&b, "Policy: %s\n", o.PolicyURL)
	}
	if o.Hiring != "" {
		fmt.Fprintf(&b, "Hiring: %s\n", o.Hiring)
	}
	return b.String(), nil
}

// Markdown renders the CVD policy.
func Markdown(o Options) (string, error) {
	o.Defaults()
	if err := o.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# Coordinated Vulnerability Disclosure Policy - %s", o.Org)
	w("")
	w("_Last updated: %s. Policy drafted with crakit to support %s and %s (coordinated vulnerability disclosure policy and contact address for reporting) and %s (single point of contact) of %s._", o.Now.UTC().Format("2006-01-02"), cra.AnnexIPartIICVD, cra.AnnexIPartIIContact, cra.ArtSinglePointOfContact, cra.Regulation)
	w("")
	w("## 1. Scope")
	w("")
	w("This policy covers security vulnerabilities in the products with digital elements that %s makes available on the market, including their remote data processing solutions (%s), and the associated update and distribution infrastructure.", o.Org, cra.ArtDefProduct)
	if o.URL != "" {
		w("")
		w("Product information: %s", o.URL)
	}
	w("")
	w("## 2. How to report")
	w("")
	w("Report vulnerabilities to our single point of contact (%s, %s):", cra.ArtSinglePointOfContact, cra.AnnexIPartIIContact)
	w("")
	for i, c := range o.Contacts {
		w("%d. %s", i+1, c)
	}
	if o.Encryption != "" {
		w("")
		w("Encrypt sensitive reports with our key: %s", o.Encryption)
	}
	w("")
	w("A machine-readable version of this contact information is published at `/.well-known/security.txt` (RFC 9116).")
	w("")
	w("## 3. What to include")
	w("")
	w("- Product name and version(s) affected")
	w("- A description of the vulnerability and its potential impact")
	w("- Steps to reproduce or a proof of concept")
	w("- Any known mitigations")
	w("- Whether you believe the vulnerability is being actively exploited")
	w("- How you would like to be credited, if at all")
	w("")
	w("## 4. What we commit to")
	w("")
	w("- We acknowledge receipt within %d business days.", o.AckDays)
	w("- We investigate, keep you informed of progress, and address and remediate the vulnerability without delay, including by providing security updates (%s).", cra.AnnexIPartIIRemedy)
	w("- Security updates are distributed securely (%s) and provided without delay and free of charge, together with advisory messages (%s).", cra.AnnexIPartIIDistrib, cra.AnnexIPartIIPatches)
	w("- Once a security update is available we publicly disclose information about the fixed vulnerability: a description, its impact and severity, and remediation guidance (%s).", cra.AnnexIPartIIDisclose)
	w("- Where a vulnerability is found to be actively exploited, we notify it via the ENISA single reporting platform within the deadlines of %s (early warning within 24 hours, notification within 72 hours, final report within 14 days of a fix being available) and inform impacted users (%s). That judgement and submission is ours, not the reporter's.", cra.ArtReportVulnStages, cra.ArtInformUsers)
	w("")
	w("## 5. Disclosure timeline")
	w("")
	w("We ask reporters to allow up to %d days from acknowledgement before public disclosure, so that a fix can be developed, tested and distributed. We will coordinate an earlier or later date with you where a fix is ready sooner, where the vulnerability is already public or actively exploited, or where remediation genuinely needs more time. Reporters may share the vulnerability with the relevant CSIRT or ENISA at any time (%s).", o.DisclosureDays, cra.ArtVoluntaryReporting)
	w("")
	w("## 6. Safe harbour")
	w("")
	w("We will not pursue legal action against, or report to law enforcement, researchers who act in good faith under this policy: who avoid privacy violations, data destruction and service disruption, who do not exploit a vulnerability beyond what is needed to demonstrate it, who do not access or modify other users' data, and who give us a reasonable time to remediate before disclosure. If in doubt, ask us first.")
	w("")
	w("## 7. Out of scope")
	w("")
	w("- Reports from automated scanners without a demonstrated impact")
	w("- Social engineering, physical attacks and denial-of-service testing against production systems")
	w("- Issues in third-party services we do not operate (please report them to the respective vendor)")
	w("")
	w("## 8. Recognition")
	w("")
	if o.AcknowledgmentsURL != "" {
		w("With your consent we credit reporters at %s.", o.AcknowledgmentsURL)
	} else {
		w("With your consent we credit reporters in our security advisories.")
	}
	w("")
	w("---")
	w("")
	w("_%s_", cra.Disclaimer)
	return b.String(), nil
}
