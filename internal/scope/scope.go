// Package scope implements the CRA scope questionnaire and verdict logic.
// Each rule cites the article, annex or recital of Regulation (EU) 2024/2847
// it is derived from.
package scope

import (
	"fmt"
	"strings"
	"time"

	"github.com/realTeddy/crakit-cli/internal/cra"
)

// Answer values.
const (
	Yes = "yes"
	No  = "no"
)

// Product types.
const (
	TypeSoftware  = "software"
	TypeHardware  = "hardware"
	TypeFirmware  = "firmware"
	TypeSaaS      = "saas"
	TypeComponent = "component"
)

// Roles (Art. 3(13), Art. 19, Art. 20, Art. 22).
const (
	RoleManufacturer = "manufacturer"
	RoleImporter     = "importer"
	RoleDistributor  = "distributor"
	RoleModifier     = "modifier"
)

// Excluded sectors (Art. 2(2)-(7)).
const (
	SectorNone       = "none"
	SectorMedical    = "medical"
	SectorAutomotive = "automotive"
	SectorAviation   = "aviation"
	SectorMarine     = "marine"
	SectorDefence    = "defence"
)

var (
	ProductTypes = []string{TypeSoftware, TypeHardware, TypeFirmware, TypeSaaS, TypeComponent}
	Roles        = []string{RoleManufacturer, RoleImporter, RoleDistributor, RoleModifier}
	Sectors      = []string{SectorNone, SectorMedical, SectorAutomotive, SectorAviation, SectorMarine, SectorDefence}
)

// Input is the set of questionnaire answers.
type Input struct {
	ProductType               string `json:"product_type"`
	Connected                 string `json:"connected"`
	Commercial                string `json:"commercial"`
	OpenSource                string `json:"open_source"`
	OSSMonetised              string `json:"oss_monetised"`
	RemoteProcessingEssential string `json:"remote_processing_essential"`
	ExcludedSector            string `json:"excluded_sector"`
	Category                  string `json:"category"`
	Role                      string `json:"role"`
	PlacedAfter               string `json:"placed_after,omitempty"`
}

// Status is the tri-state scope result.
type Status string

const (
	StatusLikely   Status = "likely"
	StatusUnlikely Status = "unlikely"
	StatusOut      Status = "out"
)

// Reason explains part of a verdict.
type Reason struct {
	Text     string `json:"text"`
	Citation string `json:"citation"`
}

// Obligation is one duty with its citation and, where applicable, the date
// from which it applies.
type Obligation struct {
	Text     string `json:"text"`
	Citation string `json:"citation"`
	Deadline string `json:"deadline,omitempty"`
}

// Verdict is the result of the questionnaire.
type Verdict struct {
	InScope                 Status       `json:"in_scope"`
	Class                   cra.Class    `json:"class"`
	Role                    string       `json:"role"`
	Reasons                 []Reason     `json:"reasons"`
	Obligations             []Obligation `json:"obligations"`
	ConformityRoute         string       `json:"conformity_route"`
	ConformityRouteCitation string       `json:"conformity_route_citation"`
	Disclaimer              string       `json:"disclaimer"`
	Input                   Input        `json:"input"`
}

// Missing returns the names of required fields that are empty or invalid.
func (in Input) Missing() []string {
	var m []string
	if !oneOf(in.ProductType, ProductTypes) {
		m = append(m, "product-type")
	}
	if !oneOf(in.Connected, []string{Yes, No}) {
		m = append(m, "connected")
	}
	if !oneOf(in.Commercial, []string{Yes, No}) {
		m = append(m, "commercial")
	}
	if !oneOf(in.OpenSource, []string{Yes, No}) {
		m = append(m, "open-source")
	}
	if in.OpenSource == Yes && !oneOf(in.OSSMonetised, []string{Yes, No}) {
		m = append(m, "oss-monetised")
	}
	if in.ProductType == TypeSaaS && !oneOf(in.RemoteProcessingEssential, []string{Yes, No}) {
		m = append(m, "remote-processing-essential")
	}
	if !oneOf(in.ExcludedSector, Sectors) {
		m = append(m, "excluded-sector")
	}
	if in.Category == "" {
		m = append(m, "category")
	} else if in.Category != "none" {
		if _, ok := cra.FindCategory(in.Category); !ok {
			m = append(m, "category")
		}
	}
	if !oneOf(in.Role, Roles) {
		m = append(m, "role")
	}
	if in.PlacedAfter != "" {
		if _, err := time.Parse("2006-01-02", in.PlacedAfter); err != nil {
			m = append(m, "placed-after")
		}
	}
	return m
}

func oneOf(v string, opts []string) bool {
	for _, o := range opts {
		if v == o {
			return true
		}
	}
	return false
}

// Evaluate applies the scope rules to the answers.
func Evaluate(in Input) Verdict {
	v := Verdict{
		Role:       in.Role,
		Class:      cra.ClassDefault,
		Disclaimer: cra.Disclaimer,
		Input:      in,
	}

	// 1. Sector exclusions (Art. 2(2)-(7)).
	if in.ExcludedSector != SectorNone && in.ExcludedSector != "" {
		v.InScope = StatusOut
		v.Reasons = append(v.Reasons, Reason{
			Text:     fmt.Sprintf("Products in the %s sector are covered by sector-specific Union legislation and excluded from the CRA: %s.", in.ExcludedSector, sectorLaw(in.ExcludedSector)),
			Citation: cra.ArtExclusions,
		})
		v.ConformityRoute = "Not applicable (out of scope)"
		v.ConformityRouteCitation = cra.ArtExclusions
		return v
	}

	// 2. SaaS: out of scope unless remote data processing is essential (Recital 12, Art. 3(1)-(2)).
	if in.ProductType == TypeSaaS && in.RemoteProcessingEssential != Yes {
		v.InScope = StatusOut
		v.Reasons = append(v.Reasons, Reason{
			Text:     "Software-as-a-service and cloud solutions are not products with digital elements unless they are 'remote data processing solutions' designed by the manufacturer and without which the product cannot perform one of its functions; NIS2 covers cloud services instead.",
			Citation: cra.RecitalSaaS + ", " + cra.ArtDefProduct + ", " + cra.ArtDefRemoteProcessing,
		})
		v.ConformityRoute = "Not applicable (out of scope)"
		v.ConformityRouteCitation = cra.RecitalSaaS
		return v
	}

	// 3. Non-commercial free and open-source software (Recitals 18-19, Art. 24).
	if in.OpenSource == Yes && in.OSSMonetised != Yes && in.Commercial != Yes {
		v.InScope = StatusOut
		v.Reasons = append(v.Reasons, Reason{
			Text:     "Free and open-source software developed or supplied outside the course of a commercial activity is not covered. Monetisation (charging for the product, paid support beyond cost recovery, or commercial use with support as the business) would indicate a commercial activity.",
			Citation: cra.RecitalOSS,
		})
		v.Reasons = append(v.Reasons, Reason{
			Text:     "If you are a legal person providing sustained support for open-source products intended for commercial activities (an open-source software steward), a light regime applies instead.",
			Citation: cra.ArtDefOSSSteward + ", " + cra.ArtOSSStewards,
		})
		v.ConformityRoute = "Not applicable (out of scope)"
		v.ConformityRouteCitation = cra.RecitalOSS
		return v
	}

	// 4. Not connected (Art. 2(1)).
	if in.Connected != Yes {
		v.InScope = StatusOut
		v.Reasons = append(v.Reasons, Reason{
			Text:     "The CRA applies to products whose intended purpose or reasonably foreseeable use includes a direct or indirect logical or physical data connection to a device or network. You answered that there is none.",
			Citation: cra.ArtScope,
		})
		v.ConformityRoute = "Not applicable (out of scope)"
		v.ConformityRouteCitation = cra.ArtScope
		return v
	}

	// In scope.
	v.InScope = StatusLikely
	v.Reasons = append(v.Reasons, Reason{
		Text:     "The product is a software or hardware product with a data connection to a device or network, made available on the EU market.",
		Citation: cra.ArtScope + ", " + cra.ArtDefProduct,
	})
	if in.ProductType == TypeComponent {
		v.Reasons = append(v.Reasons, Reason{
			Text:     "Software or hardware components placed on the market separately are products with digital elements in their own right.",
			Citation: cra.ArtDefProduct,
		})
	}
	if in.ProductType == TypeSaaS {
		v.Reasons = append(v.Reasons, Reason{
			Text:     "The remote data processing solution is covered because the product cannot perform one of its functions without it.",
			Citation: cra.ArtDefRemoteProcessing,
		})
	}
	if in.OpenSource == Yes {
		v.Reasons = append(v.Reasons, Reason{
			Text:     "Open-source software supplied in the course of a commercial activity (monetised or commercial) is in scope.",
			Citation: cra.RecitalOSS,
		})
	}
	v.Reasons = append(v.Reasons, Reason{
		Text:     "There is no exemption from scope for micro, small or medium-sized enterprises; support measures and a simplified technical documentation form exist.",
		Citation: cra.ArtSMESupport + ", " + cra.ArtSimplifiedTechDoc,
	})

	// Class from category (Annex III / IV).
	if in.Category != "" && in.Category != "none" {
		if c, ok := cra.FindCategory(in.Category); ok {
			v.Class = c.Class
			v.Reasons = append(v.Reasons, Reason{
				Text:     fmt.Sprintf("Category '%s' (%s) is listed as %s.", c.Slug, c.Description, className(c.Class)),
				Citation: c.Citation,
			})
		}
	} else {
		v.Reasons = append(v.Reasons, Reason{
			Text:     "No Annex III or Annex IV category applies, so the product is a default product.",
			Citation: cra.AnnexIIIImportant + ", " + cra.AnnexIVCritical,
		})
	}

	// Role.
	switch in.Role {
	case RoleModifier:
		v.Reasons = append(v.Reasons, Reason{
			Text:     "A person who carries out a substantial modification of a product and makes it available is considered a manufacturer and takes on manufacturer obligations.",
			Citation: cra.ArtSubstantialModification + ", " + cra.ArtDefManufacturer,
		})
	case RoleImporter:
		v.Reasons = append(v.Reasons, Reason{
			Text:     "Importers must place only compliant products on the market and verify the manufacturer has carried out conformity assessment, drawn up technical documentation and affixed CE marking.",
			Citation: cra.ArtImporters,
		})
	case RoleDistributor:
		v.Reasons = append(v.Reasons, Reason{
			Text:     "Distributors must act with due care and verify CE marking, EU declaration of conformity and manufacturer/importer identification before making the product available.",
			Citation: cra.ArtDistributors,
		})
	}

	v.ConformityRoute, v.ConformityRouteCitation = ConformityRoute(v.Class)
	v.Obligations = Obligations(v.Class, in.Role)
	return v
}

func className(c cra.Class) string {
	switch c {
	case cra.ClassImportantI:
		return "an important product, Class I"
	case cra.ClassImportantII:
		return "an important product, Class II"
	case cra.ClassCritical:
		return "a critical product"
	}
	return "a default product"
}

func sectorLaw(s string) string {
	switch s {
	case SectorMedical:
		return "medical devices and in vitro diagnostics (Regulations (EU) 2017/745 and 2017/746)"
	case SectorAutomotive:
		return "motor vehicle type-approval (Regulation (EU) 2019/2144)"
	case SectorAviation:
		return "civil aviation (Regulation (EU) 2018/1139)"
	case SectorMarine:
		return "marine equipment (Directive 2014/90/EU)"
	case SectorDefence:
		return "products developed exclusively for national security or defence purposes"
	}
	return "sector-specific legislation"
}

// ConformityRoute returns the applicable conformity assessment procedure
// for a class, with its citation (Art. 32).
func ConformityRoute(c cra.Class) (string, string) {
	switch c {
	case cra.ClassImportantI:
		return "Important product Class I: internal control (Module A) only where harmonised standards, common specifications or a European cybersecurity certification scheme (assurance level at least 'substantial') are applied in full; otherwise EU-type examination plus conformity to type (Modules B+C) or full quality assurance (Module H) with a notified body. No CRA harmonised standards had been cited in the Official Journal as of October 2026, so third-party assessment is currently required in practice for Class I until harmonised standards are cited. Free and open-source products in Annex III categories may use internal control if the technical documentation is made public (Art. 32(5)).",
			cra.ArtConformityAssessment + "(2), " + cra.AnnexVIIIModuleBC + ", " + cra.AnnexVIIIModuleH
	case cra.ClassImportantII:
		return "Important product Class II: third-party conformity assessment by a notified body (Modules B+C or Module H).",
			cra.ArtConformityAssessment + "(3), " + cra.AnnexVIIIModuleBC + ", " + cra.AnnexVIIIModuleH
	case cra.ClassCritical:
		return "Critical product: European cybersecurity certification scheme where one is available and required by delegated act; otherwise as for Class II (notified body, Modules B+C or H).",
			cra.ArtConformityAssessment + "(4)-(5), " + cra.AnnexIVCritical
	}
	return "Default product: internal control (Module A), self-assessment by the manufacturer.",
		cra.ArtConformityAssessment + "(1), " + cra.AnnexVIIIModuleA
}

// Obligations lists the manufacturer-side obligations for an in-scope product.
func Obligations(c cra.Class, role string) []Obligation {
	obs := []Obligation{
		{Text: "Notify actively exploited vulnerabilities and severe incidents via the ENISA single reporting platform: early warning within 24 hours, notification within 72 hours, final report (14 days after a fix is available for vulnerabilities; 1 month after notification for incidents).", Citation: cra.ArtReporting + ", " + cra.ArtSRP, Deadline: cra.ReportingApplies},
		{Text: cra.ReportingEndpointNote, Citation: cra.ArtReportingEndpoint + ", " + cra.ArtSRP, Deadline: cra.ReportingApplies},
		{Text: cra.SmallEnterpriseEarlyWarningNote, Citation: cra.ArtSmallEnterpriseNoFine24, Deadline: cra.ReportingApplies},
		{Text: "Inform impacted users without undue delay about actively exploited vulnerabilities and severe incidents, with corrective measures and mitigations.", Citation: cra.ArtInformUsers, Deadline: cra.ReportingApplies},
		{Text: "Design, develop and produce the product in accordance with the essential cybersecurity requirements (secure by default, no known exploitable vulnerabilities, updates, access control, encryption, logging, data erasure).", Citation: cra.ArtDesignAnnexI + ", " + cra.AnnexIPartI, Deadline: cra.FullApplication},
		{Text: "Carry out and document a cybersecurity risk assessment, keep it updated and include it in the technical documentation.", Citation: cra.ArtRiskAssessment, Deadline: cra.FullApplication},
		{Text: "Exercise due diligence on integrated third-party components, including open-source components.", Citation: cra.ArtDueDiligence, Deadline: cra.FullApplication},
		{Text: "Operate vulnerability handling processes: SBOM in a machine-readable format (top-level dependencies at least), remediate without delay, regular security testing, public disclosure of fixed vulnerabilities, coordinated vulnerability disclosure policy, contact address, secure update distribution, free patches with advisories.", Citation: cra.ArtVulnHandling + ", " + cra.AnnexIPartII, Deadline: cra.FullApplication},
		{Text: "Determine and document a support period of at least 5 years (or the expected product lifetime if shorter) during which vulnerabilities are handled; each security update released during the support period must remain available for at least 10 years or the remainder of the support period, whichever is longer.", Citation: cra.ArtSupportPeriod + ", " + cra.ArtUpdatesAvailability, Deadline: cra.FullApplication},
		{Text: "Draw up the technical documentation before placing the product on the market (product description; design, development and vulnerability handling processes including the SBOM, the coordinated vulnerability disclosure policy, evidence of the provision of a contact address, and a description of the technical solutions chosen for the secure distribution of updates; risk assessment; support-period rationale; standards applied; test reports; copy of the EU DoC; SBOM on reasoned request).", Citation: cra.ArtTechDoc + ", " + cra.AnnexVIITechDoc, Deadline: cra.FullApplication},
		{Text: "Draw up the EU declaration of conformity (full content per Annex V; simplified form per Annex VI) and either accompany the product with it or give a web address where it is available.", Citation: cra.ArtDoC + ", " + cra.AnnexVDoC + ", " + cra.AnnexVISimplifiedDoC + ", " + cra.ArtDoCAccompanies, Deadline: cra.FullApplication},
		{Text: "Affix the CE marking.", Citation: cra.ArtCEMarking, Deadline: cra.FullApplication},
		{Text: "Keep the technical documentation and EU DoC for at least 10 years after placing on the market or for the support period, whichever is longer.", Citation: cra.ArtRetention, Deadline: cra.FullApplication},
		{Text: "Indicate manufacturer name, registered trade name and a contact address (postal, email or other digital) on the product or its packaging/documentation.", Citation: cra.ArtIdentification, Deadline: cra.FullApplication},
		{Text: "Designate a single point of contact enabling users to report vulnerabilities and receive information about them, and provide user information and instructions (Annex II).", Citation: cra.ArtSinglePointOfContact + ", " + cra.ArtUserInformation + ", " + cra.AnnexIIUserInfo, Deadline: cra.FullApplication},
		{Text: "Show the end date of the support period (at least month and year) clearly at the time of purchase.", Citation: cra.ArtEndOfSupportDate, Deadline: cra.FullApplication},
	}
	route, cite := ConformityRoute(c)
	obs = append(obs, Obligation{Text: "Carry out the conformity assessment procedure: " + route, Citation: cite, Deadline: cra.FullApplication})
	if c == cra.ClassImportantI || c == cra.ClassImportantII || c == cra.ClassCritical {
		obs = append(obs, Obligation{Text: "Notified bodies may be designated from this date; plan lead time for third-party assessment where required.", Citation: cra.ArtApplication, Deadline: cra.NotifiedBodiesApply})
	}
	obs = append(obs, Obligation{Text: "Penalties: up to EUR 15,000,000 or 2.5% of worldwide annual turnover for non-compliance with Annex I or Art. 13/14; up to EUR 10,000,000 or 2% for other obligations; up to EUR 5,000,000 or 1% for incorrect, incomplete or misleading information to notified bodies or market surveillance authorities.", Citation: cra.ArtPenalties, Deadline: cra.FullApplication})
	switch role {
	case RoleImporter:
		obs = append([]Obligation{{Text: "As importer: place only compliant products on the market; verify that the manufacturer has carried out conformity assessment, drawn up technical documentation, affixed CE marking and met Art. 13 identification duties; indicate your own name and contact address.", Citation: cra.ArtImporters, Deadline: cra.FullApplication}}, obs...)
	case RoleDistributor:
		obs = append([]Obligation{{Text: "As distributor: act with due care; verify CE marking, EU DoC and manufacturer/importer identification; do not make non-compliant products available; inform the manufacturer and authorities of vulnerabilities you become aware of.", Citation: cra.ArtDistributors, Deadline: cra.FullApplication}}, obs...)
	}
	return obs
}

// Text renders the verdict as plain text.
func (v Verdict) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "crakit scope verdict (%s)\n\n", cra.Regulation)
	fmt.Fprintf(&b, "Scope:            %s\n", scopeLabel(v.InScope))
	fmt.Fprintf(&b, "Class:            %s\n", v.Class)
	fmt.Fprintf(&b, "Role:             %s\n", v.Role)
	fmt.Fprintf(&b, "Conformity route: %s [%s]\n", v.ConformityRoute, v.ConformityRouteCitation)
	b.WriteString("\nReasons:\n")
	for _, r := range v.Reasons {
		fmt.Fprintf(&b, "  - %s [%s]\n", r.Text, r.Citation)
	}
	if len(v.Obligations) > 0 {
		b.WriteString("\nObligations:\n")
		for _, o := range v.Obligations {
			d := ""
			if o.Deadline != "" {
				d = " (applies from " + o.Deadline + ")"
			}
			fmt.Fprintf(&b, "  - %s [%s]%s\n", o.Text, o.Citation, d)
		}
	}
	b.WriteString("\n" + v.Disclaimer + "\n")
	return b.String()
}

func scopeLabel(s Status) string {
	switch s {
	case StatusLikely:
		return "LIKELY IN SCOPE"
	case StatusUnlikely:
		return "UNLIKELY IN SCOPE"
	}
	return "OUT OF SCOPE"
}
