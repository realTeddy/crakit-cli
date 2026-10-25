// Package cra holds constants shared across crakit: key dates, article
// references and product category lists from Regulation (EU) 2024/2847
// (the Cyber Resilience Act).
//
// Every regulatory statement here cites the article, annex or recital it is
// taken from. Nothing in this package is legal advice.
package cra

import "time"

// Disclaimer is appended to every verdict and generated document.
const Disclaimer = "This is a checklist and drafting aid, not legal advice and not a guarantee of compliance with Regulation (EU) 2024/2847."

// Regulation is the short title used in output.
const Regulation = "Regulation (EU) 2024/2847"

// Key dates (all from Art. 71 unless noted). Stored as RFC 3339 date strings
// so they can be cited verbatim; use the Date helpers to get time.Time values.
const (
	// EntryIntoForce is the date the Regulation entered into force (Art. 71(1)).
	EntryIntoForce = "2024-12-10"
	// NotifiedBodiesApply is when Chapter IV (notification of conformity
	// assessment bodies) applies (Art. 71(2)).
	NotifiedBodiesApply = "2026-06-11"
	// ReportingApplies is when the Art. 14 reporting obligations apply (Art. 71(2)).
	ReportingApplies = "2026-09-11"
	// FullApplication is when the Regulation applies in full (Art. 71(2)).
	FullApplication = "2027-12-11"
)

// Article references used throughout the CLI.
const (
	ArtScope                   = "Art. 2(1)"
	ArtExclusions              = "Art. 2(2)-(7)"
	ArtDefProduct              = "Art. 3(1)"
	ArtDefRemoteProcessing     = "Art. 3(2)"
	ArtDefManufacturer         = "Art. 3(13)"
	ArtDefOSSSteward           = "Art. 3(14)"
	ArtManufacturerObligations = "Art. 13"
	ArtDesignAnnexI            = "Art. 13(1)"
	ArtRiskAssessment          = "Art. 13(2)"
	ArtDueDiligence            = "Art. 13(3)"
	ArtVulnHandling            = "Art. 13(6)"
	ArtSupportPeriod           = "Art. 13(8)"
	ArtUpdatesAvailability     = "Art. 13(9)"
	ArtTechDoc                 = "Art. 13(12)"
	ArtRetention               = "Art. 13(13)"
	ArtIdentification          = "Art. 13(15)-(16)"
	ArtUserInformation         = "Art. 13(18)"
	ArtSinglePointOfContact    = "Art. 13(17)"
	ArtEndOfSupportDate        = "Art. 13(19)"
	ArtDoCAccompanies          = "Art. 13(20)"
	ArtReporting               = "Art. 14"
	ArtReportVuln              = "Art. 14(1)"
	ArtReportVulnStages        = "Art. 14(2)"
	ArtReportVulnEarlyWarning  = "Art. 14(2)(a)"
	ArtReportVulnNotification  = "Art. 14(2)(b)"
	ArtReportVulnFinalReport   = "Art. 14(2)(c)"
	ArtReportIncident          = "Art. 14(3)"
	ArtReportIncidentStages    = "Art. 14(4)"
	ArtReportIncEarlyWarning   = "Art. 14(4)(a)"
	ArtReportIncNotification   = "Art. 14(4)(b)"
	ArtReportIncFinalReport    = "Art. 14(4)(c)"
	ArtReportingEndpoint       = "Art. 14(7)"
	ArtInformUsers             = "Art. 14(8)"
	ArtVoluntaryReporting      = "Art. 15"
	ArtSRP                     = "Art. 16"
	ArtImporters               = "Art. 19"
	ArtDistributors            = "Art. 20"
	ArtSubstantialModification = "Art. 22"
	ArtOSSStewards             = "Art. 24"
	ArtDoC                     = "Art. 28"
	ArtCEMarking               = "Art. 30"
	ArtConformityAssessment    = "Art. 32"
	ArtFOSSInternalControl     = "Art. 32(5)"
	ArtSMESupport              = "Art. 33"
	ArtSimplifiedTechDoc       = "Art. 33(5)"
	ArtPenalties               = "Art. 64"
	ArtSmallEnterpriseNoFine24 = "Art. 64(10)(a)"
	ArtApplication             = "Art. 71(2)"

	AnnexIPartI          = "Annex I Part I"
	AnnexIPartII         = "Annex I Part II"
	AnnexIPartIISBOM     = "Annex I Part II (1)"
	AnnexIPartIIRemedy   = "Annex I Part II (2)"
	AnnexIPartIITesting  = "Annex I Part II (3)"
	AnnexIPartIIDisclose = "Annex I Part II (4)"
	AnnexIPartIICVD      = "Annex I Part II (5)"
	AnnexIPartIIContact  = "Annex I Part II (6)"
	AnnexIPartIIDistrib  = "Annex I Part II (7)"
	AnnexIPartIIPatches  = "Annex I Part II (8)"
	AnnexIIUserInfo      = "Annex II"
	AnnexIIIImportant    = "Annex III"
	AnnexIVCritical      = "Annex IV"
	AnnexVDoC            = "Annex V"
	AnnexVISimplifiedDoC = "Annex VI"
	AnnexVIITechDoc      = "Annex VII"
	AnnexVIIIModuleA     = "Annex VIII Part I (Module A)"
	AnnexVIIIModuleBC    = "Annex VIII Parts II-III (Modules B+C)"
	AnnexVIIIModuleH     = "Annex VIII Part IV (Module H)"

	RecitalSaaS = "Recital 12"
	RecitalOSS  = "Recitals 18-19"
)

// SRPPortalURL is the ENISA single reporting platform portal (Art. 16).
const SRPPortalURL = "https://portal.cra-srp.enisa.europa.eu/"

// SmallEnterpriseEarlyWarningNote: micro and small enterprises are not fined
// for missing only the 24-hour early-warning deadline (Art. 64(10)(a)); all
// other obligations and fines still apply.
const SmallEnterpriseEarlyWarningNote = "Microenterprises and small enterprises are not subject to fines for missing only the 24-hour early-warning deadline (Art. 14(2)(a) / Art. 14(4)(a)); all other obligations and fines apply."

// ReportingEndpointNote summarises Art. 14(7) on where to submit.
const ReportingEndpointNote = "Submit via the single reporting platform end-point of the CSIRT designated as coordinator in the Member State of the manufacturer's main establishment; a manufacturer without an EU establishment uses the Member State of its authorised representative, else the importer, else the distributor, else the Member State where most users are located."

// Reporting windows under Art. 14.
const (
	EarlyWarningWindow = 24 * time.Hour // Art. 14(2)(a), Art. 14(4)(a)
	NotificationWindow = 72 * time.Hour // Art. 14(2)(b), Art. 14(4)(b)
	// VulnFinalReportDays: final report no later than 14 days after a
	// corrective or mitigating measure is available (Art. 14(2)(c)).
	VulnFinalReportDays = 14
	// IncidentFinalReportMonths: final report within 1 month after the
	// incident notification under Art. 14(4)(b) (Art. 14(4)(c)).
	IncidentFinalReportMonths = 1
)

// Product class under Art. 7 / Annex III / Annex IV.
type Class string

const (
	ClassDefault     Class = "default"
	ClassImportantI  Class = "important-I"
	ClassImportantII Class = "important-II"
	ClassCritical    Class = "critical"
)

// Category is an Annex III / Annex IV product category.
type Category struct {
	Slug        string
	Description string
	Class       Class
	Citation    string
}

// Categories lists the Annex III (important, Class I and II) and Annex IV
// (critical) product categories by slug. "none" means no listed category.
var Categories = []Category{
	// Annex III Class I
	{"identity-management", "Identity management systems and privileged access management software and hardware, incl. authentication and access control readers", ClassImportantI, "Annex III Class I"},
	{"browser", "Standalone and embedded browsers", ClassImportantI, "Annex III Class I"},
	{"password-manager", "Password managers", ClassImportantI, "Annex III Class I"},
	{"anti-malware", "Software that searches for, removes or quarantines malicious software", ClassImportantI, "Annex III Class I"},
	{"vpn", "Products with digital elements with the function of virtual private network (VPN)", ClassImportantI, "Annex III Class I"},
	{"network-management", "Network management systems", ClassImportantI, "Annex III Class I"},
	{"siem", "Security information and event management (SIEM) systems", ClassImportantI, "Annex III Class I"},
	{"boot-manager", "Boot managers", ClassImportantI, "Annex III Class I"},
	{"pki", "Public key infrastructure and digital certificate issuance software", ClassImportantI, "Annex III Class I"},
	{"network-interface", "Physical and virtual network interfaces", ClassImportantI, "Annex III Class I"},
	{"operating-system", "Operating systems", ClassImportantI, "Annex III Class I"},
	{"router-modem-switch", "Routers, modems intended for the connection to the internet, and switches", ClassImportantI, "Annex III Class I"},
	{"secure-microprocessor", "Microprocessors, microcontrollers, ASICs and FPGAs with security-related functionalities", ClassImportantI, "Annex III Class I"},
	{"smart-home-assistant", "Smart home general purpose virtual assistants", ClassImportantI, "Annex III Class I"},
	{"smart-home-security", "Smart home products with security functionalities, incl. smart door locks, security cameras, baby monitoring systems and alarm systems", ClassImportantI, "Annex III Class I"},
	{"connected-toy", "Internet connected toys covered by Directive 2009/48/EC with social interactive features or location tracking", ClassImportantI, "Annex III Class I"},
	{"wearable-health", "Personal wearable products for health monitoring, or wearables intended for use by and for children", ClassImportantI, "Annex III Class I"},
	// Annex III Class II
	{"hypervisor-container-runtime", "Hypervisors and container runtime systems supporting virtualised execution of operating systems and similar environments", ClassImportantII, "Annex III Class II"},
	{"firewall-ids-ips", "Firewalls, intrusion detection and prevention systems", ClassImportantII, "Annex III Class II"},
	{"tamper-resistant-microprocessor", "Tamper-resistant microprocessors", ClassImportantII, "Annex III Class II"},
	{"tamper-resistant-microcontroller", "Tamper-resistant microcontrollers", ClassImportantII, "Annex III Class II"},
	// Annex IV critical
	{"security-box", "Hardware devices with security boxes", ClassCritical, "Annex IV"},
	{"smart-meter-gateway", "Smart meter gateways within smart metering systems and other devices for advanced security purposes, incl. secure cryptoprocessing", ClassCritical, "Annex IV"},
	{"smartcard-secure-element", "Smartcards or similar devices, incl. secure elements", ClassCritical, "Annex IV"},
}

// FindCategory returns the category for a slug, or false.
func FindCategory(slug string) (Category, bool) {
	for _, c := range Categories {
		if c.Slug == slug {
			return c, true
		}
	}
	return Category{}, false
}

// CategorySlugs returns all slugs in declaration order.
func CategorySlugs() []string {
	out := make([]string, 0, len(Categories))
	for _, c := range Categories {
		out = append(out, c.Slug)
	}
	return out
}

// Date parses one of the date constants (YYYY-MM-DD) into a UTC time.
func Date(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic("cra: bad date constant " + s)
	}
	return t.UTC()
}

// EssentialRequirements summarises Annex I Part I.
var EssentialRequirements = []string{
	"Annex I Part I (1): designed, developed and produced to ensure an appropriate level of cybersecurity based on the risks",
	"Annex I Part I (2): made available without known exploitable vulnerabilities",
	"Annex I Part I (2)(a): secure by default configuration, with the possibility to reset to the original state",
	"Annex I Part I (2)(b): security updates incl. automatic updates by default with a clear opt-out",
	"Annex I Part I (2)(c): protection from unauthorised access by appropriate control mechanisms (authentication, identity, access management)",
	"Annex I Part I (2)(d): confidentiality of stored, transmitted or processed data (encryption at rest and in transit)",
	"Annex I Part I (2)(e): integrity of data, commands, programs and configuration",
	"Annex I Part I (2)(f): data minimisation",
	"Annex I Part I (2)(g): availability of essential and basic functions, incl. resilience against denial of service",
	"Annex I Part I (2)(h): minimise negative impact on the availability of services provided by other devices or networks",
	"Annex I Part I (2)(i): limited attack surfaces, incl. external interfaces",
	"Annex I Part I (2)(j): reduce the impact of an incident using exploitation mitigation mechanisms",
	"Annex I Part I (2)(k): security-related information by recording and monitoring internal activity (logging), with opt-out",
	"Annex I Part I (2)(l): users can securely and easily remove all data and settings permanently, and transfer them",
}

// VulnerabilityHandlingRequirements summarises Annex I Part II.
var VulnerabilityHandlingRequirements = []string{
	"Annex I Part II (1): identify and document vulnerabilities and components, incl. an SBOM in a commonly used machine-readable format covering at least the top-level dependencies",
	"Annex I Part II (2): address and remediate vulnerabilities without delay, incl. by providing security updates",
	"Annex I Part II (3): apply effective and regular tests and reviews of the security of the product",
	"Annex I Part II (4): once a security update is available, publicly disclose information about fixed vulnerabilities (description, impact, severity, remediation)",
	"Annex I Part II (5): put in place and enforce a policy on coordinated vulnerability disclosure",
	"Annex I Part II (6): take measures to facilitate sharing of information about potential vulnerabilities, incl. a contact address for reporting",
	"Annex I Part II (7): mechanisms to securely distribute updates",
	"Annex I Part II (8): security patches or updates disseminated without delay and free of charge, with advisory messages",
}
