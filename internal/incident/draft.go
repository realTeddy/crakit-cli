package incident

import (
	"fmt"
	"strings"
	"time"

	"github.com/realTeddy/crakit/cli/internal/cra"
)

// DraftHeader is printed at the top of every draft.
const DraftHeader = "Draft for submission via the ENISA Single Reporting Platform (Art. 16). The manufacturer submits this; crakit does not."

const todo = "[TODO]"

// Draft renders an SRP-ready Markdown draft for a stage, with the fields the
// Regulation lists for that stage (Art. 14(2) / Art. 14(4)).
func (in *Incident) Draft(stage Stage, now time.Time) (string, error) {
	var cite, title string
	switch {
	case in.Kind == KindVulnerability && stage == StageEarlyWarning:
		cite, title = cra.ArtReportVulnEarlyWarning, "Early warning - actively exploited vulnerability"
	case in.Kind == KindVulnerability && stage == StageNotification:
		cite, title = cra.ArtReportVulnNotification, "Vulnerability notification"
	case in.Kind == KindVulnerability && stage == StageFinalReport:
		cite, title = cra.ArtReportVulnFinalReport, "Final report - actively exploited vulnerability"
	case in.Kind == KindIncident && stage == StageEarlyWarning:
		cite, title = cra.ArtReportIncEarlyWarning, "Early warning - severe incident"
	case in.Kind == KindIncident && stage == StageNotification:
		cite, title = cra.ArtReportIncNotification, "Incident notification"
	case in.Kind == KindIncident && stage == StageFinalReport:
		cite, title = cra.ArtReportIncFinalReport, "Final report - severe incident"
	default:
		return "", fmt.Errorf("unknown stage %q (want early_warning, notification or final_report)", stage)
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# %s (%s)", title, cite)
	w("")
	w("> %s", DraftHeader)
	w("> Portal: %s", cra.SRPPortalURL)
	w("> %s", cra.Disclaimer)
	w("")
	var due string
	for _, d := range in.Deadlines(now) {
		if d.Stage == stage && d.Due != nil {
			due = fmtTime(*d.Due)
			if d.Projected {
				due += " (projected)"
			}
		}
	}
	w("## Identification")
	w("")
	w("- Local reference: %s", in.ID)
	w("- Manufacturer: %s", todo)
	w("- Manufacturer contact (single point of contact, %s): %s", cra.ArtSinglePointOfContact, todo)
	w("- Member State of main establishment / CSIRT coordinator end-point (%s): %s", cra.ArtReportingEndpoint, todo)
	w("- Product: %s", orTodo(in.Product))
	w("- Version(s) affected: %s", orTodo(in.Version))
	w("- Title: %s", orTodo(in.Title))
	w("- Became aware at: %s", fmtTime(in.AwareAt))
	if due != "" {
		w("- Submission deadline: %s [%s]", due, cite)
	}
	w("- Submitted to ENISA / CSIRT coordinator at: %s", submittedOrTodo(in, stage))
	w("")
	switch {
	case in.Kind == KindVulnerability && stage == StageEarlyWarning:
		w("## Early warning content (%s)", cite)
		w("")
		w("- Indication that the vulnerability is actively exploited: %s (describe the evidence of exploitation)", todo)
		w("- Member States in which the product is known to be made available: %s", todo)
		w("- Brief description of the vulnerability: %s", todo)
		w("- Preliminary severity / impact: %s", todo)
	case in.Kind == KindVulnerability && stage == StageNotification:
		w("## Vulnerability notification content (%s)", cite)
		w("")
		w("- General information about the product with digital elements concerned: %s %s", orTodo(in.Product), in.Version)
		w("- General information about the nature of the exploit and of the vulnerability concerned: %s", todo)
		w("- Severity and impact: %s", todo)
		w("- Corrective or mitigating measures taken: %s", todo)
		w("- Corrective or mitigating measures that users can take: %s", todo)
		w("- Sensitivity indication (whether the information is considered sensitive): %s", todo)
	case in.Kind == KindVulnerability && stage == StageFinalReport:
		w("## Final report content (%s)", cite)
		w("")
		w("- Detailed description of the vulnerability, including its severity and impact: %s", todo)
		w("- Information concerning any malicious actor that has exploited or is exploiting the vulnerability, where available: %s", todo)
		w("- Details about the security update or other corrective measures made available to remedy the vulnerability: %s", todo)
		w("- Corrective or mitigating measure available since: %s", fixOrTodo(in))
		w("- Public advisory published (%s): %s", cra.AnnexIPartIIDisclose, todo)
	case in.Kind == KindIncident && stage == StageEarlyWarning:
		w("## Early warning content (%s)", cite)
		w("")
		w("- Indication of whether the incident is suspected to be caused by unlawful or malicious acts: %s", todo)
		w("- Member States in which the product is known to be made available: %s", todo)
		w("- Brief description of the incident and its impact on the security of the product: %s", todo)
	case in.Kind == KindIncident && stage == StageNotification:
		w("## Incident notification content (%s)", cite)
		w("")
		w("- General information about the nature of the incident: %s", todo)
		w("- Initial assessment of the incident: %s", todo)
		w("- Corrective or mitigating measures taken: %s", todo)
		w("- Corrective or mitigating measures that users can take: %s", todo)
		w("- Sensitivity indication: %s", todo)
	case in.Kind == KindIncident && stage == StageFinalReport:
		w("## Final report content (%s)", cite)
		w("")
		w("- Detailed description of the incident, including its severity and impact: %s", todo)
		w("- Type of threat or root cause likely to have triggered the incident: %s", todo)
		w("- Applied and ongoing mitigation measures: %s", todo)
		w("- Notification under Art. 14(4)(b) submitted at: %s", submittedOrTodo(in, StageNotification))
	}
	w("")
	w("## User information (%s)", cra.ArtInformUsers)
	w("")
	w("- Impacted users informed at: %s", todo)
	w("- Channel and content (corrective measures / mitigations): %s", todo)
	if len(in.Notes) > 0 {
		w("")
		w("## Internal notes (not for submission)")
		w("")
		for _, n := range in.Notes {
			w("- %s: %s", fmtTime(n.At), n.Text)
		}
	}
	w("")
	w("---")
	w("")
	w("_%s_", cra.Disclaimer)
	return b.String(), nil
}

func orTodo(s string) string {
	if s == "" {
		return todo
	}
	return s
}

func submittedOrTodo(in *Incident, s Stage) string {
	if t, ok := in.SubmittedAt(s); ok {
		return fmtTime(t)
	}
	return todo
}

func fixOrTodo(in *Incident) string {
	if in.FixAvailableAt != nil {
		return fmtTime(*in.FixAvailableAt)
	}
	return todo + " (record with: crakit incident update <id> --fix-available-at <RFC3339>)"
}
