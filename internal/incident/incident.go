// Package incident keeps a local clock for Art. 14 reporting obligations of
// Regulation (EU) 2024/2847 and drafts submissions for the ENISA single
// reporting platform (Art. 16). All data stays on this machine.
package incident

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/realTeddy/crakit-cli/internal/cra"
)

// Kind of reportable event.
type Kind string

const (
	KindVulnerability Kind = "vulnerability" // Art. 14(1)-(2): actively exploited vulnerability
	KindIncident      Kind = "incident"      // Art. 14(3)-(4): severe incident
)

// Stage of reporting.
type Stage string

const (
	StageEarlyWarning Stage = "early_warning"
	StageNotification Stage = "notification"
	StageFinalReport  Stage = "final_report"
)

// Stages in order.
var Stages = []Stage{StageEarlyWarning, StageNotification, StageFinalReport}

// Status of the record.
const (
	StatusOpen     = "open"
	StatusReported = "reported"
	StatusClosed   = "closed"
)

// Incident is a stored record. All times are UTC.
type Incident struct {
	ID             string           `json:"id"`
	Kind           Kind             `json:"kind"`
	Product        string           `json:"product"`
	Version        string           `json:"version"`
	Title          string           `json:"title"`
	AwareAt        time.Time        `json:"aware_at"`
	FixAvailableAt *time.Time       `json:"fix_available_at,omitempty"`
	Submitted      map[Stage]string `json:"submitted,omitempty"` // RFC3339 UTC
	Status         string           `json:"status"`
	Notes          []Note           `json:"notes,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
}

// Note is a timestamped free-text note.
type Note struct {
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}

// New creates a record with a short random id.
func New(kind Kind, product, version, title string, awareAt time.Time) (*Incident, error) {
	if kind != KindVulnerability && kind != KindIncident {
		return nil, fmt.Errorf("kind must be %q or %q", KindVulnerability, KindIncident)
	}
	if product == "" {
		return nil, fmt.Errorf("product is required")
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &Incident{
		ID:        hex.EncodeToString(b[:]),
		Kind:      kind,
		Product:   product,
		Version:   version,
		Title:     title,
		AwareAt:   awareAt.UTC(),
		Submitted: map[Stage]string{},
		Status:    StatusOpen,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// SubmittedAt returns the recorded submission time for a stage.
func (in *Incident) SubmittedAt(s Stage) (time.Time, bool) {
	v, ok := in.Submitted[s]
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Mark records a submission.
func (in *Incident) Mark(s Stage, at time.Time) error {
	switch s {
	case StageEarlyWarning, StageNotification, StageFinalReport:
	default:
		return fmt.Errorf("unknown stage %q", s)
	}
	if in.Submitted == nil {
		in.Submitted = map[Stage]string{}
	}
	in.Submitted[s] = at.UTC().Format(time.RFC3339)
	if in.Status == StatusOpen {
		in.Status = StatusReported
	}
	return nil
}

// State of a deadline.
type State string

const (
	StatePending   State = "pending"
	StateSubmitted State = "submitted"
	StateOverdue   State = "overdue"
	StateNotYet    State = "not yet determinable"
)

// Deadline is one computed obligation.
type Deadline struct {
	Stage       Stage      `json:"stage"`
	Citation    string     `json:"citation"`
	Rule        string     `json:"rule"`
	Due         *time.Time `json:"due,omitempty"`
	Projected   bool       `json:"projected"`
	SubmittedAt *time.Time `json:"submitted_at,omitempty"`
	State       State      `json:"state"`
	Remaining   string     `json:"remaining"`
}

// Deadlines computes the Art. 14 deadlines relative to now.
func (in *Incident) Deadlines(now time.Time) []Deadline {
	now = now.UTC()
	var ds []Deadline
	ew := in.AwareAt.Add(cra.EarlyWarningWindow)
	nt := in.AwareAt.Add(cra.NotificationWindow)
	if in.Kind == KindVulnerability {
		ds = append(ds,
			Deadline{Stage: StageEarlyWarning, Citation: cra.ArtReportVulnEarlyWarning, Rule: "within 24 hours of becoming aware", Due: &ew},
			Deadline{Stage: StageNotification, Citation: cra.ArtReportVulnNotification, Rule: "within 72 hours of becoming aware", Due: &nt},
		)
		fr := Deadline{Stage: StageFinalReport, Citation: cra.ArtReportVulnFinalReport, Rule: "no later than 14 days after a corrective or mitigating measure is available"}
		if in.FixAvailableAt != nil {
			t := in.FixAvailableAt.UTC().AddDate(0, 0, cra.VulnFinalReportDays)
			fr.Due = &t
		}
		ds = append(ds, fr)
	} else {
		ds = append(ds,
			Deadline{Stage: StageEarlyWarning, Citation: cra.ArtReportIncEarlyWarning, Rule: "within 24 hours of becoming aware", Due: &ew},
			Deadline{Stage: StageNotification, Citation: cra.ArtReportIncNotification, Rule: "within 72 hours of becoming aware", Due: &nt},
		)
		fr := Deadline{Stage: StageFinalReport, Citation: cra.ArtReportIncFinalReport, Rule: "within 1 month after the incident notification under Art. 14(4)(b)"}
		if sub, ok := in.SubmittedAt(StageNotification); ok {
			t := sub.AddDate(0, cra.IncidentFinalReportMonths, 0)
			fr.Due = &t
		} else {
			t := nt.AddDate(0, cra.IncidentFinalReportMonths, 0)
			fr.Due = &t
			fr.Projected = true
		}
		ds = append(ds, fr)
	}
	for i := range ds {
		d := &ds[i]
		if sub, ok := in.SubmittedAt(d.Stage); ok {
			s := sub
			d.SubmittedAt = &s
			d.State = StateSubmitted
			if d.Due != nil && sub.After(*d.Due) {
				d.Remaining = "submitted " + humanDur(sub.Sub(*d.Due)) + " late"
			} else {
				d.Remaining = "submitted"
			}
			continue
		}
		if d.Due == nil {
			d.State = StateNotYet
			d.Remaining = "set --fix-available-at to start the 14-day clock"
			continue
		}
		if now.After(*d.Due) {
			d.State = StateOverdue
			d.Remaining = "overdue by " + humanDur(now.Sub(*d.Due))
		} else {
			d.State = StatePending
			d.Remaining = humanDur(d.Due.Sub(now)) + " left"
		}
	}
	return ds
}

func humanDur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	d = d.Round(time.Minute)
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, h, m)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// StatusText renders the status table.
func (in *Incident) StatusText(now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Incident %s  [%s]  %s\n", in.ID, in.Kind, in.Title)
	fmt.Fprintf(&b, "Product:  %s %s\n", in.Product, in.Version)
	fmt.Fprintf(&b, "Aware at: %s   Status: %s\n", fmtTime(in.AwareAt), in.Status)
	if in.FixAvailableAt != nil {
		fmt.Fprintf(&b, "Fix available at: %s\n", fmtTime(*in.FixAvailableAt))
	}
	fmt.Fprintf(&b, "Now:      %s\n\n", fmtTime(now))
	fmt.Fprintf(&b, "%-14s %-14s %-26s %-21s %s\n", "STAGE", "CITATION", "DUE (UTC)", "STATE", "REMAINING")
	for _, d := range in.Deadlines(now) {
		due := "-"
		if d.Due != nil {
			due = fmtTime(*d.Due)
			if d.Projected {
				due += " (projected)"
			}
		}
		fmt.Fprintf(&b, "%-14s %-14s %-26s %-21s %s\n", d.Stage, d.Citation, due, d.State, d.Remaining)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "User information duty: inform impacted users without undue delay, with corrective measures and mitigations [%s].\n", cra.ArtInformUsers)
	fmt.Fprintf(&b, "Where to submit: %s [%s, %s] %s\n", cra.ReportingEndpointNote, cra.ArtReportingEndpoint, cra.ArtSRP, cra.SRPPortalURL)
	fmt.Fprintf(&b, "Small enterprises: %s [%s]\n", cra.SmallEnterpriseEarlyWarningNote, cra.ArtSmallEnterpriseNoFine24)
	if in.AwareAt.Before(cra.Date(cra.ReportingApplies)) {
		fmt.Fprintf(&b, "Note: awareness predates %s, when Art. 14 starts to apply [%s]; ENISA has indicated such cases need not be reported retrospectively.\n", cra.ReportingApplies, cra.ArtApplication)
	}
	b.WriteString("\n" + cra.Disclaimer + "\n")
	return b.String()
}

func fmtTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// ListText renders all records as a table.
func ListText(all []*Incident, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-10s %-14s %-9s %-20s %-18s %s\n", "ID", "KIND", "STATUS", "AWARE (UTC)", "NEXT", "TITLE")
	sorted := append([]*Incident(nil), all...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].AwareAt.Before(sorted[j].AwareAt) })
	for _, in := range sorted {
		next := "-"
		for _, d := range in.Deadlines(now) {
			if d.State == StatePending || d.State == StateOverdue {
				next = string(d.Stage) + ": " + d.Remaining
				break
			}
		}
		fmt.Fprintf(&b, "%-10s %-14s %-9s %-20s %-18s %s\n", in.ID, in.Kind, in.Status, in.AwareAt.Format("2006-01-02 15:04"), next, in.Title)
	}
	b.WriteString("\n" + cra.Disclaimer + "\n")
	return b.String()
}
