package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/realTeddy/crakit-cli/internal/incident"
)

func runIncident(e Env, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(e.Stdout, "Usage: crakit incident <new|status|update|draft|list> [flags]")
		fmt.Fprintln(e.Stdout, "  new     --kind vulnerability|incident --product NAME [--version V] [--title T] [--aware-at RFC3339]")
		fmt.Fprintln(e.Stdout, "  status  [id] [--now RFC3339]")
		fmt.Fprintln(e.Stdout, "  update  <id> [--fix-available-at RFC3339] [--note TEXT] [--status open|reported|closed] [--mark early_warning|notification|final_report [--at RFC3339]]")
		fmt.Fprintln(e.Stdout, "  draft   <id> --stage early_warning|notification|final_report")
		fmt.Fprintln(e.Stdout, "  list")
		fmt.Fprintln(e.Stdout, "Store: --store FILE, env CRAKIT_STORE, else $XDG_CONFIG_HOME/crakit/incidents.json")
		return 0
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "new":
		return incidentNew(e, rest)
	case "status":
		return incidentStatus(e, rest)
	case "update":
		return incidentUpdate(e, rest)
	case "draft":
		return incidentDraft(e, rest)
	case "list":
		return incidentList(e, rest)
	}
	return fail(e, "unknown incident subcommand %q (want new, status, update, draft or list)", sub)
}

func storePath(e Env, flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if p := e.env("CRAKIT_STORE"); p != "" {
		return p
	}
	return incident.DefaultStorePath()
}

func parseTime(s string) (time.Time, error) {
	if s == "" || s == "now" {
		return time.Now().UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q: want RFC 3339, e.g. 2026-10-25T14:30:00Z", s)
	}
	return t.UTC(), nil
}

func incidentNew(e Env, args []string) int {
	fs := newFlagSet(e, "incident new")
	store := fs.String("store", "", "store file")
	kind := fs.String("kind", "", "vulnerability (Art. 14(1)) | incident (Art. 14(3))")
	product := fs.String("product", "", "product name")
	version := fs.String("version", "", "product version(s)")
	title := fs.String("title", "", "short title")
	awareAt := fs.String("aware-at", "", "time you became aware, RFC 3339 (default now)")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	if len(pos) > 0 {
		return fail(e, "unexpected argument %q", pos[0])
	}
	aware, err := parseTime(*awareAt)
	if err != nil {
		return fail(e, "--aware-at: %v", err)
	}
	in, err := incident.New(incident.Kind(*kind), *product, *version, *title, aware)
	if err != nil {
		return fail(e, "%v", err)
	}
	s, err := incident.Load(storePath(e, *store))
	if err != nil {
		return fail(e, "%v", err)
	}
	s.Add(in)
	if err := s.Save(); err != nil {
		return fail(e, "%v", err)
	}
	fmt.Fprintf(e.Stdout, "created incident %s (stored in %s)\n\n", in.ID, s.Path)
	fmt.Fprint(e.Stdout, in.StatusText(time.Now().UTC()))
	return 0
}

func incidentStatus(e Env, args []string) int {
	fs := newFlagSet(e, "incident status")
	store := fs.String("store", "", "store file")
	nowS := fs.String("now", "", "evaluate deadlines as of this RFC 3339 time (default now)")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	now, err := parseTime(*nowS)
	if err != nil {
		return fail(e, "--now: %v", err)
	}
	s, err := incident.Load(storePath(e, *store))
	if err != nil {
		return fail(e, "%v", err)
	}
	if len(pos) == 0 {
		if len(s.Incidents) == 0 {
			fmt.Fprintln(e.Stdout, "no incidents recorded")
			return 0
		}
		for i, in := range s.Incidents {
			if i > 0 {
				fmt.Fprintln(e.Stdout, strings.Repeat("-", 72))
			}
			fmt.Fprint(e.Stdout, in.StatusText(now))
		}
		return 0
	}
	in, err := s.Get(pos[0])
	if err != nil {
		return fail(e, "%v", err)
	}
	fmt.Fprint(e.Stdout, in.StatusText(now))
	return 0
}

func incidentUpdate(e Env, args []string) int {
	fs := newFlagSet(e, "incident update")
	store := fs.String("store", "", "store file")
	fixAt := fs.String("fix-available-at", "", "RFC 3339 time a corrective or mitigating measure became available (starts the 14-day final-report clock, Art. 14(2)(c))")
	note := fs.String("note", "", "append a note")
	status := fs.String("status", "", "open|reported|closed")
	mark := fs.String("mark", "", "record a submission: early_warning|notification|final_report")
	at := fs.String("at", "", "submission time for --mark, RFC 3339 (default now)")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	if len(pos) != 1 {
		return fail(e, "usage: crakit incident update <id> [flags]")
	}
	s, err := incident.Load(storePath(e, *store))
	if err != nil {
		return fail(e, "%v", err)
	}
	in, err := s.Get(pos[0])
	if err != nil {
		return fail(e, "%v", err)
	}
	changed := false
	if *fixAt != "" {
		t, err := parseTime(*fixAt)
		if err != nil {
			return fail(e, "--fix-available-at: %v", err)
		}
		in.FixAvailableAt = &t
		changed = true
	}
	if *note != "" {
		in.Notes = append(in.Notes, incident.Note{At: time.Now().UTC(), Text: *note})
		changed = true
	}
	if *mark != "" {
		t, err := parseTime(*at)
		if err != nil {
			return fail(e, "--at: %v", err)
		}
		if err := in.Mark(incident.Stage(*mark), t); err != nil {
			return fail(e, "%v", err)
		}
		changed = true
	}
	if *status != "" {
		switch *status {
		case incident.StatusOpen, incident.StatusReported, incident.StatusClosed:
			in.Status = *status
			changed = true
		default:
			return fail(e, "--status must be open, reported or closed")
		}
	}
	if !changed {
		return fail(e, "nothing to update (use --fix-available-at, --note, --status or --mark)")
	}
	if err := s.Save(); err != nil {
		return fail(e, "%v", err)
	}
	fmt.Fprint(e.Stdout, in.StatusText(time.Now().UTC()))
	return 0
}

func incidentDraft(e Env, args []string) int {
	fs := newFlagSet(e, "incident draft")
	store := fs.String("store", "", "store file")
	stage := fs.String("stage", "", "early_warning|notification|final_report")
	nowS := fs.String("now", "", "RFC 3339 time for deadline display (default now)")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	if len(pos) != 1 {
		return fail(e, "usage: crakit incident draft <id> --stage <stage>")
	}
	now, err := parseTime(*nowS)
	if err != nil {
		return fail(e, "--now: %v", err)
	}
	s, err := incident.Load(storePath(e, *store))
	if err != nil {
		return fail(e, "%v", err)
	}
	in, err := s.Get(pos[0])
	if err != nil {
		return fail(e, "%v", err)
	}
	out, err := in.Draft(incident.Stage(*stage), now)
	if err != nil {
		return fail(e, "%v", err)
	}
	fmt.Fprint(e.Stdout, out)
	return 0
}

func incidentList(e Env, args []string) int {
	fs := newFlagSet(e, "incident list")
	store := fs.String("store", "", "store file")
	nowS := fs.String("now", "", "RFC 3339 time (default now)")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	if len(pos) > 0 {
		return fail(e, "unexpected argument %q", pos[0])
	}
	now, err := parseTime(*nowS)
	if err != nil {
		return fail(e, "--now: %v", err)
	}
	s, err := incident.Load(storePath(e, *store))
	if err != nil {
		return fail(e, "%v", err)
	}
	if len(s.Incidents) == 0 {
		fmt.Fprintln(e.Stdout, "no incidents recorded")
		return 0
	}
	fmt.Fprint(e.Stdout, incident.ListText(s.Incidents, now))
	return 0
}
