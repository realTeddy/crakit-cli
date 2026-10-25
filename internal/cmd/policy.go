package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/realTeddy/crakit/cli/internal/policy"
)

func runPolicy(e Env, args []string) int {
	fs := newFlagSet(e, "policy")
	var o policy.Options
	var contacts multiFlag
	var expires string
	fs.StringVar(&o.Org, "org", "", "organisation name")
	fs.Var(&contacts, "contact", "contact URI (mailto:, https:// or tel:), repeatable, in order of preference")
	fs.StringVar(&o.URL, "url", "", "product or organisation URL")
	fs.StringVar(&o.PolicyURL, "policy-url", "", "URL where the CVD policy is published (security.txt Policy:)")
	fs.StringVar(&o.Encryption, "encryption", "", "URL of the PGP key (security.txt Encryption:)")
	fs.StringVar(&o.Languages, "languages", "", "comma-separated preferred languages, e.g. en,de")
	fs.StringVar(&o.AcknowledgmentsURL, "acknowledgments-url", "", "URL of the acknowledgments page")
	fs.StringVar(&expires, "expires", "", "security.txt Expires (RFC 3339 UTC, e.g. 2027-10-24T00:00:00.000Z); default one year minus a day from now")
	fs.StringVar(&o.Canonical, "canonical", "", "canonical https:// URL of the security.txt")
	fs.StringVar(&o.Hiring, "hiring", "", "security hiring URL (optional)")
	fs.IntVar(&o.AckDays, "ack-days", 5, "business days within which reports are acknowledged")
	fs.IntVar(&o.DisclosureDays, "disclosure-days", 90, "requested days before public disclosure")
	outDir := fs.String("out-dir", "", "write SECURITY.md and .well-known/security.txt here instead of printing")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	if len(pos) > 0 {
		return fail(e, "unexpected argument %q", pos[0])
	}
	o.Contacts = contacts
	if expires != "" {
		t, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			return fail(e, "--expires: %v", err)
		}
		o.Expires = t.UTC()
	}
	md, err := policy.Markdown(o)
	if err != nil {
		return fail(e, "%v", err)
	}
	st, err := policy.SecurityTxt(o)
	if err != nil {
		return fail(e, "%v", err)
	}
	if *outDir == "" {
		fmt.Fprint(e.Stdout, md)
		fmt.Fprintln(e.Stdout, "\n---- .well-known/security.txt ----")
		fmt.Fprint(e.Stdout, st)
		return 0
	}
	if err := os.MkdirAll(filepath.Join(*outDir, ".well-known"), 0o755); err != nil {
		return fail(e, "%v", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "SECURITY.md"), []byte(md), 0o644); err != nil {
		return fail(e, "%v", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, ".well-known", "security.txt"), []byte(st), 0o644); err != nil {
		return fail(e, "%v", err)
	}
	fmt.Fprintf(e.Stdout, "wrote %s and %s\n", filepath.Join(*outDir, "SECURITY.md"), filepath.Join(*outDir, ".well-known", "security.txt"))
	return 0
}
