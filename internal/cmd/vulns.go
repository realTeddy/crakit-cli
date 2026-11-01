package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/realTeddy/crakit-cli/internal/cra"
	"github.com/realTeddy/crakit-cli/internal/osv"
)

const vulnsNote = "Findings are from OSV.dev and are not a determination that a vulnerability is 'actively exploited' under Art. 14(1); that judgement is yours."

func runVulns(e Env, args []string) int {
	fs := newFlagSet(e, "vulns")
	asJSON := fs.Bool("json", false, "print findings as JSON")
	failOn := fs.String("fail-on", "none", "none|low|medium|high|critical: exit 1 if any finding is at or above")
	base := fs.String("osv-url", "", "OSV API base URL (default https://api.osv.dev; env CRAKIT_OSV_URL)")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	if len(pos) != 1 {
		return fail(e, "usage: crakit vulns <sbom.cdx.json>")
	}
	threshold, err := osv.ParseSeverity(*failOn)
	if err != nil {
		return fail(e, "%v", err)
	}
	if *base == "" {
		*base = e.env("CRAKIT_OSV_URL")
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return fail(e, "%v", err)
	}
	pkgs, err := osv.ParseCycloneDX(f)
	f.Close()
	if err != nil {
		return fail(e, "%v", err)
	}
	if len(pkgs) == 0 {
		return fail(e, "no components with a purl or name+version found in %s", pos[0])
	}
	c := osv.New(*base, Version)
	fmt.Fprintf(e.Stderr, "crakit vulns: querying %s for %d packages (package coordinates only)\n", c.BaseURL, len(pkgs))
	findings, err := c.Scan(context.Background(), pkgs)
	if err != nil {
		return fail(e, "%v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(e.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{"packages": len(pkgs), "findings": findings, "note": vulnsNote, "disclaimer": cra.Disclaimer})
		return osv.ExitCode(findings, threshold)
	}
	if len(findings) == 0 {
		fmt.Fprintf(e.Stdout, "No known vulnerabilities in OSV.dev for %d packages.\n\n%s\n%s\n", len(pkgs), vulnsNote, cra.Disclaimer)
		return 0
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "COMPONENT\tVULN\tALIASES\tSEVERITY\tFIXED IN\tSUMMARY")
	for _, f := range findings {
		fixed := "-"
		if len(f.FixedIn) > 0 {
			fixed = strings.Join(f.FixedIn, ", ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", f.Component, f.ID, strings.Join(f.Aliases, ","), f.Severity, fixed, f.Summary)
	}
	tw.Flush()
	fmt.Fprintf(e.Stdout, "\n%d finding(s) across %d packages.\n%s\n%s\n", len(findings), len(pkgs), vulnsNote, cra.Disclaimer)
	return osv.ExitCode(findings, threshold)
}
