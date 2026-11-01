package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/realTeddy/crakit-cli/internal/cra"
	"github.com/realTeddy/crakit-cli/internal/scope"
)

func runScope(e Env, args []string) int {
	fs := newFlagSet(e, "scope")
	var in scope.Input
	var asJSON bool
	fs.StringVar(&in.ProductType, "product-type", "", "software|hardware|firmware|saas|component (Art. 3(1))")
	fs.StringVar(&in.Connected, "connected", "", "yes|no: data connection to a device or network (Art. 2(1))")
	fs.StringVar(&in.Commercial, "commercial", "", "yes|no: made available in the course of a commercial activity")
	fs.StringVar(&in.OpenSource, "open-source", "", "yes|no: free and open-source software (Recitals 18-19)")
	fs.StringVar(&in.OSSMonetised, "oss-monetised", "", "yes|no: open-source product is monetised (required if --open-source yes)")
	fs.StringVar(&in.RemoteProcessingEssential, "remote-processing-essential", "", "yes|no: for saas, is remote processing essential to a product function (Art. 3(2))")
	fs.StringVar(&in.ExcludedSector, "excluded-sector", "", "none|medical|automotive|aviation|marine|defence (Art. 2(2)-(7))")
	fs.StringVar(&in.Category, "category", "", "Annex III/IV category slug or 'none' (see --list-categories)")
	fs.StringVar(&in.Role, "role", "", "manufacturer|importer|distributor|modifier")
	fs.StringVar(&in.PlacedAfter, "placed-after", "", "optional YYYY-MM-DD date the product is first placed on the market")
	fs.BoolVar(&asJSON, "json", false, "print the verdict as JSON")
	listCats := fs.Bool("list-categories", false, "list Annex III/IV category slugs and exit")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	if len(pos) > 0 {
		return fail(e, "unexpected argument %q", pos[0])
	}
	if *listCats {
		for _, c := range cra.Categories {
			fmt.Fprintf(e.Stdout, "%-34s %-13s %s  [%s]\n", c.Slug, c.Class, c.Description, c.Citation)
		}
		return 0
	}
	if missing := in.Missing(); len(missing) > 0 {
		if !e.StdinIsTerminal {
			return fail(e, "missing or invalid flags: --%s (stdin is not a terminal, so the interactive questionnaire is unavailable)", strings.Join(missing, ", --"))
		}
		var err error
		in, err = scope.Interactive(in, e.Stdin, e.Stdout)
		if err != nil {
			return fail(e, "%v", err)
		}
		if missing := in.Missing(); len(missing) > 0 {
			return fail(e, "still missing: --%s", strings.Join(missing, ", --"))
		}
		fmt.Fprintln(e.Stdout)
	}
	v := scope.Evaluate(in)
	if asJSON {
		enc := json.NewEncoder(e.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return fail(e, "%v", err)
		}
		return 0
	}
	fmt.Fprint(e.Stdout, v.Text())
	return 0
}
