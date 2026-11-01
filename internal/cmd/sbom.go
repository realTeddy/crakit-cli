package cmd

import (
	"fmt"
	"os"

	"github.com/realTeddy/crakit-cli/internal/sbom"
)

func runSBOM(e Env, args []string) int {
	fs := newFlagSet(e, "sbom")
	var opts sbom.Options
	out := fs.String("o", "", "output file (default stdout)")
	fs.StringVar(&opts.Name, "name", "", "root component name (default: directory name)")
	fs.StringVar(&opts.Version, "version", "", "root component version")
	fs.BoolVar(&opts.IncludeIndirect, "include-indirect", false, "include transitive dependencies (Annex I Part II (1) requires at least top-level)")
	tool := fs.String("tool", sbom.ToolAuto, "auto|builtin|syft|cdxgen")
	pos, ok, code := parse(fs, args)
	if !ok {
		return code
	}
	dir := "."
	if len(pos) > 0 {
		dir = pos[0]
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fail(e, "%s is not a directory", dir)
	}
	chosen, err := sbom.DetectTool(*tool)
	if err != nil {
		return fail(e, "%v", err)
	}
	var data []byte
	if chosen == sbom.ToolBuiltin {
		b, err := sbom.Generate(dir, opts)
		if err != nil {
			return fail(e, "%v", err)
		}
		data, err = b.JSON()
		if err != nil {
			return fail(e, "%v", err)
		}
		data = append(data, '\n')
		fmt.Fprintf(e.Stderr, "crakit sbom: built-in generator, %d components\n", len(b.Components))
	} else {
		fmt.Fprintf(e.Stderr, "crakit sbom: using %s\n", chosen)
		data, err = sbom.RunExternal(chosen, dir)
		if err != nil {
			return fail(e, "%v", err)
		}
	}
	if *out == "" {
		_, err = e.Stdout.Write(data)
	} else {
		err = os.WriteFile(*out, data, 0o644)
	}
	if err != nil {
		return fail(e, "%v", err)
	}
	return 0
}
