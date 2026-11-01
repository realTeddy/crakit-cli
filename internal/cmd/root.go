// Package cmd wires the crakit subcommands using the standard library flag
// package. Run is the testable entrypoint.
package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/realTeddy/crakit-cli/internal/cra"
	"github.com/realTeddy/crakit-cli/internal/sbom"
)

// Version is set at build time with -ldflags "-X .../internal/cmd.Version=x".
var Version = "0.1.0"

// Env abstracts process I/O for tests.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// StdinIsTerminal reports whether interactive prompts are possible.
	StdinIsTerminal bool
	// Getenv lets tests inject environment.
	Getenv func(string) string
}

func (e Env) env(k string) string {
	if e.Getenv != nil {
		return e.Getenv(k)
	}
	return os.Getenv(k)
}

type command struct {
	name    string
	summary string
	run     func(e Env, args []string) int
}

var commands []command

func init() {
	commands = []command{
		{"scope", "CRA scope questionnaire: is your product in scope, which class, which obligations", runScope},
		{"sbom", "Generate a CycloneDX 1.6 SBOM from lockfiles (or via syft/cdxgen if installed)", runSBOM},
		{"vulns", "Query OSV.dev for known vulnerabilities in a CycloneDX SBOM (the only network call)", runVulns},
		{"policy", "Draft a coordinated vulnerability disclosure policy and RFC 9116 security.txt", runPolicy},
		{"incident", "Local Art. 14 reporting clock: new | status | update | draft | list", runIncident},
		{"version", "Print the crakit version", runVersion},
	}
}

// Run executes crakit with args (excluding the program name) and returns the
// exit code.
func Run(args []string, e Env) int {
	sbom.ToolVersion = Version
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		usage(e.Stdout)
		return 0
	}
	if args[0] == "--version" {
		return runVersion(e, nil)
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(e, args[1:])
		}
	}
	fmt.Fprintf(e.Stderr, "crakit: unknown command %q\n\n", args[0])
	usage(e.Stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "crakit %s - self-serve EU Cyber Resilience Act (%s) kit for small makers\n\n", Version, cra.Regulation)
	fmt.Fprintln(w, "Usage: crakit <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'crakit <command> -h' for flags. Nothing leaves your machine except OSV.dev queries by package coordinates when you run 'crakit vulns'.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, cra.Disclaimer)
}

func runVersion(e Env, _ []string) int {
	fmt.Fprintf(e.Stdout, "crakit %s\n", Version)
	return 0
}

// newFlagSet creates a flag set that writes to e.Stderr and never exits.
func newFlagSet(e Env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet("crakit "+name, flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	return fs
}

// parse parses flags, allowing flags and positional arguments to be
// interspersed (stdlib flag stops at the first positional). It returns the
// positional arguments; ok is false (with usage printed) on error or -h.
func parse(fs *flag.FlagSet, args []string) (positional []string, ok bool, exit int) {
	for {
		if err := fs.Parse(args); err != nil {
			if err == flag.ErrHelp {
				return nil, false, 0
			}
			return nil, false, 2
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, true, 0
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func fail(e Env, format string, args ...any) int {
	fmt.Fprintf(e.Stderr, "crakit: "+format+"\n", args...)
	return 1
}

// multiFlag collects repeatable string flags.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
