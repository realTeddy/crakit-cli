// crakit is a self-serve EU Cyber Resilience Act (Regulation (EU) 2024/2847)
// kit for small makers of software and firmware products.
//
// This is a checklist and drafting aid, not legal advice and not a guarantee
// of compliance with Regulation (EU) 2024/2847.
package main

import (
	"os"

	"github.com/realTeddy/crakit-cli/internal/cmd"
)

func main() {
	fi, err := os.Stdin.Stat()
	isTTY := err == nil && fi.Mode()&os.ModeCharDevice != 0
	os.Exit(cmd.Run(os.Args[1:], cmd.Env{
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		StdinIsTerminal: isTTY,
	}))
}
