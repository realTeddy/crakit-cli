package scope

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/realTeddy/crakit-cli/internal/cra"
)

// Interactive fills the missing fields of in by asking numbered questions on
// w and reading answers from r. Fields already set are not asked again.
func Interactive(in Input, r io.Reader, w io.Writer) (Input, error) {
	br := bufio.NewReader(r)
	ask := func(prompt string, opts []string, cur string) (string, error) {
		if oneOf(cur, opts) {
			return cur, nil
		}
		for {
			fmt.Fprintf(w, "\n%s\n", prompt)
			for i, o := range opts {
				fmt.Fprintf(w, "  %d) %s\n", i+1, o)
			}
			fmt.Fprint(w, "> ")
			line, err := br.ReadString('\n')
			if err != nil && line == "" {
				return "", fmt.Errorf("input ended before question %q was answered", prompt)
			}
			line = strings.TrimSpace(line)
			if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(opts) {
				return opts[n-1], nil
			}
			if oneOf(line, opts) {
				return line, nil
			}
			fmt.Fprintln(w, "Please enter a number from the list.")
		}
	}
	yn := []string{Yes, No}
	var err error
	if in.ProductType, err = ask("What kind of product is it? (Art. 3(1))", ProductTypes, in.ProductType); err != nil {
		return in, err
	}
	if in.ProductType == TypeSaaS {
		if in.RemoteProcessingEssential, err = ask("Is the remote processing essential, i.e. without it a product you ship cannot perform one of its functions? (Art. 3(2), Recital 12)", yn, in.RemoteProcessingEssential); err != nil {
			return in, err
		}
	}
	if in.Connected, err = ask("Does its intended or reasonably foreseeable use include a direct or indirect data connection to a device or network? (Art. 2(1))", yn, in.Connected); err != nil {
		return in, err
	}
	if in.Commercial, err = ask("Is it made available on the EU market in the course of a commercial activity? (Art. 3(22), Recital 18)", yn, in.Commercial); err != nil {
		return in, err
	}
	if in.OpenSource, err = ask("Is it free and open-source software? (Recitals 18-19)", yn, in.OpenSource); err != nil {
		return in, err
	}
	if in.OpenSource == Yes {
		if in.OSSMonetised, err = ask("Is the open-source product monetised (charging for it, paid support beyond cost recovery, commercial use with support as the business)? (Recital 18)", yn, in.OSSMonetised); err != nil {
			return in, err
		}
	}
	if in.ExcludedSector, err = ask("Is it covered by one of the excluded sectoral regimes? (Art. 2(2)-(7))", Sectors, in.ExcludedSector); err != nil {
		return in, err
	}
	cats := append([]string{"none"}, cra.CategorySlugs()...)
	if in.Category, err = ask("Does it fall into an Annex III (important) or Annex IV (critical) category?", cats, in.Category); err != nil {
		return in, err
	}
	if in.Role, err = ask("What is your role? (Art. 3(13), Art. 19, Art. 20, Art. 22)", Roles, in.Role); err != nil {
		return in, err
	}
	return in, nil
}
