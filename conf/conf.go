// Package conf contains settings
package conf

import (
	"flag"

	"github.com/m-lab/go/flagx"
)

var (
	// Patterns is the list of strings to censor
	Patterns flagx.StringArray
)

func init() {
	flag.Var(&Patterns, "censor", "Add a string to censor")
}
