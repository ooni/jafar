// Package shellx allows to run commands
package shellx

import (
	"os"
	"os/exec"
	"strings"

	"github.com/apex/log"
)

// Run executes the specified command with the specified args
func Run(name string, arg ...string) error {
	log.Infof("exec: %s %s", name, strings.Join(arg, " "))
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	log.Infof("exec result: %+v", err)
	return err
}
