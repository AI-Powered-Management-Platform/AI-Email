package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/console"
)

// runConsolePassword hashes a password for the console.
//
// The password is taken as a flag rather than prompted because this runs in
// setup scripts as often as by hand. It is never stored by us: the operator
// puts the hash in their environment, and we keep no copy.
func runConsolePassword(args []string) error {
	fs := flag.NewFlagSet("console password", flag.ContinueOnError)
	password := fs.String("password", "", "console password, at least 12 characters")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*password) == "" {
		return fmt.Errorf("-password is required")
	}

	hash, err := console.HashPassword(*password)
	if err != nil {
		return err
	}

	fmt.Printf(`AIEMAIL_CONSOLE_PASSWORD_HASH=%s

Set this in the environment to enable the console at /console. Without it the
console is not served at all.

`, hash)
	return nil
}
