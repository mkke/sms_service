package main

import (
	"os"
	"strings"
)

// readSecret returns the content of the file name without its trailing
// newline, as an editor or a configuration template writes it. An empty name
// returns an empty secret, which is how a password stays unset. A file that
// cannot be read is an error.
func readSecret(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	data, err := os.ReadFile(name) // #nosec G304 -- the operator names the file on the command line
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(data), "\n"), nil
}
