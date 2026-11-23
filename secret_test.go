package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecret(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct {
		content string
		want    string
	}{
		"trailing newline": {"s3cret\n", "s3cret"},
		"no newline":       {"s3cret", "s3cret"},
		"only one newline": {"s3cret\n\n", "s3cret\n"},
		"empty file":       {"", ""},
		"space is kept":    {" s3cret \n", " s3cret "},
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readSecret(p)
		if err != nil || got != c.want {
			t.Errorf("%s: readSecret = %q, %v, want %q", name, got, err, c.want)
		}
	}
}

func TestReadSecretUnset(t *testing.T) {
	if got, err := readSecret(""); err != nil || got != "" {
		t.Errorf("readSecret(\"\") = %q, %v", got, err)
	}
}

func TestReadSecretMissingFile(t *testing.T) {
	if _, err := readSecret(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file gave no error")
	}
}
