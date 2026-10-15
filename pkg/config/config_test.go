package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "agents.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const valid = `{"schema":1,"adapters":{"a":{"binary":"a","versions":[{"version":"1.2.3","verified":"2026-10-15","fixtures":["x"]}]}}}`

func TestLoadChecksTheFile(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"valid", valid, ""},
		{"bad json", `{`, "parse agent config"},
		{"other schema", `{"schema":2,"adapters":{}}`, "schema 2"},
		{"no adapters", `{"schema":1,"adapters":{}}`, "no adapters"},
		{"no binary", `{"schema":1,"adapters":{"a":{"versions":[]}}}`, "no binary"},
		{"not a version", `{"schema":1,"adapters":{"a":{"binary":"a","versions":[{"version":"latest","verified":"2026-10-15","fixtures":["x"]}]}}}`, "not a version"},
		{"duplicate", `{"schema":1,"adapters":{"a":{"binary":"a","versions":[{"version":"1.0","verified":"2026-10-15","fixtures":["x"]},{"version":"1.0","verified":"2026-10-15","fixtures":["x"]}]}}}`, "twice"},
		{"bad date", `{"schema":1,"adapters":{"a":{"binary":"a","versions":[{"version":"1.0","verified":"15.10.2026","fixtures":["x"]}]}}}`, "not a date"},
		{"no fixture", `{"schema":1,"adapters":{"a":{"binary":"a","versions":[{"version":"1.0","verified":"2026-10-15"}]}}}`, "names no fixture"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(write(t, t.TempDir(), tc.body))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if !c.Configured("a", "1.2.3") || c.Configured("a", "1.2.4") || c.Configured("b", "1.2.3") || !c.Has("a") || c.Has("b") {
					t.Errorf("lookups wrong on %+v", c)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestLocateOrder: an explicit path wins over the environment, the
// environment over the search, and either must exist.
func TestLocateOrder(t *testing.T) {
	dir := t.TempDir()
	explicit := write(t, dir, valid)
	envDir := t.TempDir()
	env := write(t, envDir, valid)

	t.Setenv(EnvVar, env)
	if p, err := Locate(explicit); err != nil || p != explicit {
		t.Errorf("explicit: %q, %v", p, err)
	}
	if p, err := Locate(""); err != nil || p != env {
		t.Errorf("env: %q, %v", p, err)
	}
	t.Setenv(EnvVar, filepath.Join(envDir, "missing.json"))
	if _, err := Locate(""); err == nil {
		t.Error("a missing file named by the environment was accepted")
	}
	if _, err := Locate(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing explicit file was accepted")
	}
}

// TestLocateSearchesUpToACheckout: without a path, the nearest directory
// holding config/agents.json and go.mod is found from below it, and a
// directory with the file but no go.mod is not a checkout.
func TestLocateSearchesUpToACheckout(t *testing.T) {
	t.Setenv(EnvVar, "")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "config"), valid)
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(deep)
	if _, err := Locate(""); !errors.Is(err, ErrNotFound) {
		t.Errorf("without go.mod: err = %v, want ErrNotFound", err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Locate("")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(root); c.Root() != root && c.Root() != want {
		t.Errorf("Root() = %q, want %q", c.Root(), root)
	}
}
