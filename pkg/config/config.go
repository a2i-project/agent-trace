// Package config reads config/agents.json, the record of the agent versions
// each adapter has been verified against (I-57) and, from schema 2, each
// agent's profile (I-77). An adapter's wrapper shapes, id families, harness
// hosts and version gates were measured on particular versions of the agent;
// a session of any other version may not fit them, silently. The file names,
// per adapter, the versions whose checked-in fixtures verify, so a tool can
// say when an agent is outside that set.
//
// The profile says how the agent is found, version-checked, locked, pinned,
// isolated, invoked and recorded. The capture scripts read all of it
// (scripts/agent-profile.py); this package reads the parts the Go tools use
// (the version command, the trace and the content methods) and checks those.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Schema is the newest version of the file format this build reads, and
// MinSchema the oldest: a schema 1 file lists versions and binaries only,
// which is all cmd/verify needs.
const (
	Schema    = 2
	MinSchema = 1
)

// EnvVar names the environment variable that overrides where the file is.
const EnvVar = "AGENT_TRACE_CONFIG"

// RelPath is where the file lives in the repository, and beside a binary
// that make build puts in the repository root.
const RelPath = "config/agents.json"

// ErrNotFound is returned by Locate when no explicit path is given and no
// file is found beside the executable or above the working directory.
var ErrNotFound = errors.New("no " + RelPath + " found (give --config or set " + EnvVar + ")")

// Version is one configured agent version.
type Version struct {
	// Version is what the agent's --version prints and its session records.
	Version string `json:"version"`
	// Verified is the date (YYYY-MM-DD) of the newest checked-in capture of
	// the version.
	Verified string `json:"verified"`
	// Fixtures are the fixture directories, relative to the repository root,
	// recorded with this version. Their tests are what verifies it.
	Fixtures []string `json:"fixtures"`
}

// Adapter is one adapter's entry: its versions and the parts of its profile
// the Go tools read.
type Adapter struct {
	// Binary is the agent's command, looked up on PATH by cmd/status.
	Binary string `json:"binary"`
	// VersionCommand is how the agent states its version; nil means
	// `<binary> --version`.
	VersionCommand *VersionCommand `json:"version_command,omitempty"`
	Versions       []Version       `json:"versions"`
	// Trace is where the capture scripts copy the agent's transcript.
	Trace *Trace `json:"trace,omitempty"`
	// Content lists the content-capture methods of the agent, by name.
	Content []ContentMethod `json:"content,omitempty"`
}

// VersionCommand is the arguments that make the agent print its version,
// and which word of the output is the version ("first" or "last") for the
// capture scripts; cmd/status takes the first version-shaped word instead.
type VersionCommand struct {
	Args  []string `json:"args"`
	Field string   `json:"field"`
}

// Trace is the profile's trace record. File and Subagents name the copies a
// capture makes, with {label} for the run's label.
type Trace struct {
	Method    string `json:"method"`
	Dir       string `json:"dir"`
	File      string `json:"file"`
	Subagents string `json:"subagents"`
	// Declared says the adapter declares its trace (I-74): the capture keeps
	// a run whose trace is gone as a result and verify compares the trace's
	// hash. It must agree with the adapter (agent.TraceDeclarer).
	Declared bool `json:"declared"`
	// StatesVersion says the format states the agent's version; otherwise
	// the capture passes it to verify.
	StatesVersion bool `json:"states_version"`
}

// ContentMethod is one content-capture method: a name the capture scripts
// map to code, and its parameters. "none" stands alone and carries the
// reason --content is refused.
type ContentMethod struct {
	Method  string `json:"method"`
	Library string `json:"library,omitempty"`
	Parser  string `json:"parser,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Note    string `json:"note,omitempty"`
}

// ContentNone is the content method of an agent without content capture.
const ContentNone = "none"

// TraceLabel is the placeholder of the run's label in Trace.File.
const TraceLabel = "{label}"

// Config is the whole file.
type Config struct {
	Schema   int                `json:"schema"`
	Adapters map[string]Adapter `json:"adapters"`
	// Path is the file the config was read from.
	Path string `json:"-"`
}

var versionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)

// Load reads and checks the file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse agent config %s: %w", path, err)
	}
	if c.Schema < MinSchema || c.Schema > Schema {
		return nil, fmt.Errorf("agent config %s: schema %d, this build reads %d to %d", path, c.Schema, MinSchema, Schema)
	}
	if len(c.Adapters) == 0 {
		return nil, fmt.Errorf("agent config %s: no adapters", path)
	}
	for name, a := range c.Adapters {
		if a.Binary == "" {
			return nil, fmt.Errorf("agent config %s: adapter %q has no binary", path, name)
		}
		if err := a.checkProfile(); err != nil {
			return nil, fmt.Errorf("agent config %s: adapter %q: %w", path, name, err)
		}
		seen := map[string]bool{}
		for _, v := range a.Versions {
			if !versionRE.MatchString(v.Version) {
				return nil, fmt.Errorf("agent config %s: adapter %q: %q is not a version", path, name, v.Version)
			}
			if seen[v.Version] {
				return nil, fmt.Errorf("agent config %s: adapter %q lists %s twice", path, name, v.Version)
			}
			seen[v.Version] = true
			if _, err := time.Parse(time.DateOnly, v.Verified); err != nil {
				return nil, fmt.Errorf("agent config %s: adapter %q version %s: verified %q is not a date (YYYY-MM-DD)", path, name, v.Version, v.Verified)
			}
			if len(v.Fixtures) == 0 {
				return nil, fmt.Errorf("agent config %s: adapter %q version %s names no fixture", path, name, v.Version)
			}
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	c.Path = abs
	return &c, nil
}

// checkProfile checks the parts of the profile this package reads, where
// they are given.
func (a Adapter) checkProfile() error {
	if vc := a.VersionCommand; vc != nil && vc.Field != "" && vc.Field != "first" && vc.Field != "last" {
		return fmt.Errorf("version_command.field %q is neither first nor last", vc.Field)
	}
	if t := a.Trace; t != nil {
		if t.Method == "" {
			return errors.New("trace names no method")
		}
		if !strings.Contains(t.File, TraceLabel) {
			return fmt.Errorf("trace.file %q does not hold %s", t.File, TraceLabel)
		}
	}
	for _, m := range a.Content {
		switch {
		case m.Method == "":
			return errors.New("a content method has no name")
		case m.Method == ContentNone && len(a.Content) > 1:
			return errors.New("content method none is combined with another")
		}
	}
	return nil
}

// VersionArgs are the arguments that make the agent print its version.
func (a Adapter) VersionArgs() []string {
	if a.VersionCommand == nil || len(a.VersionCommand.Args) == 0 {
		return []string{"--version"}
	}
	return a.VersionCommand.Args
}

// TraceFile is the name a capture gives the transcript of the run with this
// label, by the adapter's profile; ok is false when the profile names none.
func (c *Config) TraceFile(adapter, label string) (string, bool) {
	a, ok := c.Adapters[adapter]
	if !ok || a.Trace == nil {
		return "", false
	}
	return strings.ReplaceAll(a.Trace.File, TraceLabel, label), true
}

// Locate finds the file. An explicit path wins, then $AGENT_TRACE_CONFIG;
// either must exist. Otherwise it looks for config/agents.json beside the
// executable (where make build puts the binaries), then in the nearest
// directory at or above the working directory that holds both it and a
// go.mod (a checkout, which is where go run and go test start).
func Locate(explicit string) (string, error) {
	for _, p := range []string{explicit, os.Getenv(EnvVar)} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("agent config: %w", err)
		}
		return p, nil
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		if p := filepath.Join(filepath.Dir(exe), RelPath); isFile(p) {
			return p, nil
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", ErrNotFound
	}
	for {
		if p := filepath.Join(dir, RelPath); isFile(p) && isFile(filepath.Join(dir, "go.mod")) {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ErrNotFound
		}
		dir = parent
	}
}

// LoadDefault locates the file as Locate does and loads it.
func LoadDefault(explicit string) (*Config, error) {
	p, err := Locate(explicit)
	if err != nil {
		return nil, err
	}
	return Load(p)
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// Root is the repository root the fixture paths are relative to: the parent
// of the directory holding the file.
func (c *Config) Root() string {
	return filepath.Dir(filepath.Dir(c.Path))
}

// Has reports whether the adapter has an entry.
func (c *Config) Has(adapter string) bool {
	_, ok := c.Adapters[adapter]
	return ok
}

// Configured reports whether version is configured for adapter.
func (c *Config) Configured(adapter, version string) bool {
	for _, v := range c.Adapters[adapter].Versions {
		if v.Version == version {
			return true
		}
	}
	return false
}

// Versions lists the adapter's configured versions in file order.
func (c *Config) Versions(adapter string) []string {
	var out []string
	for _, v := range c.Adapters[adapter].Versions {
		out = append(out, v.Version)
	}
	return out
}

// Names lists the adapters with an entry, sorted.
func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Adapters))
	for n := range c.Adapters {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
