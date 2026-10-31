package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/agent"
	_ "github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	_ "github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/config"
)

func repoConfig(t *testing.T) *config.Config {
	t.Helper()
	c, err := config.Load(filepath.Join("..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestEveryAdapterInTheConfigIsRegistered: an entry for an adapter that does
// not exist would configure nothing, unless it lists no version: the profile
// of an agent captured before its adapter is built (Codex, I-79), which only
// the capture scripts read.
func TestEveryAdapterInTheConfigIsRegistered(t *testing.T) {
	c := repoConfig(t)
	for _, name := range c.Names() {
		if _, ok := agent.Lookup(name); !ok && len(c.Adapters[name].Versions) > 0 {
			t.Errorf("config lists versions of adapter %q, which is not registered (%v)", name, agent.Names())
		}
	}
	for _, name := range agent.Names() {
		if name != agent.GenericName && !c.Has(name) {
			t.Errorf("adapter %q has no entry in %s", name, config.RelPath)
		}
	}
}

// TestEveryProfileAgreesWithItsAdapter: the repository's config is schema 2,
// every profile has a trace file and a content method, and a profile
// declares its trace exactly when its adapter, if built, does (I-74): the
// capture script keeps a run whose declared trace is gone and asks verify to
// compare the trace's hash on the profile's word alone.
func TestEveryProfileAgreesWithItsAdapter(t *testing.T) {
	c := repoConfig(t)
	if c.Schema != config.Schema {
		t.Fatalf("%s is schema %d, want %d", config.RelPath, c.Schema, config.Schema)
	}
	for _, name := range c.Names() {
		p := c.Adapters[name]
		if p.Trace == nil || p.Trace.File == "" {
			t.Errorf("%s: the profile names no trace file", name)
			continue
		}
		if len(p.Content) == 0 {
			t.Errorf("%s: the profile names no content method (none, if it has none)", name)
		}
		a, ok := agent.Lookup(name)
		if !ok {
			continue // a profile without an adapter (I-79); its adapter must agree once built
		}
		_, declares := a.(agent.TraceDeclarer)
		if p.Trace.Declared != declares {
			t.Errorf("%s: the profile's trace.declared is %v, the adapter declares its trace: %v", name, p.Trace.Declared, declares)
		}
	}
}

// TestEveryListedFixtureHasItsVersion: each fixture a version names exists
// and was recorded by that version. A Claude Code session states its version
// on every record, and the adapter reports it; every transcript in the
// fixture, subagents included, must agree. An agy conversation states none
// (I-57), so a Gemini fixture is checked by its name, which the capture gave
// it from agy --version, and by the adapter reading it.
func TestEveryListedFixtureHasItsVersion(t *testing.T) {
	c := repoConfig(t)
	for _, name := range c.Names() {
		a, ok := agent.Lookup(name)
		if !ok {
			continue
		}
		for _, v := range c.Adapters[name].Versions {
			for _, f := range v.Fixtures {
				dir := filepath.Join(c.Root(), f)
				if st, err := os.Stat(dir); err != nil || !st.IsDir() {
					t.Errorf("%s %s: fixture %s is not a directory (%v)", name, v.Version, f, err)
					continue
				}
				switch name {
				case "claude-code":
					checkClaudeCodeFixture(t, a, dir, v.Version)
				case "gemini":
					checkGeminiFixture(t, a, dir, v.Version)
				default:
					t.Errorf("no version check for adapter %q: add one here", name)
				}
			}
		}
	}
}

func checkClaudeCodeFixture(t *testing.T, a agent.Adapter, dir, version string) {
	t.Helper()
	sessions, _ := filepath.Glob(filepath.Join(dir, "*.session.jsonl"))
	if len(sessions) == 0 {
		t.Errorf("%s: no *.session.jsonl", dir)
	}
	for _, s := range sessions {
		_, rep, err := a.Parse(s)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		if rep.AgentVersion != version {
			t.Errorf("%s: the adapter reports version %q, the config says %s", s, rep.AgentVersion, version)
		}
	}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jsonl") {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var rec struct {
				Version *string `json:"version"`
			}
			if json.Unmarshal([]byte(line), &rec) == nil && rec.Version != nil && *rec.Version != version {
				t.Errorf("%s:%d: version %q, the config says %s", p, i+1, *rec.Version, version)
				return nil // one line per file is enough
			}
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func checkGeminiFixture(t *testing.T, a agent.Adapter, dir, version string) {
	t.Helper()
	if !strings.Contains(filepath.Base(dir), "agy-"+version) {
		t.Errorf("%s: the name does not say agy-%s", dir, version)
	}
	dbs, _ := filepath.Glob(filepath.Join(dir, "*.conversation.db"))
	if len(dbs) == 0 {
		t.Errorf("%s: no *.conversation.db", dir)
	}
	for _, db := range dbs {
		_, rep, err := a.Parse(db)
		if err != nil {
			t.Errorf("%s: %v", db, err)
			continue
		}
		if rep.AgentVersion != "" && rep.AgentVersion != version {
			t.Errorf("%s: the adapter reports version %q, the config says %s", db, rep.AgentVersion, version)
		}
	}
}

var versionInName = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`)

// TestEveryVersionedFixtureIsListed: a fixture directory whose name carries a
// version is listed under that version, so a new capture checked in as a
// fixture cannot be forgotten in the config, and a fixture cannot be listed
// under another version than its name says.
func TestEveryVersionedFixtureIsListed(t *testing.T) {
	c := repoConfig(t)
	listed := map[string]string{}
	for _, name := range c.Names() {
		for _, v := range c.Adapters[name].Versions {
			for _, f := range v.Fixtures {
				listed[filepath.ToSlash(filepath.Clean(f))] = v.Version
			}
		}
	}
	dirs, _ := filepath.Glob(filepath.Join(c.Root(), "pkg", "agent", "*", "testdata", "*"))
	sort.Strings(dirs)
	n := 0
	for _, d := range dirs {
		st, err := os.Stat(d)
		if err != nil || !st.IsDir() {
			continue
		}
		want := versionInName.FindString(filepath.Base(d))
		if want == "" {
			continue
		}
		n++
		rel, _ := filepath.Rel(c.Root(), d)
		rel = filepath.ToSlash(rel)
		got, ok := listed[rel]
		switch {
		case !ok:
			t.Errorf("fixture %s (version %s) is not listed in %s", rel, want, config.RelPath)
		case got != want:
			t.Errorf("fixture %s is listed under %s, its name says %s", rel, got, want)
		}
	}
	if n == 0 {
		t.Fatal("found no versioned fixture directory: the glob is wrong")
	}
}
