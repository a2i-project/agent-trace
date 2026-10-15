package claudecode

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/config"
)

// gatedNotConfigured are versions in harnessReadVersions that config/agents.json
// does not list, each with why. I-46 read the harness's parser from the
// binary's strings, which is a weaker check than a capture; no capture of
// 2.1.284 is checked in, so it is gated but not configured (I-57).
var gatedNotConfigured = map[string]string{
	"2.1.284": "binary strings read for I-46, no checked-in capture",
}

// TestVersionGatesAgreeWithTheConfig ties the adapter's version-specific code
// to config/agents.json (I-57): every configured version has I-46's harness
// read, the version the file-tool shapes were captured on is configured, and
// a gated version the config lacks is explained above. A new version added to
// the config without deciding whether I-46 holds for it fails here.
func TestVersionGatesAgreeWithTheConfig(t *testing.T) {
	c, err := config.Load(filepath.Join("..", "..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	configured := c.Versions(Name)
	if len(configured) == 0 {
		t.Fatalf("no %s versions in %s", Name, c.Path)
	}
	for _, v := range configured {
		if !harnessReadVersions[v] {
			t.Errorf("configured version %s is not in harnessReadVersions (I-46): read its binary's parser before configuring it", v)
		}
	}
	if !c.Configured(Name, capturedVersion) {
		t.Errorf("capturedVersion %s is not configured", capturedVersion)
	}
	gated := make([]string, 0, len(harnessReadVersions))
	for v := range harnessReadVersions {
		gated = append(gated, v)
	}
	sort.Strings(gated)
	for _, v := range gated {
		_, explained := gatedNotConfigured[v]
		switch {
		case c.Configured(Name, v) && explained:
			t.Errorf("version %s is configured now: remove it from gatedNotConfigured", v)
		case !c.Configured(Name, v) && !explained:
			t.Errorf("harnessReadVersions has %s, which is not configured: configure it or explain it in gatedNotConfigured", v)
		}
	}
}
