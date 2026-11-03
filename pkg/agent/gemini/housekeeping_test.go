package gemini

import (
	"path/filepath"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-85: the renewal is declared by its exact shape for 1.4.7 only. Another
// path, a query, another method, a POST without a body, another host and
// another version stay checked.
func TestHarnessHousekeepingDeclaresTheTokenRenewalOnly(t *testing.T) {
	is := agent.HarnessHousekeeping(Adapter{}, "1.4.7")
	if is == nil {
		t.Fatal("1.4.7 declares nothing")
	}
	body := "sha256:00"
	req := func(target string, withBody bool) models.GroundTruthEvent {
		e := models.GroundTruthEvent{ActionType: models.NetRequest, Target: target}
		if withBody {
			e.RequestHash = &body
		}
		return e
	}
	for _, c := range []struct {
		e    models.GroundTruthEvent
		want bool
	}{
		{models.GroundTruthEvent{ActionType: models.NetConnect, Target: "oauth2.googleapis.com"}, true},
		{req("POST https://oauth2.googleapis.com/token", true), true},
		{req("POST https://oauth2.googleapis.com/token", false), false},
		{req("POST https://oauth2.googleapis.com/token?x=1", true), false},
		{req("POST https://oauth2.googleapis.com/revoke", true), false},
		{req("GET https://oauth2.googleapis.com/token", false), false},
		{req("POST https://oauth2.googleapis.com/device/code", true), false},
		{models.GroundTruthEvent{ActionType: models.NetConnect, Target: "accounts.google.com"}, false},
		{models.GroundTruthEvent{ActionType: models.NetConnect, Target: "oauth2.googleapis.com", TargetTruncated: true}, false},
	} {
		if got := is(c.e); got != c.want {
			t.Errorf("%s %s (body %v): %v, want %v", c.e.ActionType, c.e.Target, c.e.RequestHash != nil, got, c.want)
		}
	}
	for _, v := range []string{"", "1.3.4", "1.4.8"} {
		if agent.HarnessHousekeeping(Adapter{}, v) != nil {
			t.Errorf("version %q declares housekeeping", v)
		}
	}
}

// housekeepingNotGated are configured versions without the declaration,
// each with why.
var housekeepingNotGated = map[string]string{
	"1.3.4": "its captures read no request content, so the renewal's request is not measured",
}

// TestHousekeepingGateAgreesWithTheConfig ties the declared versions to
// config/agents.json, as Claude Code's gate is (V-54).
func TestHousekeepingGateAgreesWithTheConfig(t *testing.T) {
	c, err := config.Load(filepath.Join("..", "..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Versions(Name) {
		if _, skip := housekeepingNotGated[v]; !housekeepingVersions[v] && !skip {
			t.Errorf("configured version %s is not in housekeepingVersions (V-85): measure its token renewal, or explain it", v)
		}
	}
	for v := range housekeepingVersions {
		if !c.Configured(Name, v) {
			t.Errorf("housekeepingVersions has %s, which is not configured", v)
		}
	}
}
