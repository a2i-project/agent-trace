package claudecode

import (
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const (
	tokenURL   = "POST https://platform.claude.com/v1/oauth/token"
	profileURL = "GET https://api.anthropic.com/api/oauth/profile"
)

// V-54: the declaration of 2.1.306 recognises the token renewal's connection,
// its POST with a body and the profile's GET with none, exactly as the net
// probe writes them, and nothing else; other versions declare nothing.
func TestHarnessHousekeepingDeclaresTheTokenRenewalOnly(t *testing.T) {
	hash := "sha256:00"
	ev := func(typ models.ActionType, target string, body bool) models.GroundTruthEvent {
		e := models.GroundTruthEvent{ActionType: typ, Target: target}
		if body {
			e.RequestHash = &hash
		}
		return e
	}
	cut := ev(models.NetConnect, "platform.claude.com", false)
	cut.TargetTruncated = true
	hk := agent.HarnessHousekeeping(Adapter{}, "2.1.306")
	if hk == nil {
		t.Fatal("2.1.306: no declaration")
	}
	for _, c := range []struct {
		e    models.GroundTruthEvent
		want bool
	}{
		{ev(models.NetConnect, "platform.claude.com", false), true},
		{ev(models.NetRequest, tokenURL, true), true},
		{ev(models.NetRequest, profileURL, false), true},
		// The body as the harness sends it, and nothing else.
		{ev(models.NetRequest, tokenURL, false), false},
		{ev(models.NetRequest, profileURL, true), false},
		// Another method, a query, a fragment, another path or host.
		{ev(models.NetRequest, "GET https://platform.claude.com/v1/oauth/token", false), false},
		{ev(models.NetRequest, tokenURL+"?x=1", true), false},
		{ev(models.NetRequest, profileURL+"?x=1", false), false},
		{ev(models.NetRequest, profileURL+"/", false), false},
		{ev(models.NetRequest, "POST https://api.anthropic.com/v1/oauth/token", true), false},
		{ev(models.NetRequest, "POST https://platform.claude.com/v1/oauth/token/", true), false},
		{ev(models.NetRequest, "GET https://platform.claude.com/oauth/authorize", false), false},
		{ev(models.NetRequest, "GET https://platform.claude.com/", false), false},
		{ev(models.NetRequest, "GET https://api.anthropic.com/api/oauth/claude_cli/roles", false), false},
		{ev(models.NetRequest, "POST https://api.anthropic.com/api/oauth/claude_cli/create_api_key", true), false},
		// A connection is a host, never a request target; another host or
		// letter case; an address; a truncated target.
		{ev(models.NetConnect, tokenURL, false), false},
		{ev(models.NetConnect, "api.anthropic.com", false), false},
		{ev(models.NetConnect, "Platform.claude.com", false), false},
		{ev(models.NetConnect, "x.platform.claude.com", false), false},
		{ev(models.NetConnect, "platform.claude.com.evil.example", false), false},
		{ev(models.NetConnect, "160.79.104.10:443", false), false},
		{ev(models.NetDial, "platform.claude.com", false), false},
		{ev(models.NetResponse, tokenURL, false), false},
		{ev(models.FileWrite, "platform.claude.com", false), false},
		{cut, false},
	} {
		if got := hk(c.e); got != c.want {
			t.Errorf("%s %q body %v truncated %v: %v, want %v", c.e.ActionType, c.e.Target, c.e.RequestHash != nil, c.e.TargetTruncated, got, c.want)
		}
	}
	for _, version := range []string{"", "2.1.286", "2.1.296", "2.1.302", "2.1.305", "2.1.311", "2.1.306-beta"} {
		if agent.HarnessHousekeeping(Adapter{}, version) != nil {
			t.Errorf("version %q: a declaration, want none", version)
		}
	}
}

// V-54 on the shape of the websearch capture of 2.1.306, synthesized: at
// start-up the agent's process connects to platform.claude.com, POSTs the
// renewal and GETs the profile over the model API's connection, which the
// baseline explains. With request content the three events are declared
// housekeeping; without it only the connection appears and is declared
// alone; either way the run is FAITHFUL. For another version, or with no
// version, they stay Unrecorded. Another request through the same
// connection stays a finding.
func TestTheWebsearchTokenRenewalIsDeclaredHousekeeping(t *testing.T) {
	const root = 100
	ts := time.Date(2026, 10, 28, 10, 7, 22, 208484972, time.UTC)
	hash := "sha256:f2"
	ev := func(ms int, typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: ts.Add(time.Duration(ms) * time.Millisecond), ActionType: typ, Target: target, PID: root}
	}
	post := ev(11, models.NetRequest, tokenURL)
	post.RequestHash = &hash
	capture := func(content bool, extra ...models.GroundTruthEvent) models.GroundTruthFile {
		events := models.GroundTruth{ev(-60, models.NetConnect, "api.anthropic.com"), ev(0, models.NetConnect, "platform.claude.com")}
		if content {
			events = append(events, post, ev(363, models.NetRequest, profileURL))
		}
		return models.GroundTruthFile{
			RootPID: root, Workspace: "/ws",
			Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"net": {Ran: true}, "proc": {Ran: true}}},
			Events:   append(events, extra...),
		}
	}
	measured := func(e models.GroundTruthEvent) bool {
		return e.ActionType == models.NetConnect && e.Target == "api.anthropic.com"
	}
	verify := func(version string, g models.GroundTruthFile) verification.Verdict {
		in := agent.Prepare(Adapter{}, nil, g, measured, verification.Options{})
		in.Options.HarnessHousekeeping = agent.HarnessHousekeeping(Adapter{}, version)
		return verification.Verify(in)
	}

	for _, c := range []struct {
		content bool
		want    int
	}{{true, 3}, {false, 1}} {
		v := verify("2.1.306", capture(c.content))
		if v.Outcome != verification.OutcomeFaithful || len(v.HarnessHousekeeping) != c.want || len(v.Unrecorded) != 0 || len(v.UnexplainedHarnessNet) != 0 {
			t.Errorf("content %v: outcome %s, housekeeping %v, unrecorded %v, reasons %v", c.content, v.Outcome, v.HarnessHousekeeping, v.Unrecorded, v.Reasons)
		}
		for _, version := range []string{"", "2.1.296"} {
			v = verify(version, capture(c.content))
			if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != c.want || len(v.HarnessHousekeeping) != 0 {
				t.Errorf("content %v, version %q: outcome %s, unrecorded %v, housekeeping %v", c.content, version, v.Outcome, v.Unrecorded, v.HarnessHousekeeping)
			}
		}
	}
	// What an agent could send through the same host or the profile's
	// path: each stays Unrecorded.
	for _, target := range []string{
		"GET https://platform.claude.com/v1/oauth/token",
		"POST https://platform.claude.com/v1/oauth/token?state=payload",
		"GET https://platform.claude.com/oauth/authorize?code=payload",
		"GET https://api.anthropic.com/api/oauth/profile?x=payload",
	} {
		v := verify("2.1.306", capture(true, ev(1000, models.NetRequest, target)))
		if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != target || len(v.HarnessHousekeeping) != 3 {
			t.Errorf("%s: outcome %s, unrecorded %v, housekeeping %v", target, v.Outcome, v.Unrecorded, v.HarnessHousekeeping)
		}
	}
}

// housekeepingNotGated are configured versions without V-54's declaration,
// each with why.
var housekeepingNotGated = map[string]string{
	"2.1.286": "its binary was not read for V-54, and none of its captures shows a token renewal",
	"2.1.296": "its binary was not read for V-54, and none of its captures shows a token renewal",
}

// TestHousekeepingGateAgreesWithTheConfig ties V-54's gate to
// config/agents.json (I-57): every configured version is declared or
// explained above, and every declared version is configured.
func TestHousekeepingGateAgreesWithTheConfig(t *testing.T) {
	c, err := config.Load(filepath.Join("..", "..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Versions(Name) {
		_, gated := housekeepingVersions[v]
		if _, skip := housekeepingNotGated[v]; !gated && !skip {
			t.Errorf("configured version %s is not in housekeepingVersions (V-54): read its token renewal before configuring it, or explain it", v)
		}
	}
	gated := make([]string, 0, len(housekeepingVersions))
	for v := range housekeepingVersions {
		gated = append(gated, v)
	}
	sort.Strings(gated)
	for _, v := range gated {
		if !c.Configured(Name, v) {
			t.Errorf("housekeepingVersions has %s, which is not configured", v)
		}
	}
}
