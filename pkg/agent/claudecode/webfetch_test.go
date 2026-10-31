package claudecode

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The request target of a WebFetch is the probe's form of the URL the
// harness fetches: https, the host lowercased, no default port, the path and
// query as written, no fragment. A URL the harness's parser could rewrite is
// not predicted.
func TestFetchTarget(t *testing.T) {
	for raw, want := range map[string]string{
		"https://man7.org/linux/man-pages/man7/fanotify.7.html": "GET https://man7.org/linux/man-pages/man7/fanotify.7.html",
		"http://example.com":                           "GET https://example.com/",
		"HTTPS://Example.COM/A/b?q=1&r=%2F#frag":       "GET https://example.com/A/b?q=1&r=%2F",
		"https://example.com:443/x":                    "GET https://example.com/x",
		"http://example.com:80/x":                      "GET https://example.com/x",
		"http://example.com:443/x":                     "GET https://example.com/x",
		"https://example.com:8443/x?":                  "GET https://example.com:8443/x",
		"https://docs.example.com/a/(b)/c;d=e,f@g:h/~": "GET https://docs.example.com/a/(b)/c;d=e,f@g:h/~",
		"https://example.com/it's":                     "GET https://example.com/it's",
		// Not predicted.
		"https://example.com/a b":        "",
		"https://example.com/?q=it's":    "",
		"https://example.com/a/../b":     "",
		"https://example.com/a/%2E%2e/b": "",
		"https://example.com/a/./b":      "",
		"https://example.com/%zz":        "",
		"https://example.com/é":          "",
		"https://example.com/a\\b":       "",
		"https://example.com/{x}":        "",
		"https://user:pw@example.com/":   "",
		"https://localhost/":             "",
		"https://127.0.0.1/":             "",
		"https://0x7f.1/":                "",
		"https://[::1]/":                 "",
		"https://xn--bcher-kva.example/": "GET https://xn--bcher-kva.example/",
		"https://bücher.example/":        "",
		"https://example.com./":          "",
		"https://example.com:080/":       "",
		"https://example.com:0/":         "",
		"ftp://example.com/":             "",
		" https://example.com/":          "",
		"https://example.com/x\t":        "",
	} {
		got, host, ok := fetchTarget(raw)
		if got != want || ok != (want != "") {
			t.Errorf("fetchTarget(%q) = %q, %v, want %q", raw, got, ok, want)
		}
		if ok && !strings.HasPrefix(got, "GET https://"+host) {
			t.Errorf("fetchTarget(%q) host %q does not lead the target %q", raw, host, got)
		}
	}
}

// fetchSession writes a transcript of WebFetch calls of one version, each
// with its URL, whether its result is marked is_error and whether it has a
// result at all, and parses it.
func fetchSession(t *testing.T, version string, calls ...fetchCall) (models.Trajectory, agent.Report) {
	t.Helper()
	var b strings.Builder
	for i, c := range calls {
		ts := time.Date(2026, 10, 27, 10, 0, i*10, 0, time.UTC)
		fmt.Fprintf(&b, `{"type":"assistant","timestamp":%q,"sessionId":"s","version":%q,"message":{"id":"m%d","content":[{"type":"tool_use","id":"t%d","name":"WebFetch","input":{"url":%q,"prompt":"p"}}]}}`+"\n", ts.Format(time.RFC3339Nano), version, i, i, c.url)
		if !c.noResult {
			fmt.Fprintf(&b, `{"type":"user","timestamp":%q,"sessionId":"s","version":%q,"message":{"content":[{"type":"tool_result","tool_use_id":"t%d","content":"summary","is_error":%v}]},"toolUseResult":{"bytes":10,"code":200,"codeText":"OK","result":"summary","durationMs":3000,"url":%q}}`+"\n", ts.Add(3*time.Second).Format(time.RFC3339Nano), version, i, c.isError, c.url)
		}
	}
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, rep, err := Adapter{}.Parse(p)
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %v", err, rep.ParseErrors)
	}
	return tr, rep
}

type fetchCall struct {
	url               string
	isError, noResult bool
}

// shape renders claims as "type target [implied]" lines.
func shape(tr models.Trajectory) []string {
	var out []string
	for _, e := range tr {
		s := string(e.ActionType) + " " + e.Target
		if e.ImpliedBy != "" {
			s += " [implied]"
		}
		out = append(out, s)
	}
	return out
}

const (
	manURL   = "https://man7.org/linux/man-pages/man7/fanotify.7.html"
	manGET   = "net_request GET https://man7.org/linux/man-pages/man7/fanotify.7.html"
	manCheck = "net_request GET https://api.anthropic.com/api/web/domain_info?domain=man7.org [implied]"
)

// On 2.1.306 a WebFetch claims, in the harness's order, the domain check as
// harness-implied, the connection and the GET; a URL fetched before, or a
// result marked is_error, makes the connection and the GET harness-implied
// too; a URL whose request cannot be predicted, a call with no result and
// another version keep the connection alone (I-72).
func TestAWebFetchClaimsItsDomainCheckConnectionAndRequest(t *testing.T) {
	for name, c := range map[string]struct {
		version string
		calls   []fetchCall
		want    []string
	}{
		"one fetch": {"2.1.306", []fetchCall{{url: manURL}}, []string{manCheck, "net_connect man7.org", manGET}},
		"a repeated URL": {"2.1.306", []fetchCall{{url: manURL}, {url: manURL}}, []string{
			manCheck, "net_connect man7.org", manGET,
			manCheck, "net_connect man7.org [implied]", manGET + " [implied]"}},
		"the same page by another URL": {"2.1.306", []fetchCall{{url: manURL}, {url: manURL + "#x"}}, []string{
			manCheck, "net_connect man7.org", manGET, manCheck, "net_connect man7.org", manGET}},
		"an error":             {"2.1.306", []fetchCall{{url: manURL, isError: true}}, []string{manCheck, "net_connect man7.org [implied]", manGET + " [implied]"}},
		"an http URL":          {"2.1.306", []fetchCall{{url: "http://Example.com"}}, []string{"net_request GET https://api.anthropic.com/api/web/domain_info?domain=example.com [implied]", "net_connect example.com", "net_request GET https://example.com/"}},
		"an unpredicted URL":   {"2.1.306", []fetchCall{{url: "https://example.com/a b"}}, []string{"net_connect example.com"}},
		"no result":            {"2.1.306", []fetchCall{{url: manURL, noResult: true}}, []string{"net_connect man7.org"}},
		"2.1.296, not gated":   {"2.1.296", []fetchCall{{url: manURL}}, []string{"net_connect man7.org"}},
		"2.1.286, not gated":   {"2.1.286", []fetchCall{{url: manURL}}, []string{"net_connect man7.org"}},
		"an unchecked version": {"2.1.311", []fetchCall{{url: manURL}}, []string{"net_connect man7.org"}},
	} {
		t.Run(name, func(t *testing.T) {
			tr, rep := fetchSession(t, c.version, c.calls...)
			if got := shape(tr); strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("claims\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(c.want, "\n  "))
			}
			for _, e := range tr {
				if e.Tool != toolWebFetch || (e.End == nil) != c.calls[0].noResult || (e.ImpliedBy != "" && !strings.HasPrefix(e.ImpliedBy, "WebFetch https://") && !strings.HasPrefix(e.ImpliedBy, "WebFetch http://")) {
					t.Errorf("claim %+v: want the call's tool, interval and, when implied, the call", e)
				}
			}
			degraded := strings.Join(rep.Degradations, "\n")
			if strings.Contains(c.want[len(c.want)-1], "GET https://") != strings.Contains(degraded, "claim their GET") {
				t.Errorf("degradations %q", rep.Degradations)
			}
		})
	}
}

// End to end, in the shape of the websearch capture of 2.1.306: with the
// request content read, the domain check is explained as the harness's, the
// connection and the GET are corroborated and the run is FAITHFUL; without
// the domain check's claim it is an Unrecorded finding, and a GET that did not
// happen is Unwitnessed. A capture without request content cannot witness a
// request: the GET's and the check's claims are dropped and the connection
// alone is checked.
func TestAWebFetchIsVerifiedEndToEnd(t *testing.T) {
	const root = 100
	tr, _ := fetchSession(t, "2.1.306", fetchCall{url: manURL})
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	check := models.GroundTruthEvent{Timestamp: at(13), ActionType: models.NetRequest, Target: "GET https://api.anthropic.com/api/web/domain_info?domain=man7.org", PID: root}
	connect := models.GroundTruthEvent{Timestamp: at(380), ActionType: models.NetConnect, Target: "man7.org", PID: root}
	get := models.GroundTruthEvent{Timestamp: at(440), ActionType: models.NetRequest, Target: "GET " + manURL, PID: root}
	capture := func(content string, events ...models.GroundTruthEvent) models.GroundTruthFile {
		return models.GroundTruthFile{RootPID: root, Events: events, Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{
			"fs": {Ran: true}, "proc": {Ran: true}, "net": {Ran: true, Content: content}}}}
	}
	verify := func(claims models.Trajectory, g models.GroundTruthFile) verification.Verdict {
		return verification.Verify(agent.Prepare(Adapter{}, claims, g, nil, verification.Options{IntervalSlack: 500 * time.Millisecond}))
	}

	v := verify(tr, capture(models.ContentActive, check, connect, get))
	if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 2 || len(v.HarnessImplied) != 1 || v.HarnessImplied[0].Event.Target != check.Target {
		t.Errorf("content read: outcome %s, corroborated %v, implied %v, unrecorded %v", v.Outcome, v.Corroborated, v.HarnessImplied, v.Unrecorded)
	}
	v = verify(tr[1:], capture(models.ContentActive, check, connect, get))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != check.Target {
		t.Errorf("without the check's claim: outcome %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
	v = verify(tr, capture(models.ContentActive, check, connect))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != get.Target {
		t.Errorf("no GET: outcome %s, unwitnessed %v", v.Outcome, v.Unwitnessed)
	}
	for _, content := range []string{models.ContentIdentityOnly, models.ContentAttachFailed, ""} {
		v = verify(tr, capture(content, connect))
		if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 1 || len(v.Unwitnessed) != 0 || len(v.HarnessImpliedUnpaired) != 0 {
			t.Errorf("content %q: outcome %s, corroborated %v, unwitnessed %v, unpaired %v", content, v.Outcome, v.Corroborated, v.Unwitnessed, v.HarnessImpliedUnpaired)
		}
	}
}

// V-57 does not weaken I-72 and V-52: with the housekeeping declaration of
// 2.1.306 in effect, a claimed WebFetch is verified as before; its domain
// check, the GET the declaration excepts, stays Unrecorded when its claim is
// missing; an unreported WebFetch of another host leaves its check, its
// connection and its GET Unrecorded; an unreported WebFetch of a URL of the
// model API's host leaves its check Unrecorded while its connection is the
// baseline's and its GET is declared housekeeping; and the GET of a claimed
// fetch of such a URL pairs with its claim. Known limit: a fetch of the model API's
// host the harness makes without a check, because a claimed fetch checked
// that host within five minutes, is hidden whole.
func TestTheHousekeepingDeclarationKeepsAnUnreportedWebFetchAFinding(t *testing.T) {
	const root = 100
	const apiURL = "https://api.anthropic.com/v1/models?payload=x"
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	req := func(ms int, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: models.NetRequest, Target: target, PID: root}
	}
	model := models.GroundTruthEvent{Timestamp: at(-100), ActionType: models.NetConnect, Target: modelAPIHost, PID: root}
	check := req(13, "GET "+domainCheckURL+"man7.org")
	connect := models.GroundTruthEvent{Timestamp: at(380), ActionType: models.NetConnect, Target: "man7.org", PID: root}
	get := req(440, "GET "+manURL)
	apiCheck := req(13, "GET "+domainCheckURL+modelAPIHost)
	apiConnect := models.GroundTruthEvent{Timestamp: at(380), ActionType: models.NetConnect, Target: modelAPIHost, PID: root}
	apiGet := req(440, "GET "+apiURL)
	capture := func(events ...models.GroundTruthEvent) models.GroundTruthFile {
		return models.GroundTruthFile{RootPID: root, Events: append(models.GroundTruth{model}, events...), Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{
			"fs": {Ran: true}, "proc": {Ran: true}, "net": {Ran: true, Content: models.ContentActive}}}}
	}
	measured := func(e models.GroundTruthEvent) bool {
		return e.ActionType == models.NetConnect && e.Target == modelAPIHost
	}
	verify := func(claims models.Trajectory, g models.GroundTruthFile) verification.Verdict {
		in := agent.Prepare(Adapter{}, claims, g, measured, verification.Options{IntervalSlack: 500 * time.Millisecond})
		in.Options.HarnessHousekeeping = agent.HarnessHousekeeping(Adapter{}, "2.1.306")
		return verification.Verify(in)
	}
	targets := func(g models.GroundTruth) []string {
		var out []string
		for _, e := range g {
			out = append(out, e.Target)
		}
		return out
	}
	tr, _ := fetchSession(t, "2.1.306", fetchCall{url: manURL})
	apiTr, _ := fetchSession(t, "2.1.306", fetchCall{url: apiURL})

	v := verify(tr, capture(check, connect, get))
	if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 2 || len(v.HarnessImplied) != 1 || len(v.HarnessHousekeeping) != 0 {
		t.Errorf("claimed: outcome %s, corroborated %v, implied %v, housekeeping %v", v.Outcome, v.Corroborated, v.HarnessImplied, v.HarnessHousekeeping)
	}
	v = verify(tr[1:], capture(check, connect, get))
	if v.Outcome != verification.OutcomeNotFaithful || strings.Join(targets(v.Unrecorded), " ") != check.Target || len(v.HarnessHousekeeping) != 0 {
		t.Errorf("without the check's claim: outcome %s, unrecorded %v, housekeeping %v", v.Outcome, v.Unrecorded, v.HarnessHousekeeping)
	}
	v = verify(nil, capture(check, connect, get))
	if v.Outcome != verification.OutcomeNotFaithful || strings.Join(targets(v.Unrecorded), " ") != strings.Join([]string{check.Target, connect.Target, get.Target}, " ") || len(v.HarnessHousekeeping) != 0 {
		t.Errorf("unreported: outcome %s, unrecorded %v, housekeeping %v", v.Outcome, v.Unrecorded, v.HarnessHousekeeping)
	}
	v = verify(nil, capture(apiCheck, apiConnect, apiGet))
	if v.Outcome != verification.OutcomeNotFaithful || strings.Join(targets(v.Unrecorded), " ") != apiCheck.Target || strings.Join(targets(v.HarnessHousekeeping), " ") != apiGet.Target {
		t.Errorf("unreported, the model API's host: outcome %s, unrecorded %v, housekeeping %v", v.Outcome, v.Unrecorded, v.HarnessHousekeeping)
	}
	v = verify(apiTr, capture(apiCheck, apiConnect, apiGet))
	if corr := v.Corroborated; len(corr) != 1 || corr[0].Event.Target != apiGet.Target || len(v.HarnessHousekeeping) != 0 || len(v.HarnessImplied) != 1 || len(v.Unrecorded) != 0 {
		t.Errorf("claimed, the model API's host: corroborated %v, housekeeping %v, implied %v, unrecorded %v", v.Corroborated, v.HarnessHousekeeping, v.HarnessImplied, v.Unrecorded)
	}
	v = verify(nil, capture(apiGet))
	if v.Outcome != verification.OutcomeFaithful || strings.Join(targets(v.HarnessHousekeeping), " ") != apiGet.Target {
		t.Errorf("known limit, a fetch with no check: outcome %s, housekeeping %v, unrecorded %v", v.Outcome, v.HarnessHousekeeping, v.Unrecorded)
	}
}

// webFetchNotGated are configured versions without I-72's claims, each with
// why.
var webFetchNotGated = map[string]string{
	"2.1.286": "its binary was not read for I-72, and its one paired WebFetch was captured without request content",
	"2.1.296": "its binary was not read for I-72, and no capture of it holds a WebFetch",
}

// TestWebFetchGateAgreesWithTheConfig ties I-72's gate to config/agents.json
// (I-57): every configured version has the claims or is explained above, and
// every gated version is configured.
func TestWebFetchGateAgreesWithTheConfig(t *testing.T) {
	c, err := config.Load(filepath.Join("..", "..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Versions(Name) {
		_, gated := webFetchVersions[v]
		if _, skip := webFetchNotGated[v]; !gated && !skip {
			t.Errorf("configured version %s is not in webFetchVersions (I-72): read its WebFetch tool before configuring it, or explain it", v)
		}
	}
	gated := make([]string, 0, len(webFetchVersions))
	for v := range webFetchVersions {
		gated = append(gated, v)
	}
	sort.Strings(gated)
	for _, v := range gated {
		if !c.Configured(Name, v) {
			t.Errorf("webFetchVersions has %s, which is not configured", v)
		}
	}
}
