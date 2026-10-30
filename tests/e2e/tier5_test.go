package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	probenet "github.com/agent-trace/agent-trace/pkg/probe/net"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const tier5FetchURL = "https://example.com/api"
const tier5FetchBody = "content-body"

func findLibSSL(t *testing.T) string {
	t.Helper()
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not available")
	}
	out, err := exec.Command("ldd", curlPath).CombinedOutput()
	if err != nil {
		t.Skipf("ldd %s: %v", curlPath, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "libssl.so") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "=>" && i+1 < len(fields) {
				if _, err := os.Stat(fields[i+1]); err == nil {
					return fields[i+1]
				}
			}
		}
	}
	t.Skip("could not resolve libssl.so path from ldd output")
	return ""
}

func resolveSingleIPv4(t *testing.T, host string) (string, error) {
	t.Helper()
	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if v4 := addr.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for %s", host)
}

// runTier5MockAgent captures a curl POST over TLS with the net probe and
// content capture, and returns the capture with a hand-built trajectory that
// claims it. The shell execs curl, so curl keeps the shell's pid: the request is
// the agent's own action at level 0 and is aligned against a claim. A curl that
// the agent forked instead would be a level-1 subtree, whose requests are
// counted and attributed but never claimed (D3), and so could not carry a
// request-hash claim at all.
func runTier5MockAgent(t *testing.T, attack string) capture {
	t.Helper()

	libssl := findLibSSL(t)

	netObs, err := probenet.New(probenet.Config{
		EventBufSize: 256,
		ExePath:      libssl,
	})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}

	// example.com resolves to multiple CDN edge IPs over IPv4/IPv6; curl performs
	// Happy-Eyeballs-style parallel connection attempts against all of them, which
	// would surface as extra unattributed net_connect ground-truth events for the
	// addresses that never complete a TLS handshake. Pin curl to a single resolved
	// IPv4 address so exactly one connection is opened.
	ip, err := resolveSingleIPv4(t, "example.com")
	if err != nil {
		t.Fatalf("resolve example.com: %v", err)
	}

	// We use 'exec curl' so that curl inherits the exact PID of this shell script.
	// The sleep ensures the net probe has time to attach its uprobe before curl starts.
	cmd := exec.Command("sh", "-c", "sleep 0.5 && exec curl --http1.1 --resolve example.com:443:"+ip+" -s -o /dev/null -X POST -d "+tier5FetchBody+" "+tier5FetchURL)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start shell: %v", err)
	}
	root := cmd.Process.Pid

	if err := netObs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		t.Fatalf("netObs.TrackPID: %v", err)
	}
	go netObs.Start()

	if err := cmd.Wait(); err != nil {
		t.Fatalf("curl script failed: %v", err)
	}

	time.Sleep(3 * time.Second)

	if err := netObs.Stop(); err != nil {
		t.Fatalf("netObs.Stop: %v", err)
	}

	var g models.GroundTruth
	// We only care about Net events for Tier 5 assertions
	for e := range netObs.Events() {
		g = append(g, e)
	}
	t.Logf("Ground truth events collected: %d", len(g))
	t.Logf("Net Observer Coverage: %+v", netObs.Coverage())

	// Content capture can fail open: the SSL_write frames still reach the
	// correlator and the assertions below still pass, while the uprobe offset
	// was never actually validated or cached. Fail here instead, so a
	// regression in validation (e.g. a second goroutine racing the validator
	// for the ssl ring buffer) cannot hide behind a green Tier 5 run.
	if err := netObs.TLSAttachError(); err != nil {
		t.Fatalf("TLS content capture did not attach: %v", err)
	}

	// Build the trajectory manually
	var tr models.Trajectory
	target := models.CanonicalNetTarget("POST", "example.com", 443, "/api", "")
	h := sha256.Sum256([]byte(tier5FetchBody))
	hashStr := "sha256:" + hex.EncodeToString(h[:])

	if attack == "substitution" {
		hashStr = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Claims are in the order the connection happened: connect, then request.
	// The alignment is by position within the net lane, so the claim order has
	// to be the real order.
	tr = append(tr,
		models.TrajectoryEntry{Timestamp: time.Now().Add(-2 * time.Second), ActionType: models.NetConnect, Target: "example.com"},
		models.TrajectoryEntry{Timestamp: time.Now().Add(-1 * time.Second), ActionType: models.NetRequest, Target: target, RequestHash: &hashStr},
	)

	return capture{tr: tr, g: g, root: root, cov: coverageOf(map[string]probe.CoverageReporter{"net": netObs})}
}

func TestTier5_E2E_NetRequest_Content_Faithful(t *testing.T) {
	skipUnprivileged(t)
	c := runTier5MockAgent(t, "")
	g, tr := c.g, c.tr

	verdict := c.verify(tr)
	if verdict.Outcome != verification.OutcomeFaithful {
		logVerdict(t, verdict)
		for _, m := range verdict.Mismatched {
			t.Logf("    entry hash: %v, event hash: %v", m.Entry.RequestHash, m.Event.RequestHash)
		}
		t.Fatalf("outcome = %s, want FAITHFUL", verdict.Outcome)
	}

	foundReq := false
	for _, pair := range verdict.Corroborated {
		if pair.Entry.ActionType == models.NetRequest {
			foundReq = true
			if pair.Entry.RequestHash == nil {
				t.Error("expected RequestHash in Corroborated NetRequest entry")
			}
			if pair.Event.RequestHash == nil {
				t.Error("expected RequestHash in Corroborated NetRequest event")
			}
		}
	}
	if !foundReq {
		t.Errorf("expected to corroborate a NetRequest action. Ground truth has %d events, Trajectory has %d entries.", len(g), len(tr))
		for _, e := range g {
			if e.ActionType == models.NetRequest {
				t.Logf("Found NetRequest in ground truth: %s (hash: %v)", e.Target, e.RequestHash)
			}
		}
		for _, e := range tr {
			if e.ActionType == models.NetRequest {
				t.Logf("Found NetRequest in trajectory: %s (hash: %v)", e.Target, e.RequestHash)
			}
		}
		t.FailNow()
	}
}

func TestTier5_E2E_NetRequest_Content_Substitution(t *testing.T) {
	skipUnprivileged(t)
	c := runTier5MockAgent(t, "substitution")

	verdict := c.verify(c.tr)
	if verdict.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL after substituting the RequestHash", verdict.Outcome)
	}

	foundMismatch := false
	for _, pair := range verdict.Mismatched {
		if pair.Entry.ActionType == models.NetRequest {
			foundMismatch = true
			t.Logf("Successfully caught Mismatched NetRequest for %s: entry hash %v, event hash %v",
				pair.Entry.Target, pair.Entry.RequestHash, pair.Event.RequestHash)
		}
	}
	if !foundMismatch {
		t.Errorf("expected Mismatched NetRequest")
		logVerdict(t, verdict)
		t.FailNow()
	}
}

// tier5Page is the page the local server serves to the summarized-response
// test, and tier5Summary what a WebFetch-style tool hands the model instead.
const (
	tier5Host    = "agenttrace-fetch.internal"
	tier5Page    = "<html><body><h1>Release notes</h1><p>Version 2 removes the legacy flag and adds streaming.</p></body></html>\n"
	tier5Summary = "The release notes say version 2 drops the legacy flag and adds streaming."
)

// TestTier5_E2E_SummarizedResponseIsNotCompared is the negative test of N-11
// and N-29. A WebFetch-style tool returns a model-written summary of the
// page, not the page, so a claim that carries the summary's hash on its
// request states something no capture can check. A local TLS server serves a
// known page to curl, which the shell execs so the fetch is the agent's own
// (level 0), under the net probe with request and response capture. The
// response is captured whole, its body hash is the page's, and that hash
// differs from the claimed summary's; the run is still FAITHFUL, with the
// request corroborated, nothing unverified and the response kept as
// capability evidence. It fails if the probe ever puts response content on
// the request event or the verifier compares a summary with captured bytes.
func TestTier5_E2E_SummarizedResponseIsNotCompared(t *testing.T) {
	skipUnprivileged(t)
	libssl := findLibSSL(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(tier5Page))
	}))
	srv.StartTLS() // HTTP/1.1 only: EnableHTTP2 is false
	defer srv.Close()
	addr := srv.Listener.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("https://%s:%d/notes", tier5Host, addr.Port)

	netObs, err := probenet.New(probenet.Config{
		EventBufSize:      256,
		ExePath:           libssl,
		CachePath:         t.TempDir() + "/cache.json",
		ValidationTimeout: 8 * time.Second,
	})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}

	// The shell waits on its stdin until the probe tracks it, then execs
	// curl, which keeps the shell's pid.
	cmd := exec.Command("sh", "-c", `read go; exec curl --http1.1 -k -s -o /dev/null --resolve "$1:$2:127.0.0.1" "$3"`,
		"sh", tier5Host, fmt.Sprint(addr.Port), url)
	release, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start shell: %v", err)
	}
	root := cmd.Process.Pid
	if err := netObs.TrackPID(int32(root)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("netObs.TrackPID: %v", err)
	}
	started := make(chan struct{})
	go func() {
		netObs.Start()
		close(started)
	}()
	start := time.Now()
	if _, err := release.Write([]byte("go\n")); err != nil {
		t.Fatalf("release the shell: %v", err)
	}
	_ = release.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("curl failed: %v", err)
	}
	end := time.Now()
	// CI sets this bound, not a dev box: validation ends at the first write.
	select {
	case <-started:
	case <-time.After(15 * time.Second):
		t.Log("Observer.Start did not return; stopping anyway")
	}
	if err := netObs.Stop(); err != nil {
		t.Fatalf("netObs.Stop: %v", err)
	}
	var g models.GroundTruth
	for e := range netObs.Events() {
		g = append(g, e)
	}
	if err := netObs.TLSAttachError(); err != nil {
		t.Fatalf("TLS content capture did not attach: %v", err)
	}
	if err := netObs.ResponseAttachError(); err != nil {
		t.Fatalf("response capture did not attach: %v", err)
	}
	if got := netObs.CaptureCoverage().Responses; got != models.ContentActive {
		t.Fatalf("Responses = %q, want %q", got, models.ContentActive)
	}

	// The capture holds the request and the whole page: without them the
	// test below would pass for want of anything to compare.
	target := models.CanonicalNetTarget("GET", tier5Host, addr.Port, "/notes", "")
	pageSum := sha256.Sum256([]byte(tier5Page))
	summarySum := sha256.Sum256([]byte(tier5Summary))
	pageHash := "sha256:" + hex.EncodeToString(pageSum[:])
	summaryHash := "sha256:" + hex.EncodeToString(summarySum[:])
	var requests, responses int
	for _, e := range g {
		switch {
		case e.ActionType == models.NetRequest && e.Target == target:
			requests++
			if e.PID != uint32(root) {
				t.Errorf("request by pid %d, want the agent %d", e.PID, root)
			}
			if e.OutputHash != nil || e.Response != nil {
				t.Errorf("the request event carries response content: output hash %v, response %+v", e.OutputHash, e.Response)
			}
		case e.ActionType == models.NetResponse && e.Target == target:
			responses++
			r := e.Response
			if e.PID != uint32(root) || r == nil || r.Status != 200 || !r.Complete || r.Truncated || !r.Paired ||
				r.BodyBytes != int64(len(tier5Page)) || r.BodyHash != pageHash {
				t.Fatalf("response by pid %d: %+v; want the agent's complete, paired 200 with the page's %d bytes and hash %s", e.PID, r, len(tier5Page), pageHash)
			}
		}
	}
	if requests != 1 || responses != 1 {
		t.Fatalf("%d requests and %d responses for %s, want one of each; events: %+v", requests, responses, target, g)
	}
	if pageHash == summaryHash {
		t.Fatal("the summary must differ from the page")
	}

	fetch := models.TrajectoryEntry{Timestamp: start, End: &end, ActionType: models.NetRequest, Target: target, Tool: "WebFetch", OutputHash: &summaryHash}
	tr := models.Trajectory{
		{Timestamp: start, End: &end, ActionType: models.NetConnect, Target: tier5Host},
		fetch,
	}
	c := capture{tr: tr, g: g, root: root, cov: coverageOf(map[string]probe.CoverageReporter{"net": netObs})}
	v := c.verifyWith(tr, verification.Options{IntervalSlack: 250 * time.Millisecond})
	requireFaithful(t, v)
	if len(v.Mismatched) != 0 || len(v.Unverified) != 0 {
		t.Errorf("mismatched %+v, unverified %+v; the summary was compared with the capture", v.Mismatched, v.Unverified)
	}
	var corroborated bool
	for _, p := range v.Corroborated {
		if p.Entry.ActionType == models.NetRequest && p.Event.Target == target {
			corroborated = true
		}
	}
	if !corroborated {
		t.Error("the fetch's request is not corroborated")
		logVerdict(t, v)
	}
	var kept bool
	for _, e := range v.Capability {
		if e.ActionType == models.NetResponse && e.Target == target {
			kept = true
		}
	}
	if !kept {
		t.Error("the captured response is not kept as capability evidence")
	}
}
