package agent

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// contentFake needs content for claims of the target "needs" and declares
// the content method method for them ("" reads the probe's whole state).
type contentFake struct {
	fake
	method string
}

func (contentFake) NeedsContent(e models.TrajectoryEntry) bool { return e.Target == "needs" }

type declaringFake struct{ contentFake }

func (d declaringFake) ContentMethod(models.TrajectoryEntry) string { return d.method }

func coverageWith(content string, methods map[string]models.ContentMethodState) *models.Coverage {
	net := models.ProbeCoverage{Ran: true, Content: content, Responses: content}
	if methods != nil {
		net.Diagnostics = &models.ProbeDiagnostics{ContentMethods: methods}
	}
	return &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"net": net}}
}

// A content claim is kept when the method it depends on read content, and
// dropped when that method did not, whatever another method did (N-42). An
// adapter that declares no method reads the probe's whole state, as before.
func TestPrepareReadsTheDeclaredContentMethod(t *testing.T) {
	claims := models.Trajectory{{ActionType: models.NetRequest, Target: "needs"}, {ActionType: models.NetConnect, Target: "always"}}
	split := map[string]models.ContentMethodState{
		"tls-openssl-ex":  {Requests: models.ContentAttachFailed, Responses: models.ContentAttachFailed},
		"tls-rustls-aead": {Requests: models.ContentActive, Responses: models.ContentActive},
	}
	for _, tc := range []struct {
		name string
		a    Adapter
		cov  *models.Coverage
		kept int
	}{
		{"undeclared, content active", contentFake{fake: fake{name: "f"}}, coverageWith(models.ContentActive, nil), 2},
		{"undeclared, content failed", contentFake{fake: fake{name: "f"}}, coverageWith(models.ContentAttachFailed, nil), 1},
		{"declared method active", declaringFake{contentFake{fake: fake{name: "f"}, method: "tls-rustls-aead"}}, coverageWith(models.ContentActive, split), 2},
		{"declared method silent", declaringFake{contentFake{fake: fake{name: "f"}, method: "tls-openssl-ex"}}, coverageWith(models.ContentActive, split), 1},
		{"declared method not configured", declaringFake{contentFake{fake: fake{name: "f"}, method: "tls-symbols"}}, coverageWith(models.ContentActive, split), 1},
		{"declared empty reads the whole", declaringFake{contentFake{fake: fake{name: "f"}}}, coverageWith(models.ContentActive, split), 2},
	} {
		g := models.GroundTruthFile{Coverage: tc.cov}
		in := Prepare(tc.a, claims, g, nil, verification.Options{})
		if len(in.Claims) != tc.kept {
			t.Errorf("%s: %d claims kept, want %d", tc.name, len(in.Claims), tc.kept)
		}
	}
}

func TestMethodContent(t *testing.T) {
	single := coverageWith(models.ContentActive, nil).Probes["net"]
	if r, s := single.MethodContent("tls-symbols"); r != models.ContentActive || s != models.ContentActive {
		t.Errorf("a capture without per-method states reads the probe's: %s %s", r, s)
	}
	multi := coverageWith(models.ContentActive, map[string]models.ContentMethodState{"tls-rustls-aead": {Requests: models.ContentActive, Responses: models.ContentAttachFailed}}).Probes["net"]
	if r, s := multi.MethodContent("tls-rustls-aead"); r != models.ContentActive || s != models.ContentAttachFailed {
		t.Errorf("tls-rustls-aead: %s %s", r, s)
	}
	if r, _ := multi.MethodContent("tls-openssl-ex"); r != models.ContentIdentityOnly {
		t.Errorf("a method not configured: %s", r)
	}
}
