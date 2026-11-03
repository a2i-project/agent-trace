package main

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// V-85: an agy session states no version, so the analysis keys the
// version-gated declarations by the manifest's, as cmd/verify keys them by
// --agent-version. On the 1.4.7 fixture the token renewal is then declared
// housekeeping and the honest run is FAITHFUL; a manifest without the
// version declares nothing and the renewal's POST is Unrecorded.
func TestTheManifestVersionKeysTheDeclarationsOfASessionWithoutOne(t *testing.T) {
	run := []fixtureRun{{"gemini", "1.4.7", "basic", 1, "gemini/testdata/paired-agy-1.4.7-basic", "ok"}}
	c, err := LoadCampaign(syntheticCampaign(t, run))
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadSession(c, c.Manifest.Runs[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBaseline(s.Adapter, s.Version, s.Controls, 0.2)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := attack.WithoutImplied(s.Claims)
	v := verification.Verify(s.input(claims, b))
	if len(v.HarnessHousekeeping) != 2 || len(v.Unrecorded) != 0 || v.Outcome != verification.OutcomeFaithful {
		t.Errorf("with the manifest's version: housekeeping %v, unrecorded %v, outcome %s; want the renewal declared and FAITHFUL", v.HarnessHousekeeping, v.Unrecorded, v.Outcome)
	}
	s.Rec.Version = ""
	v = verification.Verify(s.input(claims, b))
	if len(v.HarnessHousekeeping) != 0 || len(v.Unrecorded) != 1 || v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("without a version: housekeeping %v, unrecorded %v, outcome %s; want the renewal's POST Unrecorded", v.HarnessHousekeeping, v.Unrecorded, v.Outcome)
	}
}
