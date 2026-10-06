package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleEvents() GroundTruth {
	return GroundTruth{{Timestamp: time.Now().Truncate(time.Millisecond), ActionType: ProcessExec, Target: "ls"}}
}

func TestParseGroundTruthFile(t *testing.T) {
	events := sampleEvents()
	arrayData, _ := json.Marshal(events)

	withCov, _ := json.Marshal(GroundTruthFile{
		Events: events,
		Coverage: &Coverage{Schema: CoverageSchema, Probes: map[string]ProbeCoverage{
			"proc": {Ran: true, RingbufDrops: 3},
		}},
	})
	noCov, _ := json.Marshal(map[string]any{"events": events})
	nullCov, _ := json.Marshal(map[string]any{"events": events, "coverage": nil})
	badSchema, _ := json.Marshal(GroundTruthFile{Events: events, Coverage: &Coverage{Schema: 99}})
	badEvent := []byte(`{"events":[{"action_type":"process_exec","target":"x"}],"coverage":null}`)

	tests := []struct {
		name         string
		data         []byte
		wantErr      string
		wantEvents   int
		wantCoverage bool
		wantDrops    uint64
	}{
		{name: "legacy array has unknown coverage", data: arrayData, wantEvents: 1},
		{name: "object with coverage", data: withCov, wantEvents: 1, wantCoverage: true, wantDrops: 3},
		{name: "object without coverage key", data: noCov, wantEvents: 1},
		{name: "object with null coverage", data: nullCov, wantEvents: 1},
		{name: "unsupported schema", data: badSchema, wantErr: "unsupported coverage schema"},
		{name: "invalid event in object", data: badEvent, wantErr: "timestamp is required"},
		{name: "invalid event in array", data: []byte(`[{"action_type":"process_exec","target":"x"}]`), wantErr: "timestamp is required"},
		{name: "empty", data: []byte("  \n"), wantErr: "empty"},
		{name: "malformed", data: []byte(`{"events":`), wantErr: "unexpected end"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseGroundTruthFile(tc.data)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(f.Events) != tc.wantEvents {
				t.Errorf("events = %d, want %d", len(f.Events), tc.wantEvents)
			}
			if (f.Coverage != nil) != tc.wantCoverage {
				t.Fatalf("coverage present = %v, want %v", f.Coverage != nil, tc.wantCoverage)
			}
			if tc.wantCoverage && f.Coverage.Probes["proc"].RingbufDrops != tc.wantDrops {
				t.Errorf("proc ringbuf drops = %d, want %d", f.Coverage.Probes["proc"].RingbufDrops, tc.wantDrops)
			}
		})
	}
}

// A caller that unmarshals the object form straight into GroundTruth would
// silently drop the coverage record. It must fail instead.
func TestParseGroundTruth_RejectsObjectForm(t *testing.T) {
	data, _ := json.Marshal(GroundTruthFile{Events: sampleEvents()})
	if _, err := ParseGroundTruth(data); err == nil {
		t.Error("ParseGroundTruth accepted the object form; callers could drop coverage silently")
	}
	var g GroundTruth
	if err := json.Unmarshal(data, &g); err == nil {
		t.Error("json.Unmarshal into GroundTruth accepted the object form")
	}
}

// The counter is a loss counter, so an explicit zero must stay in the file
// (measured zero, not "not measured"), and a non-zero value must survive a
// write and read.
func TestProbeCoverage_UntrackedChildrenRoundTrips(t *testing.T) {
	for _, n := range []uint64{0, 7} {
		for _, field := range []string{"state_map_full"} {
			data, _ := json.Marshal(ProbeCoverage{Ran: true, StateMapFull: n})
			if !strings.Contains(string(data), `"`+field+`":`) {
				t.Errorf("n=%d: %s missing from %s", n, field, data)
			}
			var back ProbeCoverage
			if err := json.Unmarshal(data, &back); err != nil || back.StateMapFull != n {
				t.Errorf("n=%d: state_map_full round trip = %d, %v", n, back.StateMapFull, err)
			}
		}
		data, err := json.Marshal(GroundTruthFile{
			Events: sampleEvents(),
			Coverage: &Coverage{Schema: CoverageSchema, Probes: map[string]ProbeCoverage{
				"net": {Ran: true, UntrackedChildren: n},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"untracked_children":`) {
			t.Errorf("n=%d: untracked_children missing from %s", n, data)
		}
		f, err := ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.Coverage.Probes["net"].UntrackedChildren; got != n {
			t.Errorf("round trip = %d, want %d", got, n)
		}
	}
}
