package models

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
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

func TestGroundTruthFileRootPID(t *testing.T) {
	data, err := json.Marshal(GroundTruthFile{Events: sampleEvents(), RootPID: 4242})
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseGroundTruthFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if f.RootPID != 4242 {
		t.Errorf("RootPID round trip = %d, want 4242", f.RootPID)
	}

	// A file without the field, and the legacy array, read as no root.
	legacyObj, _ := json.Marshal(map[string]any{"events": sampleEvents()})
	f, err = ParseGroundTruthFile(legacyObj)
	if err != nil || f.RootPID != 0 {
		t.Errorf("object without root_pid: RootPID = %d, err = %v, want 0", f.RootPID, err)
	}
	arr, _ := json.Marshal(sampleEvents())
	f, err = ParseGroundTruthFile(arr)
	if err != nil || f.RootPID != 0 {
		t.Errorf("legacy array: RootPID = %d, err = %v, want 0", f.RootPID, err)
	}
	// Zero is omitted rather than written, so an absent root is never
	// mistaken for a recorded one.
	zero, _ := json.Marshal(GroundTruthFile{Events: sampleEvents()})
	if strings.Contains(string(zero), "root_pid") {
		t.Errorf("zero RootPID was written: %s", zero)
	}
}

// Schema 2 adds Diagnostics and nothing else: a schema 1 record still reads,
// with nil Diagnostics (not measured), and a schema 2 record keeps its
// diagnostics, a measured zero included, through a write and a read.
func TestParseGroundTruthFile_SchemaVersions(t *testing.T) {
	events := sampleEvents()
	for _, tc := range []struct {
		schema  int
		wantErr bool
	}{{0, true}, {1, false}, {2, false}, {3, true}} {
		data, _ := json.Marshal(GroundTruthFile{Events: events, Coverage: &Coverage{Schema: tc.schema, Probes: map[string]ProbeCoverage{"proc": {Ran: true}}}})
		f, err := ParseGroundTruthFile(data)
		if (err != nil) != tc.wantErr {
			t.Errorf("schema %d: err = %v, want error %v", tc.schema, err, tc.wantErr)
			continue
		}
		if err == nil && f.Coverage.Probes["proc"].Diagnostics != nil {
			t.Errorf("schema %d: Diagnostics = %+v, want nil when absent", tc.schema, f.Coverage.Probes["proc"].Diagnostics)
		}
	}

	zero := uint64(0)
	d := &ProbeDiagnostics{
		Rings:       map[string]RingStats{"ssl_events": {SizeBytes: 4 << 20, PeakBytes: 1234, Records: 9, Drops: 0, ReadDrops: &zero}},
		TrackedSets: map[string]TrackedSetStats{"tls": {Capacity: 4096, Peak: 3, AtStop: 1}},
		NetContent:  &NetContentCounts{Connections: 5, ContentUnsupported: 2, H2Preface: 1},
	}
	data, _ := json.Marshal(GroundTruthFile{Events: events, Coverage: &Coverage{Schema: CoverageSchema, Probes: map[string]ProbeCoverage{"net": {Ran: true, Diagnostics: d}}}})
	for _, key := range []string{`"read_drops":0`, `"drops":0`, `"with_content":0`, `"h2_preface":1`, `"at_stop":1`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("%s missing from %s", key, data)
		}
	}
	f, err := ParseGroundTruthFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Coverage.Probes["net"].Diagnostics; !reflect.DeepEqual(got, d) {
		t.Errorf("round trip = %+v, want %+v", got, d)
	}
	plain, _ := json.Marshal(ProbeCoverage{Ran: true})
	if strings.Contains(string(plain), "diagnostics") {
		t.Errorf("nil Diagnostics was written: %s", plain)
	}
}

// Every ground truth file checked into the repository parses under this
// build, and none carries diagnostics, so their verification cannot depend
// on them.
func TestParseGroundTruthFile_EveryFixtureParses(t *testing.T) {
	n := 0
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, "ground_truth.json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := ParseGroundTruthFile(data)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		n++
		if f.Coverage == nil {
			return nil
		}
		for name, p := range f.Coverage.Probes {
			if p.Diagnostics != nil {
				t.Errorf("%s: probe %s carries diagnostics", path, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 50 {
		t.Errorf("parsed %d fixtures, want the repository's (at least 50)", n)
	}
}
