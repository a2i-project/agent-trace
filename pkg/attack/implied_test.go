package attack

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// impliedSession is a trajectory with harness-implied claims around the
// agent's own: a Bash call that reads a file (one implied open after it), a
// Read, and a WebFetch whose domain check is implied before its own claims.
func impliedSession() models.Trajectory {
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	return models.Trajectory{
		{Timestamp: at(1), ActionType: models.ProcessExec, Tool: "Bash", Target: "cat a"},
		{Timestamp: at(1), ActionType: models.FileOpen, Tool: "Bash", Target: "/w/a", ImpliedBy: "cat a"},
		{Timestamp: at(2), ActionType: models.FileOpen, Tool: "Read", Target: "/w/b"},
		{Timestamp: at(3), ActionType: models.NetRequest, Tool: "WebFetch", Target: "GET https://check/h", ImpliedBy: "WebFetch https://h/x", ImpliedBefore: true},
		{Timestamp: at(3), ActionType: models.NetConnect, Tool: "WebFetch", Target: "h"},
		{Timestamp: at(3), ActionType: models.NetRequest, Tool: "WebFetch", Target: "GET https://h/x"},
		{Timestamp: at(4), ActionType: models.FileOpen, Tool: "Read", Target: "/w/c"},
	}
}

func targets(t models.Trajectory) []string {
	var out []string
	for _, e := range t {
		out = append(out, e.Target)
	}
	return out
}

func sameTargets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWithImpliedPutsTheAdaptersClaimsBack(t *testing.T) {
	full := impliedSession()
	own, n := WithoutImplied(full)
	if n != 2 {
		t.Fatalf("%d implied claims, want 2", n)
	}
	if got := WithImplied(full, own, Record{}); !sameTargets(targets(got), targets(full)) {
		t.Fatalf("round trip: %v", targets(got))
	}
	cases := []struct {
		name string
		mut  func() (models.Trajectory, Record, error)
		want []string
	}{
		{"the Read omitted", func() (models.Trajectory, Record, error) { return Omit(own, Options{Indices: []int{1}}) },
			[]string{"cat a", "/w/a", "GET https://check/h", "h", "GET https://h/x", "/w/c"}},
		{"the Bash call omitted: its implied open goes with it", func() (models.Trajectory, Record, error) { return Omit(own, Options{Indices: []int{0}}) },
			[]string{"/w/b", "GET https://check/h", "h", "GET https://h/x", "/w/c"}},
		{"part of the WebFetch omitted: its check stays", func() (models.Trajectory, Record, error) { return Omit(own, Options{Indices: []int{2}}) },
			[]string{"cat a", "/w/a", "/w/b", "GET https://check/h", "GET https://h/x", "/w/c"}},
		{"the whole WebFetch omitted, retimed: its check goes", func() (models.Trajectory, Record, error) {
			return Omit(own, Options{Indices: []int{2, 3}, Retime: true})
		}, []string{"cat a", "/w/a", "/w/b", "/w/c"}},
		{"the command substituted: its implied open goes", func() (models.Trajectory, Record, error) {
			return Substitute(own, SubstituteOptions{Options: Options{Indices: []int{0}}, Field: FieldTarget})
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut, rec, err := tc.mut()
			if err != nil {
				t.Fatal(err)
			}
			got := WithImplied(full, mut, rec)
			want := tc.want
			if want == nil {
				want = append([]string{mut[0].Target}, targets(full)[2:]...)
			}
			if !sameTargets(targets(got), want) {
				t.Errorf("got %v, want %v", targets(got), want)
			}
		})
	}
	// A fabrication keeps every implied claim after its own claim, and the
	// agent's claims are the mutated trajectory, in order.
	for seed := uint64(0); seed < 50; seed++ {
		for _, g := range []func(models.Trajectory, Options) (models.Trajectory, Record, error){Omit, Fabricate, func(t models.Trajectory, o Options) (models.Trajectory, Record, error) {
			return Substitute(t, SubstituteOptions{Options: o})
		}} {
			mut, rec, err := g(own, Options{N: 2, Seed: seed})
			if err != nil {
				continue
			}
			got := WithImplied(full, mut, rec)
			if back, _ := WithoutImplied(got); !sameTargets(targets(back), targets(mut)) {
				t.Fatalf("seed %d %s: own claims %v, mutated %v", seed, rec.Kind, targets(back), targets(mut))
			}
			if rec.Kind == Fabrication {
				if _, n := WithoutImplied(got); n != 2 {
					t.Fatalf("seed %d: a fabrication dropped implied claims: %v", seed, targets(got))
				}
			}
		}
	}
}
