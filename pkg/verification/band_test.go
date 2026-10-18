package verification

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// laneGen draws lanes for the comparison of the banded program with the
// whole table (V-42).
type laneGen struct {
	rng   *rand.Rand
	paths []string
}

var genTypes = []models.ActionType{
	models.FileOpen, models.FileWrite, models.FileClose, models.FileRename,
	models.ProcessExec, models.ProcessExit, models.NetConnect, models.NetRequest,
}

func (g laneGen) hash() *string {
	if g.rng.Intn(3) > 0 {
		return nil
	}
	h := fmt.Sprintf("sha256:%d", g.rng.Intn(3))
	return &h
}

// entry is a claim; event is an observed action that agrees with it, and
// drift changes the event's target, type or content.
func (g laneGen) entry(ms int) models.TrajectoryEntry {
	c := models.TrajectoryEntry{Timestamp: at(ms), ActionType: genTypes[g.rng.Intn(len(genTypes))], Target: g.paths[g.rng.Intn(len(g.paths))]}
	switch c.ActionType {
	case models.FileClose, models.FileWrite:
		c.OutputHash = g.hash()
	case models.ProcessExit:
		if g.rng.Intn(2) == 0 {
			code := int32(g.rng.Intn(2))
			c.ExitCode = &code
		}
	case models.NetRequest:
		c.RequestHash = g.hash()
	case models.FileOpen:
		c.InputHash = g.hash()
		if g.rng.Intn(4) == 0 {
			c.ImpliedBy = "cmd"
		}
	}
	if g.rng.Intn(2) == 0 {
		end := c.Timestamp.Add(time.Duration(g.rng.Intn(400)) * time.Millisecond)
		c.End = &end
	}
	return c
}

func (g laneGen) event(c models.TrajectoryEntry, ms int) models.GroundTruthEvent {
	e := models.GroundTruthEvent{Timestamp: at(ms), ActionType: c.ActionType, Target: c.Target, InputHash: c.InputHash, OutputHash: c.OutputHash, ExitCode: c.ExitCode, RequestHash: c.RequestHash}
	switch g.rng.Intn(12) {
	case 0:
		e.Target = g.paths[g.rng.Intn(len(g.paths))]
	case 1:
		e.ActionType = genTypes[g.rng.Intn(len(genTypes))]
	case 2:
		e.OutputHash, e.InputHash = g.hash(), g.hash()
	case 3:
		e.Target, e.TargetTruncated = e.Target[:len(e.Target)/2], true
	}
	return e
}

// session draws n claims in blocks and the events an agent doing them would
// cause, with omissions, fabrications, drift, blocks completed out of order
// and harness events at the given rates (per mille).
func (g laneGen) session(n, omit, fabricate, surplus int) (models.Trajectory, models.GroundTruth) {
	var c models.Trajectory
	var o models.GroundTruth
	ms := 0
	for len(c) < n {
		k := 1
		if g.rng.Intn(3) == 0 {
			k = 1 + g.rng.Intn(12) // over maxBlock now and then
		}
		id := ""
		if k > 1 {
			id = fmt.Sprintf("b%d", g.rng.Intn(1+n/4)) // a reused id makes a block non-contiguous
		}
		var block models.Trajectory
		var evs models.GroundTruth
		for t := 0; t < k; t++ {
			ms += 1 + g.rng.Intn(50)
			e := g.entry(ms)
			e.BlockID = id
			block = append(block, e)
			if g.rng.Intn(1000) >= fabricate {
				evs = append(evs, g.event(e, ms+g.rng.Intn(300)))
			}
			if g.rng.Intn(1000) < omit {
				evs = append(evs, g.event(g.entry(ms), ms+g.rng.Intn(300)))
			}
		}
		g.rng.Shuffle(len(evs), func(a, b int) { evs[a], evs[b] = evs[b], evs[a] })
		for g.rng.Intn(1000) < surplus {
			evs = append(evs, g.event(g.entry(ms), ms+g.rng.Intn(300)))
		}
		c = append(c, block...)
		o = append(o, evs...)
	}
	return c, o
}

func compareWithTheWholeTable(t *testing.T, name string, c models.Trajectory, o models.GroundTruth, opts Options) {
	t.Helper()
	got, gotErr := Align(c, o, opts)
	want, wantErr := refAlign(c, o, opts)
	if gotErr != wantErr {
		t.Fatalf("%s: err %v, the whole table gives %v", name, gotErr, wantErr)
	}
	if !reflect.DeepEqual(got, want) {
		for i := range want {
			if i < len(got) && !reflect.DeepEqual(got[i], want[i]) {
				t.Fatalf("%s: lane %s differs: Optimal %d/%d, %d/%d edits\nclaims %+v\nevents %+v", name, want[i].Lane, got[i].Optimal, want[i].Optimal, len(got[i].Edits), len(want[i].Edits), c, o)
			}
		}
		t.Fatalf("%s: %d lanes, the whole table gives %d", name, len(got), len(want))
	}
}

// The banded program (V-42) gives every lane the whole table gives: the same
// edits, diffs, interval and unverified marks, count and degradations, on
// lanes small enough to differ everywhere and on long ones whose band is
// narrow, with omissions, fabrications, drift and harness surplus, blocks in
// and out of order, over the cap and non-contiguous, harness-implied claims,
// exits and truncated targets.
func TestAlign_TheBandGivesWhatTheWholeTableGives(t *testing.T) {
	g := laneGen{rng: rand.New(rand.NewSource(42)), paths: []string{"/w/a", "/w/b", "/w/c", "/w/dir/d"}}
	for trial := 0; trial < 3000; trial++ {
		c, o := g.session(1+g.rng.Intn(8), 1000*g.rng.Intn(2)/3, 1000*g.rng.Intn(2)/3, 400)
		opts := Options{IntervalSlack: time.Duration(g.rng.Intn(2)) * 100 * time.Millisecond}
		compareWithTheWholeTable(t, fmt.Sprintf("small %d", trial), c, o, opts)
	}
	trials := 60
	if testing.Short() {
		trials = 10
	}
	g.paths = nil
	for i := 0; i < 40; i++ {
		g.paths = append(g.paths, fmt.Sprintf("/w/f%d", i))
	}
	for trial := 0; trial < trials; trial++ {
		rates := [][3]int{{0, 0, 0}, {0, 0, 300}, {20, 20, 100}, {100, 100, 500}, {300, 0, 0}}[trial%5]
		c, o := g.session(50+g.rng.Intn(250), rates[0], rates[1], rates[2])
		compareWithTheWholeTable(t, fmt.Sprintf("long %d rates %v", trial, rates), c, o, Options{IntervalSlack: 50 * time.Millisecond})
	}
}

// A long honest lane aligns in a band a few cells wide, where the whole table
// was refused before V-42.
func TestAlign_ALongHonestLaneAligns(t *testing.T) {
	var c models.Trajectory
	var o models.GroundTruth
	for i := 0; i < 5000; i++ {
		c = append(c, claim(models.FileOpen, "/w/a"))
		o = append(o, obs(models.FileOpen, "/w/a"))
	}
	as, err := Align(c, o, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a := as[0]; a.Optimal != 1 || len(a.Edits) != 5000 || countKinds(a)[EditMatch] != 5000 {
		t.Errorf("Optimal %d, %v", a.Optimal, countKinds(a))
	}
}
