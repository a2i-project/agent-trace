package proc

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/ringbuf"
)

// fakeObjects returns bpfObjects whose programs are distinct placeholders,
// and the program name of each placeholder, so the attach lists can be
// checked without loading anything.
func fakeObjects(t *testing.T) (*bpfObjects, map[*ebpf.Program]string) {
	t.Helper()
	objs := &bpfObjects{}
	names := map[*ebpf.Program]string{}
	v := reflect.ValueOf(&objs.bpfPrograms).Elem()
	for i := 0; i < v.NumField(); i++ {
		p := new(ebpf.Program)
		v.Field(i).Set(reflect.ValueOf(p))
		names[p] = v.Type().Field(i).Tag.Get("ebpf")
	}
	return objs, names
}

// Every program in proc.bpf.c is a raw tracepoint, attached by New or
// tail-called in the sys_enter chain, in the slot order of enum sys_slot
// (P-32, P-36). A perf-event tracepoint section would bring back the
// kernel 7.0 exec loss and the slow detach. Runs without root.
func TestHooks_EveryProgramIsARawTracepointAndIsWired(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}
	for name, ps := range spec.Programs {
		if ps.Type != ebpf.RawTracepoint || !strings.HasPrefix(ps.SectionName, "raw_tracepoint/") {
			t.Errorf("program %s is %v in section %q, want a raw tracepoint", name, ps.Type, ps.SectionName)
		}
	}

	objs, names := fakeObjects(t)
	wired := map[string]bool{}

	wantAttach := map[string]string{
		"task_newtask":       "handle_fork",
		"sched_process_exec": "handle_exec_ok",
		"sched_process_exit": "handle_exit",
		"sys_enter":          "trace_sys_enter",
	}
	attach := procRawTracepoints(objs)
	if len(attach) != len(wantAttach) {
		t.Errorf("procRawTracepoints has %d entries, want %d", len(attach), len(wantAttach))
	}
	for _, tp := range attach {
		got := names[tp.prog]
		if wantAttach[tp.name] != got {
			t.Errorf("raw tracepoint %s runs %q, want %q", tp.name, got, wantAttach[tp.name])
		}
		if section := "raw_tracepoint/" + tp.name; spec.Programs[got] != nil && spec.Programs[got].SectionName != section {
			t.Errorf("program %s is in section %q, attached to %s", got, spec.Programs[got].SectionName, tp.name)
		}
		wired[got] = true
	}

	// enum sys_slot: SLOT_EXECVE, SLOT_EXECVEAT, SLOT_EXEC_CWD.
	wantSlots := []string{"handle_execve", "handle_execveat", "handle_exec_cwd"}
	slots := sysEnterPrograms(objs)
	if got := spec.Maps["sys_enter_progs"].MaxEntries; int(got) != len(slots) {
		t.Errorf("sys_enter_progs has %d slots, sysEnterPrograms fills %d", got, len(slots))
	}
	for i, p := range slots {
		got := names[p]
		if i >= len(wantSlots) || got != wantSlots[i] {
			t.Errorf("slot %d holds %q, want %v", i, got, wantSlots)
			continue
		}
		if spec.Programs[got].SectionName != "raw_tracepoint/sys_enter" {
			t.Errorf("tail-called program %s is in section %q, want raw_tracepoint/sys_enter", got, spec.Programs[got].SectionName)
		}
		wired[got] = true
	}

	for name := range spec.Programs {
		if !wired[name] {
			t.Errorf("program %s is neither attached nor in a sys_enter slot", name)
		}
	}
}

type fakeDeadline struct{ set bool }

func (f *fakeDeadline) SetDeadline(time.Time) { f.set = true }

// readLoop drains the ring at Stop: a flush sets the deadline and keeps
// reading, a deadline or a closed reader ends the loop, anything else is
// retried (P-32).
func TestDrainRead(t *testing.T) {
	for _, c := range []struct {
		name         string
		err          error
		stop, setDdl bool
	}{
		{"flush starts the drain", ringbuf.ErrFlushed, false, true},
		{"an empty ring after the flush ends it", os.ErrDeadlineExceeded, true, false},
		{"a closed reader ends it", ringbuf.ErrClosed, true, false},
		{"another error is retried", errors.New("EINTR"), false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var d fakeDeadline
			if got := drainRead(&d, c.err); got != c.stop {
				t.Errorf("stop = %v, want %v", got, c.stop)
			}
			if d.set != c.setDdl {
				t.Errorf("deadline set = %v, want %v", d.set, c.setDdl)
			}
		})
	}
}

// hasCycle reports whether the instructions' control flow has a cycle: a
// jump that reaches an instruction on its own path. Calls fall through.
func hasCycle(insns asm.Instructions) bool {
	index := map[asm.RawInstructionOffset]int{}
	var raw []asm.RawInstructionOffset
	iter := insns.Iterate()
	for iter.Next() {
		index[iter.Offset] = len(raw)
		raw = append(raw, iter.Offset)
	}
	succ := func(i int) []int {
		in := insns[i]
		op := in.OpCode
		var next []int
		fall := i + 1
		if op.Class().IsJump() {
			switch op.JumpOp() {
			case asm.Exit:
				return nil
			case asm.Call:
			default:
				target := raw[i] + asm.RawInstructionOffset(in.Size()/asm.InstructionSize) + asm.RawInstructionOffset(in.Offset)
				if t, ok := index[target]; ok {
					next = append(next, t)
				}
				if op.JumpOp() == asm.Ja {
					return next
				}
			}
		}
		if fall < len(insns) {
			next = append(next, fall)
		}
		return next
	}
	const white, grey, black = 0, 1, 2
	color := make([]int, len(insns))
	var visit func(int) bool
	visit = func(i int) bool {
		color[i] = grey
		for _, j := range succ(i) {
			if color[j] == grey || (color[j] == white && visit(j)) {
				return true
			}
		}
		color[i] = black
		return false
	}
	for i := range insns {
		if color[i] == white && visit(i) {
			return true
		}
	}
	return false
}

// No program holds a loop the verifier must walk path by path: the argument
// loop is unrolled, and the path walk runs one step per bpf_loop call, whose
// callback the verifier checks once (P-36). An open-coded walk exceeded the
// verifier's million instructions on Linux 7.0. Runs without root; the load
// itself is checked by the privileged tests.
func TestSpec_NoOpenCodedLoops(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}
	for name, ps := range spec.Programs {
		if hasCycle(ps.Instructions) {
			t.Errorf("program %s has a loop in its control flow", name)
		}
	}
	for _, name := range []string{"handle_exec_cwd", "handle_exec_ok"} {
		loops := 0
		for _, in := range spec.Programs[name].Instructions {
			if in.IsBuiltinCall() && in.Constant == int64(asm.FnLoop) {
				loops++
			}
		}
		if loops != 1 {
			t.Errorf("program %s calls bpf_loop %d times, want the path walk's one", name, loops)
		}
	}
}
