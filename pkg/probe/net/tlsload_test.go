package net

import (
	"reflect"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Every program of tls.bpf.c belongs to the common set or to exactly one
// content method, so a new program cannot be loaded by default.
func TestTLSPrograms_EachBelongsToOneMethod(t *testing.T) {
	spec, err := loadTlsbpf()
	if err != nil {
		t.Fatal(err)
	}
	owner := map[string]string{}
	add := func(m string, names []string) {
		for _, n := range names {
			if prev, ok := owner[n]; ok {
				t.Errorf("program %s listed for %s and %s", n, prev, m)
			}
			owner[n] = m
		}
	}
	add("common", tlsCommonPrograms)
	for m, names := range tlsMethodPrograms {
		add(m, names)
	}
	for name := range spec.Programs {
		if _, ok := owner[name]; !ok {
			t.Errorf("program %s belongs to no content method", name)
		}
	}
	for name := range owner {
		if spec.Programs[name] == nil {
			t.Errorf("listed program %s is not in the object", name)
		}
	}
}

// The programs selected for loading depend only on the configured methods:
// exactly the common ones and those of each configured method, with the
// maps they reference and no others. Claude Code's tls-symbols loads no Go,
// rustls or _ex program and none of their rings.
func TestSelectTLSPrograms_OnlyTheConfiguredMethods(t *testing.T) {
	all := []string{MethodTLSSymbols, MethodOpenSSLEx, MethodRustlsAEAD, MethodGoCrypto}
	for mask := 0; mask < 1<<len(all); mask++ {
		var methods []string
		for i, m := range all {
			if mask&(1<<i) != 0 {
				methods = append(methods, m)
			}
		}
		spec, err := loadTlsbpf()
		if err != nil {
			t.Fatal(err)
		}
		full, _ := loadTlsbpf()
		if err := selectTLSPrograms(spec, methods); err != nil {
			t.Fatalf("%v: %v", methods, err)
		}
		want := append([]string{}, tlsCommonPrograms...)
		for _, m := range methods {
			want = append(want, tlsMethodPrograms[m]...)
		}
		sort.Strings(want)
		if got := sortedNames(spec.Programs); !reflect.DeepEqual(got, want) {
			t.Errorf("%v: programs %v, want %v", methods, got, want)
		}
		wantMaps := map[string]bool{}
		for _, name := range want {
			for _, ins := range full.Programs[name].Instructions {
				if ref := ins.Reference(); full.Maps[ref] != nil {
					wantMaps[ref] = true
				}
			}
		}
		if got := sortedNames(spec.Maps); !reflect.DeepEqual(got, sortedNames(wantMaps)) {
			t.Errorf("%v: maps %v, want %v", methods, got, sortedNames(wantMaps))
		}
	}
	spec, _ := loadTlsbpf()
	if err := selectTLSPrograms(spec, []string{MethodTLSSymbols}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"go_events", "go_args", "go_stat", "aead_events", "aead_cfg", "pending_enc"} {
		if spec.Maps[m] != nil {
			t.Errorf("tls-symbols alone loads map %s", m)
		}
	}
	for _, m := range []string{"ssl_events", "ssl_write_args", "ssl_read_args", "tracked_pids", "ssl_write_stat"} {
		if spec.Maps[m] == nil {
			t.Errorf("tls-symbols does not load map %s", m)
		}
	}
	if err := selectTLSPrograms(spec, []string{"tls-nothing"}); err == nil {
		t.Error("an unknown method selected programs")
	}
}

// assignCollection fills the fields of the objects struct whose objects
// were loaded and leaves the others nil.
func TestAssignCollection_LeavesUnloadedFieldsNil(t *testing.T) {
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}, Maps: map[string]*ebpf.Map{}}
	var objs tlsbpfObjects
	assignCollection(&objs, coll)
	if objs.ProbeGoReadRet != nil || objs.SslEvents != nil {
		t.Error("fields set from an empty collection")
	}
}

// The Go return probes copy their chunks in a bpf_loop callback, not an
// open-coded loop, which the verifier on Linux 7.0 rejected as too large
// (N-48, as for the proc probe's path walk, P-36).
func TestGoReturnProbes_NoOpenCodedLoop(t *testing.T) {
	spec, err := loadTlsbpf()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"probe_go_write_ret", "probe_go_read_ret"} {
		insns := spec.Programs[name].Instructions
		if hasJumpBack(insns) {
			t.Errorf("program %s has a loop in its control flow", name)
		}
		loops := 0
		for _, in := range insns {
			if in.IsBuiltinCall() && in.Constant == int64(asm.FnLoop) {
				loops++
			}
		}
		if loops != 1 {
			t.Errorf("program %s calls bpf_loop %d times, want 1", name, loops)
		}
	}
}

// hasJumpBack reports whether a jump inside insns targets an earlier
// instruction: clang compiles a bounded loop with one, and the program's
// functions (the bpf_loop callback among them) have none.
func hasJumpBack(insns asm.Instructions) bool {
	index := map[asm.RawInstructionOffset]int{}
	var raw []asm.RawInstructionOffset
	iter := insns.Iterate()
	for iter.Next() {
		index[iter.Offset] = len(raw)
		raw = append(raw, iter.Offset)
	}
	for i, in := range insns {
		op := in.OpCode
		if !op.Class().IsJump() || op.JumpOp() == asm.Exit || op.JumpOp() == asm.Call {
			continue
		}
		target := raw[i] + asm.RawInstructionOffset(in.Size()/asm.InstructionSize) + asm.RawInstructionOffset(in.Offset)
		if t, ok := index[target]; ok && t <= i {
			return true
		}
	}
	return false
}
