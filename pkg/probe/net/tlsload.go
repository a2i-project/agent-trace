package net

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/cilium/ebpf"
)

// Which tls.bpf.c programs a capture loads (N-48): the fork and exit hooks,
// which every content method needs, and the programs of each configured
// method, with the maps those programs use. A method that is not configured
// is not loaded, so its verifier verdict cannot affect another method:
// Claude Code's tls-symbols loads what it loaded before Go's probes existed.

// tlsCommonPrograms serve every content method.
var tlsCommonPrograms = []string{"handle_fork", "handle_exit"}

// tlsMethodPrograms are the programs of each content method.
var tlsMethodPrograms = map[string][]string{
	MethodTLSSymbols: {"probe_ssl_write", "probe_ssl_write_return", "probe_ssl_read_entry", "probe_ssl_read_return"},
	MethodOpenSSLEx:  {"probe_ssl_write_ex", "probe_ssl_write_ex_return", "probe_ssl_read_ex_entry", "probe_ssl_read_ex_return"},
	MethodRustlsAEAD: {"probe_aead_encrypt", "probe_aead_decrypt_entry", "probe_aead_decrypt_return", "aead_sys_enter"},
	MethodGoCrypto:   {"probe_go_write", "probe_go_write_ret", "probe_go_read", "probe_go_read_ret"},
}

// tlsUserMaps are the maps userspace reads or writes for each content
// method, "" for every capture with content. Each is loaded with its method
// even when none of the loaded programs references it (ssl_read_counting is
// referenced by the _ex programs only, and tls-symbols's validation sets it
// all the same). TestTLSUserMaps_CoverEveryAccess checks this table against
// every access to the objects in the package's code.
var tlsUserMaps = map[string][]string{
	"":               {"tracked_pids", "tracked_stat", "tracked_seeded"},
	MethodTLSSymbols: {"ssl_events", "ssl_write_counting", "ssl_write_stat", "ssl_read_counting"},
	MethodOpenSSLEx:  {"ssl_events", "ssl_write_counting", "ssl_write_stat", "ssl_read_counting"},
	MethodRustlsAEAD: {"aead_cfg", "aead_events"},
	MethodGoCrypto:   {"go_events", "go_stat"},
}

// tlsCounterMaps are the counters kernelCounters reads when they are
// loaded: a counter whose programs are not loaded counts nothing, so its
// absence reads as zero.
var tlsCounterMaps = []string{"faulted_reads", "drop_count", "untracked_count", "read_fault_count", "read_drop_count", "aead_drop_count", "go_drop_count"}

// methods lists the configured content methods.
func (p contentPlan) methods() []string {
	var m []string
	if p.sslPath != "" {
		m = append(m, p.sslMethod)
	}
	if p.aeadPath != "" {
		m = append(m, MethodRustlsAEAD)
	}
	if p.goPath != "" {
		m = append(m, MethodGoCrypto)
	}
	return m
}

// selectTLSPrograms keeps in spec the common programs and those of methods,
// the maps they reference (their own instructions and the functions they
// call) and the maps userspace uses for those methods (tlsUserMaps), and
// removes every other program and map. It fails when a listed program or
// map is missing or a method is unknown.
func selectTLSPrograms(spec *ebpf.CollectionSpec, methods []string) error {
	keep := map[string]bool{}
	for _, name := range tlsCommonPrograms {
		keep[name] = true
	}
	for _, m := range methods {
		progs, ok := tlsMethodPrograms[m]
		if !ok {
			return fmt.Errorf("no tls programs for content method %q", m)
		}
		for _, name := range progs {
			keep[name] = true
		}
	}
	maps := map[string]bool{}
	for _, m := range append([]string{""}, methods...) {
		for _, name := range tlsUserMaps[m] {
			if spec.Maps[name] == nil {
				return fmt.Errorf("tls object has no map %s", name)
			}
			maps[name] = true
		}
	}
	for name := range keep {
		ps, ok := spec.Programs[name]
		if !ok {
			return fmt.Errorf("tls object has no program %s", name)
		}
		for _, ins := range ps.Instructions {
			if ref := ins.Reference(); ref != "" && spec.Maps[ref] != nil {
				maps[ref] = true
			}
		}
	}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	for name := range spec.Maps {
		if !maps[name] {
			delete(spec.Maps, name)
		}
	}
	return nil
}

// assignCollection moves the programs and maps of coll into the fields of
// dst (a bpf2go objects struct, by their ebpf tags) and closes coll; a field
// whose object was not loaded stays nil.
func assignCollection(dst any, coll *ebpf.Collection) {
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f, fv := t.Field(i), v.Field(i)
			if f.Anonymous && fv.Kind() == reflect.Struct {
				walk(fv)
				continue
			}
			tag := f.Tag.Get("ebpf")
			switch fv.Interface().(type) {
			case *ebpf.Program:
				if p := coll.DetachProgram(tag); p != nil {
					fv.Set(reflect.ValueOf(p))
				}
			case *ebpf.Map:
				if m := coll.DetachMap(tag); m != nil {
					fv.Set(reflect.ValueOf(m))
				}
			}
		}
	}
	walk(reflect.ValueOf(dst).Elem())
	coll.Close()
}

// sortedNames returns the keys of a program or map set, sorted.
func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
