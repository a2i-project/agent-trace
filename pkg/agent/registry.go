package agent

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

var (
	mu       sync.RWMutex
	adapters = map[string]Adapter{}
)

// Register adds an adapter. It panics on a duplicate or empty name, since both
// are programming errors found at start-up. Adapters call it from init.
func Register(a Adapter) {
	mu.Lock()
	defer mu.Unlock()
	if a.Name() == "" {
		panic("agent: adapter with an empty name")
	}
	if _, dup := adapters[a.Name()]; dup {
		panic(fmt.Sprintf("agent: adapter %q registered twice", a.Name()))
	}
	adapters[a.Name()] = a
}

// Lookup returns the adapter registered under name.
func Lookup(name string) (Adapter, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := adapters[name]
	return a, ok
}

// Names lists the registered adapters, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(adapters))
	for n := range adapters {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ErrNoMatch is wrapped by Detect when no adapter recognises a path, so a
// caller can tell it from an ambiguity and fall back to the generic adapter.
var ErrNoMatch = errors.New("no adapter recognises the path")

// Detect returns the adapter that recognises path. The generic adapter never
// detects, so a path no real adapter claims returns false. Two adapters
// claiming the same path is an error rather than a guess.
func Detect(path string) (Adapter, error) {
	mu.RLock()
	defer mu.RUnlock()
	var found []string
	var match Adapter
	for _, n := range sortedLocked() {
		if a := adapters[n]; a.Detect(path) {
			found = append(found, n)
			match = a
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: %s (registered: %v)", ErrNoMatch, path, sortedLocked())
	case 1:
		return match, nil
	default:
		return nil, fmt.Errorf("%s is recognised by several adapters %v, choose one with --agent", path, found)
	}
}

func sortedLocked() []string {
	names := make([]string, 0, len(adapters))
	for n := range adapters {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
