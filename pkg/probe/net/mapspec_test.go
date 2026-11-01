package net

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// Kernel limits on map sizes that a map create checks, so that a spec
// beyond them fails with E2BIG only when loaded as root. Values from Linux
// 6.x (include/linux/percpu.h, kernel/bpf/arraymap.c, hashtab.c,
// ringbuf.c), the strictest of the kernels CI runs.
const (
	pcpuMinUnitSize = 32 << 10 // PCPU_MIN_UNIT_SIZE: a per-CPU value
	kmallocMaxSize  = 4 << 20  // KMALLOC_MAX_SIZE with 4 KiB pages (order 10)
	maxBPFStack     = 512      // MAX_BPF_STACK: a hash key
	htabElemSize    = 64       // more than sizeof(struct htab_elem)
)

// checkMapLimits reports every map of spec outside the kernel's limits.
func checkMapLimits(t *testing.T, object string, spec *ebpf.CollectionSpec) {
	t.Helper()
	page := uint32(os.Getpagesize())
	for name, m := range spec.Maps {
		round8 := (m.ValueSize + 7) &^ 7
		switch m.Type {
		case ebpf.PerCPUArray, ebpf.PerCPUHash, ebpf.LRUCPUHash:
			if round8 > pcpuMinUnitSize {
				t.Errorf("%s: per-CPU map %s has a %d-byte value, above the kernel's %d", object, name, m.ValueSize, pcpuMinUnitSize)
			}
		case ebpf.Array:
			if m.ValueSize > kmallocMaxSize {
				t.Errorf("%s: array %s has a %d-byte value, above %d", object, name, m.ValueSize, kmallocMaxSize)
			}
		case ebpf.Hash, ebpf.LRUHash:
			if m.KeySize > maxBPFStack {
				t.Errorf("%s: hash %s has a %d-byte key, above %d", object, name, m.KeySize, maxBPFStack)
			}
			if m.ValueSize >= kmallocMaxSize-maxBPFStack-htabElemSize {
				t.Errorf("%s: hash %s has a %d-byte value, too large", object, name, m.ValueSize)
			}
		case ebpf.RingBuf:
			if n := m.MaxEntries; n == 0 || n&(n-1) != 0 || n%page != 0 {
				t.Errorf("%s: ring buffer %s has size %d, not a power of two and a multiple of the %d-byte page", object, name, n, page)
			}
		}
		if m.Type == ebpf.PerCPUArray || m.Type == ebpf.Array || m.Type == ebpf.Hash || m.Type == ebpf.LRUHash || m.Type == ebpf.PerCPUHash {
			if m.KeySize == 0 || m.ValueSize == 0 || m.MaxEntries == 0 {
				t.Errorf("%s: map %s has a zero key, value or entry count", object, name)
			}
		}
	}
}

// TestTLSMapSpecsWithinKernelLimits checks, unprivileged, every map of the
// tls and net objects against the kernel's size limits, including the
// rustls ring as prepareTLS shrinks it when that method is not configured:
// a value past a limit fails every content capture with E2BIG at load,
// which only a privileged run would otherwise show.
func TestTLSMapSpecsWithinKernelLimits(t *testing.T) {
	tls, err := loadTlsbpf()
	if err != nil {
		t.Fatal(err)
	}
	checkMapLimits(t, "tls.bpf.c", tls)
	tls.Maps["aead_events"].MaxEntries = uint32(os.Getpagesize())
	checkMapLimits(t, "tls.bpf.c without tls-rustls-aead", tls)
	if tls.Maps["ssl_heap"].ValueSize > pcpuMinUnitSize {
		t.Errorf("ssl_heap value %d", tls.Maps["ssl_heap"].ValueSize)
	}
	net, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	checkMapLimits(t, "net.bpf.c", net)
}
