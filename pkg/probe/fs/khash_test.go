package fs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// fakeKhash stands in for the kernel copy: it holds the records lookup
// returns.
type fakeKhash struct {
	records map[khashKey]khashRecord
	synced  int
}

func (f *fakeKhash) sync() { f.synced++ }
func (f *fakeKhash) lookup(k khashKey) (khashRecord, bool) {
	r, ok := f.records[k]
	return r, ok
}
func (f *fakeKhash) losses() (uint64, uint64) { return 0, 0 }
func (f *fakeKhash) close()                   {}

func TestLsmListHasBPF(t *testing.T) {
	for list, want := range map[string]bool{
		"lockdown,capability,landlock,yama,apparmor,bpf,ima,evm\n": true,
		"lockdown,capability,landlock,yama,apparmor,ima,evm":       false,
		"bpf":         true,
		"bpffs,other": false,
		"":            false,
	} {
		if got := lsmListHasBPF(list); got != want {
			t.Errorf("lsmListHasBPF(%q) = %v, want %v", list, got, want)
		}
	}
}

// TestKernelDev checks the conversion between stat's device encoding and
// super_block.s_dev's (MKDEV: major << 20 | minor), both ways, for a minor
// number above 255, which the two encodings place differently.
func TestKernelDev(t *testing.T) {
	dev := unix.Mkdev(259, 300)
	if got, want := kernelDev(dev), uint32(259<<20|300); got != want {
		t.Fatalf("kernelDev = %#x, want %#x", got, want)
	}
	if got := userDev(uint64(kernelDev(dev))); got != dev {
		t.Fatalf("userDev(kernelDev(%#x)) = %#x", dev, got)
	}
}

func khashRaw(kdev, ino uint64, tgid, status uint32, body []byte) []byte {
	raw := make([]byte, khashHdrSize+len(body))
	le := binary.NativeEndian
	le.PutUint64(raw[0:], kdev)
	le.PutUint64(raw[8:], ino)
	le.PutUint64(raw[16:], uint64(len(body)))
	le.PutUint32(raw[24:], tgid)
	le.PutUint32(raw[28:], status)
	copy(raw[khashHdrSize:], body)
	return raw
}

func TestParseKhashRecord(t *testing.T) {
	body := []byte("content at the close\n")
	key, r, ok := parseKhashRecord(khashRaw(8<<20|1, 42, 7, khashOK, body))
	if !ok || key != (khashKey{dev: unix.Mkdev(8, 1), ino: 42, tgid: 7}) {
		t.Fatalf("key = %+v, ok = %v", key, ok)
	}
	if r.status != khashOK || r.digest != content.SHA256Bytes(body) {
		t.Fatalf("record = %+v, want the content's hash", r)
	}
	if _, r, ok := parseKhashRecord(khashRaw(1, 2, 3, khashWriter, nil)); !ok || r.status != khashWriter || r.digest != "" {
		t.Fatalf("status record = %+v, %v", r, ok)
	}
	if _, _, ok := parseKhashRecord(make([]byte, khashHdrSize-1)); ok {
		t.Fatal("a short record parsed")
	}
	short := khashRaw(1, 2, 3, khashOK, body)
	binary.NativeEndian.PutUint64(short[16:], uint64(len(body)+1))
	if _, _, ok := parseKhashRecord(short); ok {
		t.Fatal("a record shorter than its stated size parsed")
	}
}

// TestKernelHasher_TakeKeepsTheNewestRecord checks that the index keeps the
// newest record of a process's file, which a close takes (P-49).
func TestKernelHasher_TakeKeepsTheNewestRecord(t *testing.T) {
	k := &kernelHasher{latest: map[khashKey]khashRecord{}}
	k.take(khashRaw(1, 2, 3, khashOK, []byte("first")))
	k.take(khashRaw(1, 2, 3, khashOK, []byte("second")))
	k.take(khashRaw(1, 2, 4, khashWriter, nil))
	k.take([]byte{1, 2})
	r, ok := k.lookup(khashKey{dev: userDev(1), ino: 2, tgid: 3})
	if !ok || r.digest != content.SHA256Bytes([]byte("second")) {
		t.Fatalf("lookup = %+v, %v; want the second record", r, ok)
	}
	if k.consumed != 4 {
		t.Fatalf("consumed = %d, want 4 (a malformed record is consumed too)", k.consumed)
	}
}

// kernelHashObserver is newHashSeamObserver with the kernel copy faked: the
// record for the file at path, closed by this process, has the given status
// and content.
func kernelHashObserver(t *testing.T, dir, path string, status uint32, body []byte) (*Observer, *fakeKhash) {
	t.Helper()
	obs := newHashSeamObserver(t, dir, content.SHA256FD)
	key, _, ok := statxID(unix.AT_FDCWD, path, 0)
	if !ok {
		t.Fatalf("statx %s", path)
	}
	r := khashRecord{status: status}
	if status == khashOK {
		r.digest = content.SHA256Bytes(body)
	}
	fake := &fakeKhash{records: map[khashKey]khashRecord{{dev: key.dev, ino: key.ino, tgid: uint32(os.Getpid())}: r}}
	obs.khash = fake
	obs.hashes = &fileHashes{mode: khashModeKernel}
	return obs, fake
}

// TestObserver_KernelHashedCloseIgnoresWhatFollows: a close the kernel
// copied is published at once with the copy's hash, and an open of the file
// by the closing process afterwards, which withdraws a userspace hash
// (P-39), changes nothing; nor does the file's content changing after the
// close (P-48).
func TestObserver_KernelHashedCloseIgnoresWhatFollows(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(target, []byte("at close"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, _ := kernelHashObserver(t, dir, target, khashOK, []byte("at close"))
	pid := int32(os.Getpid())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: pid, Path: target}, time.Now())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN, PID: pid, Path: target}, time.Now())
	if err := os.WriteFile(target, []byte("rewritten later"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), true)

	var closes []models.GroundTruthEvent
	for _, e := range drainEvents(obs) {
		if e.ActionType == models.FileClose {
			closes = append(closes, e)
		}
	}
	if len(closes) != 1 || closes[0].OutputHash == nil || *closes[0].OutputHash != content.SHA256Bytes([]byte("at close")) {
		t.Fatalf("closes = %+v, want one with the hash of the content at the close", closes)
	}
	c := obs.hashes.counts(0, 0)
	if c.Kernel != 1 || c.Userspace != 0 || len(c.Fallbacks) != 0 {
		t.Fatalf("counts = %+v, want one kernel hash", c)
	}
	if h, ok := obs.lookupShadowHash(target, inodeKey{}, 0, false, false); !ok || h != *closes[0].OutputHash {
		t.Fatalf("settled hash = %q, %v; want the kernel's", h, ok)
	}
}

// TestObserver_KernelDeclinedCloseTakesTheUserspacePath: a close the kernel
// gave a status other than OK, or no record at all, goes through the settle
// protocol exactly as without the kernel copy, and the reason is counted.
func TestObserver_KernelDeclinedCloseTakesTheUserspacePath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status uint32
		match  bool
		reason string
	}{
		{"writer held", khashWriter, true, "writer_held"},
		{"not cached", khashNotCached, true, "not_cached"},
		{"too large", khashTooLarge, true, "too_large"},
		{"no record", khashOK, false, reasonUnmatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "out.txt")
			if err := os.WriteFile(target, []byte("final"), 0o644); err != nil {
				t.Fatal(err)
			}
			obs, fake := kernelHashObserver(t, dir, target, tc.status, []byte("final"))
			if !tc.match {
				fake.records = nil
			}
			obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, time.Now())
			if got := drainEvents(obs); len(got) != 0 {
				t.Fatalf("published before the settle: %+v", got)
			}
			obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
			evs := drainEvents(obs)
			if len(evs) != 1 || evs[0].OutputHash == nil || *evs[0].OutputHash != content.SHA256Bytes([]byte("final")) {
				t.Fatalf("events = %+v, want the userspace hash", evs)
			}
			c := obs.hashes.counts(0, 0)
			if c.Kernel != 0 || c.Userspace != 1 || c.Fallbacks[tc.reason] != 1 {
				t.Fatalf("counts = %+v, want one userspace hash and fallback %s", c, tc.reason)
			}
		})
	}
}

// TestObserver_KernelHashOffLeavesTheCoverageAsBefore: without the option
// the fs coverage record has no Diagnostics, as in every capture before
// P-50, so old and new captures without it are written alike.
func TestObserver_KernelHashOffLeavesTheCoverageAsBefore(t *testing.T) {
	obs := newHashSeamObserver(t, t.TempDir(), content.SHA256FD)
	if d := obs.CaptureCoverage().Diagnostics; d != nil {
		t.Fatalf("Diagnostics = %+v, want nil", d)
	}
	obs.hashes = &fileHashes{mode: "unavailable: test"}
	d := obs.CaptureCoverage().Diagnostics
	if d == nil || d.FileHashes == nil || d.FileHashes.Mode != "unavailable: test" {
		t.Fatalf("Diagnostics = %+v, want the mode", d)
	}
}
