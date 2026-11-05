package fs

import (
	"encoding/binary"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// Defaults of the kernel content copy (P-48).
const (
	// DefaultKernelHashCap is the largest file whose content the kernel
	// copies at close; a larger one goes through the userspace path.
	DefaultKernelHashCap = 4 << 20
	// DefaultKernelHashRing is the size of the ring that carries the copies.
	DefaultKernelHashRing = 32 << 20
	// khashSyncWait bounds how long the read loop waits, after a fanotify
	// read, for the kernel records of the closes counted before it (P-49).
	khashSyncWait = 20 * time.Millisecond
)

// Status values of a kernel record; they mirror KH_* in khash.bpf.c.
const (
	khashOK uint32 = iota
	khashWriter
	khashTooLarge
	khashNotCached
	khashRaced
	khashNoReserve
	khashError
)

// khashReason names a status in the coverage record's fallbacks.
var khashReason = map[uint32]string{
	khashWriter:    "writer_held",
	khashTooLarge:  "too_large",
	khashNotCached: "not_cached",
	khashRaced:     "raced",
	khashNoReserve: "ring_full",
	khashError:     "error",
}

// Coverage names of the kernel path's mode and of fallbacks that no record
// status gives.
const (
	khashModeKernel   = "kernel"
	reasonUnmatched   = "unmatched"
	reasonNoIdentity  = "no_identity"
	khashHdrSize      = 32
	khashDevMinorBits = 20
)

// khashKey identifies the closes of one process on one file: the device in
// stat's encoding, the inode and the closing process's tgid.
type khashKey struct {
	dev, ino uint64
	tgid     uint32
}

// khashRecord is the latest kernel record of a khashKey.
type khashRecord struct {
	status uint32
	digest string
}

// khashSource is what the observer asks of the kernel copy; the unprivileged
// tests give it a fake.
type khashSource interface {
	// sync consumes the kernel records of every close counted so far.
	sync()
	// lookup returns the newest consumed record of a process's file.
	lookup(khashKey) (khashRecord, bool)
	// losses returns the closes whose record found no room and the syncs
	// that timed out.
	losses() (lost, timeouts uint64)
	close()
}

// kernelHasher owns the loaded kernel copy and the records it produced.
type kernelHasher struct {
	objs   khashObjects
	links  []link.Link
	reader *ringbuf.Reader
	rec    ringbuf.Record

	mu sync.Mutex
	// latest holds, per process and file, the newest record consumed. A
	// close takes the newest one consumed by the time its fanotify record
	// is processed (P-49).
	latest map[khashKey]khashRecord
	// consumed counts every record read from the ring; lostSeen is the
	// kernel's lost count when latest was last cleared.
	consumed uint64
	lostSeen uint64
	timeouts uint64
	// given counts the closes given up on at a timeout: their records are
	// no longer waited for, and arrive, if they do, as surplus.
	given uint64
}

// kernelHashSupport reports why the kernel copy cannot run on this kernel,
// or "" when it can be tried: the kernel BTF must have the file dynptr
// kfuncs, and the BPF LSM must be active.
func kernelHashSupport() string {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return "no kernel BTF: " + err.Error()
	}
	for _, fn := range []string{"bpf_dynptr_from_file", "bpf_dynptr_file_discard", "bpf_dynptr_copy", "bpf_lsm_file_release"} {
		var f *btf.Func
		if err := spec.TypeByName(fn, &f); err != nil {
			return "kernel BTF has no " + fn
		}
	}
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return "cannot read the active LSM list: " + err.Error()
	}
	if !lsmListHasBPF(string(data)) {
		return "the BPF LSM is not active (" + strings.TrimSpace(string(data)) + ")"
	}
	return ""
}

// lsmListHasBPF reports whether the comma-separated list of active LSMs in
// /sys/kernel/security/lsm names bpf.
func lsmListHasBPF(list string) bool {
	for _, name := range strings.Split(strings.TrimSpace(list), ",") {
		if name == "bpf" {
			return true
		}
	}
	return false
}

// kernelDev converts a device number from stat's encoding to the kernel's
// internal one (MKDEV: major << 20 | minor), which super_block.s_dev holds.
func kernelDev(dev uint64) uint32 {
	return unix.Major(dev)<<khashDevMinorBits | unix.Minor(dev)
}

// userDev converts super_block.s_dev to stat's encoding.
func userDev(kdev uint64) uint64 {
	return unix.Mkdev(uint32(kdev>>khashDevMinorBits), uint32(kdev&(1<<khashDevMinorBits-1)))
}

// startKernelHash loads and attaches the kernel copy for the filesystems
// whose mount fds are given. It returns the reason when it cannot.
func startKernelHash(mountFDs []int, contentCap, ringSize uint64) (*kernelHasher, string) {
	if why := kernelHashSupport(); why != "" {
		return nil, why
	}
	spec, err := loadKhash()
	if err != nil {
		return nil, "load spec: " + err.Error()
	}
	if err := spec.Variables["content_cap"].Set(contentCap); err != nil {
		return nil, "set content_cap: " + err.Error()
	}
	spec.Maps["khash_ring"].MaxEntries = uint32(ringSize)
	k := &kernelHasher{latest: map[khashKey]khashRecord{}}
	if err := spec.LoadAndAssign(&k.objs, nil); err != nil {
		return nil, "load: " + err.Error()
	}
	for _, fd := range mountFDs {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			continue
		}
		if err := k.objs.KhashDevs.Put(kernelDev(uint64(st.Dev)), uint8(1)); err != nil {
			k.close()
			return nil, "devices: " + err.Error()
		}
	}
	if k.reader, err = ringbuf.NewReader(k.objs.KhashRing); err != nil {
		k.close()
		return nil, "ring reader: " + err.Error()
	}
	// The epoch hooks attach before the copy, so that no copy runs without
	// them, and the close counter after it, so that every close it counts
	// gets a record.
	attach := func(p *ebpf.Program) string {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			return "attach " + p.String() + ": " + err.Error()
		}
		k.links = append(k.links, l)
		return ""
	}
	for _, p := range []*ebpf.Program{k.objs.KhashWriteOpen, k.objs.KhashTruncate} {
		if why := attach(p); why != "" {
			k.close()
			return nil, why
		}
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: k.objs.KhashRelease})
	if err != nil {
		k.close()
		return nil, "attach lsm/file_release: " + err.Error()
	}
	k.links = append(k.links, l)
	if why := attach(k.objs.KhashBegin); why != "" {
		k.close()
		return nil, why
	}
	return k, ""
}

// close detaches the programs and releases the maps.
func (k *kernelHasher) close() {
	for i := len(k.links) - 1; i >= 0; i-- {
		_ = k.links[i].Close()
	}
	k.links = nil
	if k.reader != nil {
		_ = k.reader.Close()
		k.reader = nil
	}
	_ = k.objs.Close()
}

// counts reads the kernel's begun and lost counters.
func (k *kernelHasher) counts() (begun, lost uint64, ok bool) {
	var c khashKhashCounts
	if err := k.objs.KhashCountMap.Lookup(uint32(0), &c); err != nil {
		return 0, 0, false
	}
	return c.Begun, c.Lost, true
}

// sync consumes the ring until it holds a record, or a lost count, for every
// close the kernel counted before this call, or until khashSyncWait passes.
// The read loop calls it after each fanotify read and before processing the
// records read: every close in those records was counted before its
// fanotify record was queued, so after sync its kernel record has been
// consumed (P-49).
func (k *kernelHasher) sync() {
	begun, _, ok := k.counts()
	if !ok {
		return
	}
	deadline := time.Now().Add(khashSyncWait)
	for {
		_, lost, _ := k.counts()
		k.mu.Lock()
		if lost != k.lostSeen {
			// A record that could not be reserved leaves an older record of
			// its file as the newest; no record is trusted across the loss.
			k.lostSeen = lost
			clear(k.latest)
		}
		done := k.consumed+lost+k.given >= begun
		k.mu.Unlock()
		if done {
			return
		}
		k.reader.SetDeadline(deadline)
		if err := k.reader.ReadInto(&k.rec); err != nil {
			k.mu.Lock()
			k.timeouts++
			if have := k.consumed + lost + k.given; begun > have {
				k.given += begun - have
			}
			clear(k.latest)
			k.mu.Unlock()
			return
		}
		k.take(k.rec.RawSample)
	}
}

// take indexes one raw record.
func (k *kernelHasher) take(raw []byte) {
	key, r, ok := parseKhashRecord(raw)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.consumed++
	if ok {
		k.latest[key] = r
	}
}

// parseKhashRecord decodes a ring record: the header of struct khash_hdr,
// then the content when the status is OK, which it hashes.
func parseKhashRecord(raw []byte) (khashKey, khashRecord, bool) {
	if len(raw) < khashHdrSize {
		return khashKey{}, khashRecord{}, false
	}
	le := binary.NativeEndian
	key := khashKey{dev: userDev(le.Uint64(raw[0:])), ino: le.Uint64(raw[8:]), tgid: le.Uint32(raw[24:])}
	size := le.Uint64(raw[16:])
	r := khashRecord{status: le.Uint32(raw[28:])}
	if r.status == khashOK {
		if uint64(len(raw)-khashHdrSize) < size {
			return khashKey{}, khashRecord{}, false
		}
		r.digest = content.SHA256Bytes(raw[khashHdrSize : khashHdrSize+size])
	}
	return key, r, true
}

// lookup returns the newest record of key consumed so far.
func (k *kernelHasher) lookup(key khashKey) (khashRecord, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	r, ok := k.latest[key]
	return r, ok
}

// losses implements khashSource.
func (k *kernelHasher) losses() (lost, timeouts uint64) {
	_, lost, _ = k.counts()
	k.mu.Lock()
	defer k.mu.Unlock()
	return lost, k.timeouts
}

// startKernelHash starts the kernel copy for the marked filesystems, or
// records why it could not (P-48).
func (o *Observer) startKernelHash(marked map[fsID]int) {
	contentCap, ring := o.cfg.KernelHashCap, o.cfg.KernelHashRing
	if contentCap == 0 {
		contentCap = DefaultKernelHashCap
	}
	if ring == 0 {
		ring = DefaultKernelHashRing
	}
	fds := make([]int, 0, len(marked))
	for _, fd := range marked {
		fds = append(fds, fd)
	}
	o.hashes = &fileHashes{mode: khashModeKernel}
	k, why := startKernelHash(fds, contentCap, ring)
	if why != "" {
		o.hashes.mode = "unavailable: " + why
		return
	}
	o.khash = k
}

// syncKernelHash runs after each fanotify read (P-49).
func (o *Observer) syncKernelHash() {
	if o.khash != nil {
		o.khash.sync()
	}
}

// fileHashes is what the coverage record says about the kernel path.
type fileHashes struct {
	mu        sync.Mutex
	mode      string
	kernel    uint64
	userspace uint64
	fallbacks map[string]uint64
}

func (f *fileHashes) fallback(reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fallbacks == nil {
		f.fallbacks = map[string]uint64{}
	}
	f.fallbacks[reason]++
}

func (f *fileHashes) add(kernel bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if kernel {
		f.kernel++
	} else {
		f.userspace++
	}
}

// counts returns the coverage record's FileHashes.
func (f *fileHashes) counts(lost, timeouts uint64) *models.FileHashCounts {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &models.FileHashCounts{Mode: f.mode, Kernel: f.kernel, Userspace: f.userspace}
	for r, n := range f.fallbacks {
		if c.Fallbacks == nil {
			c.Fallbacks = map[string]uint64{}
		}
		c.Fallbacks[r] = n
	}
	c.Lost, c.SyncTimeouts = lost, timeouts
	return c
}

// ext4SuperMagic is statfs's f_type of ext4.
const ext4SuperMagic = 0xEF53

// ext4HandleInode returns the device and inode number an ext4 file handle
// names: its types FILEID_INO32_GEN (1) and FILEID_INO32_GEN_PARENT (2) begin
// with the 32-bit inode number, in the host's byte order. It serves a file the probe can no longer open by its
// handle, such as one deleted before its close was read.
func ext4HandleInode(mountFD int, handleType int32, data []byte) (dev, ino uint64, ok bool) {
	if (handleType != 1 && handleType != 2) || len(data) < 8 || mountFD < 0 {
		return 0, 0, false
	}
	var sfs unix.Statfs_t
	if unix.Fstatfs(mountFD, &sfs) != nil || sfs.Type != ext4SuperMagic {
		return 0, 0, false
	}
	var st unix.Stat_t
	if unix.Fstat(mountFD, &st) != nil {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(binary.NativeEndian.Uint32(data)), true
}

// kernelHashFor returns the kernel's hash of a close, and a fallback reason
// when there is none. pathFD is the close's O_PATH fd (-1 when the handle
// did not open); key and born are what statx read from it.
func (o *Observer) kernelHashFor(pid uint32, pathFD, mountFD int, handleType int32, handleData []byte) (digest string, sh shadowHash, reason string) {
	var dev, ino uint64
	if pathFD >= 0 {
		key, born, ok := statxID(pathFD, "", unix.AT_EMPTY_PATH)
		if ok {
			dev, ino = key.dev, key.ino
			sh = shadowHash{key: key, born: born, known: true}
		}
	}
	if !sh.known {
		var ok bool
		if dev, ino, ok = ext4HandleInode(mountFD, handleType, handleData); !ok {
			return "", sh, reasonNoIdentity
		}
	}
	r, ok := o.khash.lookup(khashKey{dev: dev, ino: ino, tgid: pid})
	if !ok {
		return "", sh, reasonUnmatched
	}
	if r.status != khashOK {
		return "", sh, khashReason[r.status]
	}
	sh.hash = r.digest
	return r.digest, sh, ""
}
