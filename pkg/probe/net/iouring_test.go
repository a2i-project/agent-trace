package net

import (
	"encoding/binary"
	"errors"
	stdnet "net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Tests for the io_uring counters (N-25). The test process itself is tracked
// and submits the operations through a minimal ring built from raw
// syscalls, so the workload needs no compiler, no liburing and no runtime
// that happens to use io_uring.

// Opcodes and flags from the kernel UAPI (include/uapi/linux/io_uring.h).
const (
	opRead  = 22 // IORING_OP_READ
	opWrite = 23 // IORING_OP_WRITE
	opSend  = 26 // IORING_OP_SEND

	sqeFixedFile = 1 << 0 // IOSQE_FIXED_FILE

	enterGetEvents = 1 << 0 // IORING_ENTER_GETEVENTS
	registerFiles  = 2      // IORING_REGISTER_FILES

	offSQRing = 0          // IORING_OFF_SQ_RING
	offCQRing = 0x8000000  // IORING_OFF_CQ_RING
	offSQEs   = 0x10000000 // IORING_OFF_SQES
	sqeSize   = 64
	cqeSize   = 16
)

// uringParams mirrors struct io_uring_params.
type uringParams struct {
	sqEntries, cqEntries, flags, sqThreadCPU, sqThreadIdle, features, wqFd uint32
	resv                                                                   [3]uint32
	sqOff                                                                  struct {
		head, tail, ringMask, ringEntries, flags, dropped, array, resv1 uint32
		userAddr                                                        uint64
	}
	cqOff struct {
		head, tail, ringMask, ringEntries, overflow, cqes, flags, resv1 uint32
		userAddr                                                        uint64
	}
}

// ring is a one-operation-at-a-time io_uring instance.
type ring struct {
	fd       int
	p        uringParams
	sq, cq   []byte
	sqes     []byte
	buf      []byte // the only buffer handed to the kernel; on the heap, so it cannot move
	released bool
}

func newRing(t *testing.T) *ring {
	t.Helper()
	r := &ring{buf: make([]byte, 4096)}
	fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 4, uintptr(unsafe.Pointer(&r.p)), 0)
	if errno != 0 {
		if errors.Is(errno, unix.ENOSYS) || errors.Is(errno, unix.EPERM) {
			t.Skipf("io_uring unavailable: %v", errno)
		}
		t.Fatalf("io_uring_setup: %v", errno)
	}
	r.fd = int(fd)
	var err error
	sqLen := int(r.p.sqOff.array + r.p.sqEntries*4)
	if r.sq, err = unix.Mmap(r.fd, offSQRing, sqLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE); err != nil {
		t.Fatalf("mmap sq ring: %v", err)
	}
	cqLen := int(r.p.cqOff.cqes + r.p.cqEntries*cqeSize)
	if r.cq, err = unix.Mmap(r.fd, offCQRing, cqLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE); err != nil {
		t.Fatalf("mmap cq ring: %v", err)
	}
	if r.sqes, err = unix.Mmap(r.fd, offSQEs, int(r.p.sqEntries*sqeSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE); err != nil {
		t.Fatalf("mmap sqes: %v", err)
	}
	t.Cleanup(r.close)
	return r
}

func (r *ring) close() {
	if r.released {
		return
	}
	r.released = true
	_ = unix.Munmap(r.sqes)
	_ = unix.Munmap(r.cq)
	_ = unix.Munmap(r.sq)
	_ = unix.Close(r.fd)
}

func (r *ring) u32(b []byte, off uint32) *uint32 { return (*uint32)(unsafe.Pointer(&b[off])) }

// registerFiles registers fds as the ring's fixed files.
func (r *ring) registerFiles(t *testing.T, fds ...int32) {
	t.Helper()
	_, _, errno := unix.Syscall6(unix.SYS_IO_URING_REGISTER, uintptr(r.fd), registerFiles, uintptr(unsafe.Pointer(&fds[0])), uintptr(len(fds)), 0, 0)
	if errno != 0 {
		t.Fatalf("io_uring_register files: %v", errno)
	}
}

// do submits one operation on fd (an index when flags has sqeFixedFile),
// waits for its completion and returns the result. A write or send carries
// data; a read reads up to n bytes into r.buf.
func (r *ring) do(t *testing.T, op uint8, flags uint8, fd int32, data []byte, n int) int32 {
	t.Helper()
	if data != nil {
		n = copy(r.buf, data)
	}
	buf := r.buf[:n]
	tail := atomic.LoadUint32(r.u32(r.sq, r.p.sqOff.tail))
	mask := *r.u32(r.sq, r.p.sqOff.ringMask)
	idx := tail & mask
	sqe := r.sqes[idx*sqeSize : (idx+1)*sqeSize]
	clear(sqe)
	sqe[0] = op
	sqe[1] = flags
	binary.LittleEndian.PutUint32(sqe[4:], uint32(fd))
	binary.LittleEndian.PutUint64(sqe[8:], 0) // off
	binary.LittleEndian.PutUint64(sqe[16:], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	binary.LittleEndian.PutUint32(sqe[24:], uint32(len(buf)))
	binary.LittleEndian.PutUint64(sqe[32:], 1) // user_data
	runtime.KeepAlive(r.buf)
	*r.u32(r.sq, r.p.sqOff.array+idx*4) = idx
	atomic.StoreUint32(r.u32(r.sq, r.p.sqOff.tail), tail+1)

	if _, _, errno := unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(r.fd), 1, 1, enterGetEvents, 0, 0); errno != 0 {
		t.Fatalf("io_uring_enter: %v", errno)
	}
	head := atomic.LoadUint32(r.u32(r.cq, r.p.cqOff.head))
	if head == atomic.LoadUint32(r.u32(r.cq, r.p.cqOff.tail)) {
		t.Fatal("io_uring_enter returned without a completion")
	}
	cqe := r.p.cqOff.cqes + (head&*r.u32(r.cq, r.p.cqOff.ringMask))*cqeSize
	res := int32(binary.LittleEndian.Uint32(r.cq[cqe+8:]))
	atomic.StoreUint32(r.u32(r.cq, r.p.cqOff.head), head+1)
	return res
}

// stopAndCoverage stops obs, drains it and returns its final coverage.
func stopAndCoverage(t *testing.T, obs *Observer) Coverage {
	t.Helper()
	time.Sleep(200 * time.Millisecond) // CI sets the bound: counters are updated in the kernel, nothing to drain
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for range obs.Events() {
	}
	return obs.Coverage()
}

// TestObserver_IOURingSocketOpsAreCounted: a send and a write on a connected
// socket through io_uring, and a read of a registered file, which the probe
// cannot resolve, are each one network operation. The connection itself
// was made with connect(2), so the probe saw it but none of its data.
func TestObserver_IOURingSocketOpsAreCounted(t *testing.T) {
	skipUnprivileged(t)

	port := sinks(t, 1)[0]
	file := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(file, []byte("registered"), 0o600); err != nil {
		t.Fatal(err)
	}
	obs := startObserver(t)

	r := newRing(t)
	conn, err := stdnet.Dial("tcp4", stdnet.JoinHostPort("127.0.0.1", itoa(uint16(port))))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	sock, err := conn.(*stdnet.TCPConn).File() // a blocking duplicate of the socket
	if err != nil {
		t.Fatalf("socket fd: %v", err)
	}
	defer func() { _ = sock.Close() }()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if res := r.do(t, opSend, 0, int32(sock.Fd()), []byte("sent by IORING_OP_SEND"), 0); res <= 0 {
		t.Fatalf("IORING_OP_SEND = %d", res)
	}
	if res := r.do(t, opWrite, 0, int32(sock.Fd()), []byte("written by IORING_OP_WRITE"), 0); res <= 0 {
		t.Fatalf("IORING_OP_WRITE on the socket = %d", res)
	}
	r.registerFiles(t, int32(f.Fd()))
	if res := r.do(t, opRead, sqeFixedFile, 0, nil, 16); res <= 0 {
		t.Fatalf("IORING_OP_READ of the registered file = %d", res)
	}
	r.close()

	cov := stopAndCoverage(t, obs)
	if cov.IOURingRings != 1 || cov.IOURingOps != 3 {
		t.Errorf("rings = %d, operations = %d; want 1 and 3: the hooks did not see the workload", cov.IOURingRings, cov.IOURingOps)
	}
	if cov.IOURingNetOps != 3 {
		t.Errorf("IOURingNetOps = %d, want 3 (send, write on the socket, read of a registered file)", cov.IOURingNetOps)
	}
	if got := obs.CaptureCoverage().IOURingNetOps; got != cov.IOURingNetOps {
		t.Errorf("CaptureCoverage().IOURingNetOps = %d, want %d", got, cov.IOURingNetOps)
	}
}

// TestObserver_IOURingFileOpsAreNotNetwork is the control: a tracked process
// that reads and writes ordinary files through io_uring submits operations
// the probe sees, and none of them is network activity.
func TestObserver_IOURingFileOpsAreNotNetwork(t *testing.T) {
	skipUnprivileged(t)

	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	if err := os.WriteFile(in, []byte("read through io_uring"), 0o600); err != nil {
		t.Fatal(err)
	}
	obs := startObserver(t)

	r := newRing(t)
	src, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	dst, err := os.Create(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dst.Close() }()

	n := r.do(t, opRead, 0, int32(src.Fd()), nil, 64)
	if n <= 0 {
		t.Fatalf("IORING_OP_READ = %d", n)
	}
	data := append([]byte(nil), r.buf[:n]...)
	if res := r.do(t, opWrite, 0, int32(dst.Fd()), data, 0); res != n {
		t.Fatalf("IORING_OP_WRITE = %d, want %d", res, n)
	}
	r.close()

	cov := stopAndCoverage(t, obs)
	if cov.IOURingRings != 1 || cov.IOURingOps != 2 {
		t.Errorf("rings = %d, operations = %d; want 1 and 2: without them a zero below proves nothing", cov.IOURingRings, cov.IOURingOps)
	}
	if cov.IOURingNetOps != 0 {
		t.Errorf("IOURingNetOps = %d, want 0 for file-only io_uring use", cov.IOURingNetOps)
	}
	if got := obs.CaptureCoverage().IOURingNetOps; got != 0 {
		t.Errorf("CaptureCoverage().IOURingNetOps = %d, want 0", got)
	}
}
