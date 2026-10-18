package fs

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// The benchmarks here drive the whole observer (read loop, parsing, path
// resolution, the settle protocol and hashing) on real kernel records without
// root. The probe's filesystem mark and open_by_handle_at need privilege, so
// the rig marks a few directories with unprivileged inode marks instead and
// opens a handle through the path it was last seen at (pathOpener), which
// costs a path lookup and a name_to_handle_at where the probe pays one
// open_by_handle_at. Everything else is the probe's own code.

// pathOpener is a handleOpener that opens a handle by path. Handles of the
// files in stable directories are listed once; a handle not known yet, or
// whose path now names another file, rescans the volatile directories.
type pathOpener struct {
	mu       sync.Mutex
	paths    map[string]string
	stable   map[string]bool
	volatile []string
	// dead are the handles a rescan did not find: their file is gone, and
	// open_by_handle_at would fail on them at once.
	dead  map[string]bool
	scans int
}

func newPathOpener(stable, volatile []string) *pathOpener {
	p := &pathOpener{paths: map[string]string{}, stable: map[string]bool{}, volatile: volatile, dead: map[string]bool{}}
	for _, d := range stable {
		p.scan(d, true)
	}
	for _, d := range volatile {
		p.scan(d, false)
	}
	return p
}

func benchHandleKey(handleType int32, handleData []byte) string {
	b := make([]byte, 4, 4+len(handleData))
	binary.LittleEndian.PutUint32(b, uint32(handleType))
	return string(append(b, handleData...))
}

func (p *pathOpener) add(path string, stable bool) {
	fh, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return
	}
	key := benchHandleKey(fh.Type(), fh.Bytes())
	p.paths[key] = path
	if stable {
		p.stable[key] = true
	}
}

func (p *pathOpener) scan(dir string, stable bool) {
	p.add(dir, stable)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p.add(filepath.Join(dir, e.Name()), stable)
	}
}

func (p *pathOpener) open(_ int, handleType int32, handleData []byte) (int, error) {
	key := benchHandleKey(handleType, handleData)
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		if p.dead[key] {
			p.mu.Unlock()
			return -1, unix.ESTALE
		}
		if attempt > 0 {
			p.scans++
			delete(p.paths, key)
			for _, d := range p.volatile {
				p.scan(d, false)
			}
		}
		path, ok := p.paths[key]
		stable := p.stable[key]
		if !ok && attempt > 0 {
			p.dead[key] = true
		}
		p.mu.Unlock()
		if !ok {
			continue
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_PATH|unix.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		if stable {
			return fd, nil
		}
		fh, _, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
		if err == nil && benchHandleKey(fh.Type(), fh.Bytes()) == key {
			return fd, nil
		}
		_ = unix.Close(fd)
	}
	return -1, unix.ESTALE
}

// benchRig is an observer on an inode-marked fanotify group.
type benchRig struct {
	obs    *Observer
	ws     string
	opener *pathOpener
	// shell is the workload's shell, for the writer check.
	shell  atomic.Uint32
	events []models.GroundTruthEvent
	done   chan struct{}
}

// privateTools copies the shell workload's commands and the libraries they
// load into dir/bin and dir/lib, so that their opens reach the rig's inode
// marks as they reach the probe's filesystem mark, while other processes'
// opens of the system copies do not. The loader and its cache are still
// read from the system.
func privateTools(tb testing.TB, dir string) (bin, lib string) {
	tb.Helper()
	bin, lib = filepath.Join(dir, "bin"), filepath.Join(dir, "lib")
	for _, d := range []string{bin, lib} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			tb.Fatal(err)
		}
	}
	copyFile := func(src, dst string) {
		data, err := os.ReadFile(src)
		if err != nil {
			tb.Skipf("copy %s: %v", src, err)
		}
		if err := os.WriteFile(dst, data, 0o755); err != nil {
			tb.Fatal(err)
		}
	}
	for _, c := range []string{"bash", "head", "mv", "cat", "rm"} {
		p, err := exec.LookPath(c)
		if err != nil {
			tb.Skipf("%s: %v", c, err)
		}
		copyFile(p, filepath.Join(bin, c))
		out, err := exec.Command("ldd", p).Output()
		if err != nil {
			tb.Skipf("ldd %s: %v", p, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[1] == "=>" && strings.HasPrefix(f[2], "/") {
				copyFile(f[2], filepath.Join(lib, filepath.Base(f[0])))
			}
		}
	}
	return bin, lib
}

// newBenchRig marks ws and the tools' directories with inode marks for the
// probe's mask and builds the observer around the group with assemble, as New
// does around a filesystem mark.
func newBenchRig(tb testing.TB, ws string, tools []string) *benchRig {
	tb.Helper()
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|reportFlags|unix.FAN_CLOEXEC), unix.O_RDONLY)
	if err != nil {
		tb.Skipf("fanotify_init with the probe's flags: %v", err)
	}
	dirs := append([]string{ws}, tools...)
	set := markedSet{fds: map[fsID]int{}, unmarked: map[string]string{}}
	for _, d := range dirs {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, watchMask|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, d); err != nil {
			_ = unix.Close(fd)
			tb.Skipf("fanotify_mark %s: %v", d, err)
		}
		id, err := fsidOf(d)
		if err != nil {
			tb.Fatal(err)
		}
		if _, ok := set.fds[id]; !ok {
			mfd, err := openMountFD(d)
			if err != nil {
				tb.Fatal(err)
			}
			set.fds[id] = mfd
		}
		set.marked = append(set.marked, d)
	}
	wsID, _ := fsidOf(ws)
	cache := newDirCache(dirCacheSize, openRenameWatch(set.marked, 0))
	obs, err := assemble(Config{Path: ws, EventBufSize: 4096}, fd, set, set.fds[wsID], cache)
	if err != nil {
		tb.Fatal(err)
	}
	opener := newPathOpener(dirs[1:], []string{ws})
	obs.openHandle = opener.open
	r := &benchRig{obs: obs, ws: ws, opener: opener, done: make(chan struct{})}
	obs.writerHolds = func(_ uint32, fd int) bool { return openForWriteBy(r.shell.Load(), fd) }
	go func() {
		for e := range obs.Events() {
			r.events = append(r.events, e)
		}
		close(r.done)
	}()
	obs.Start()
	return r
}

func (r *benchRig) stop(tb testing.TB) {
	tb.Helper()
	if err := r.obs.Stop(); err != nil {
		tb.Fatal(err)
	}
	<-r.done
}

// shellLoop is the shell workload of scripts/bench-overhead.sh without its
// TCP connection: per iteration a builtin write, a write by head, a rename, a
// read of both files and their removal.
const shellLoop = `for ((i = 0; i < $1; i++)); do
  printf 'line %d\n' "$i" >"f$i.txt"
  head -c 4096 /dev/zero >"d$i.bin"
  mv "f$i.txt" "g$i.txt"
  cat "g$i.txt" "d$i.bin" >/dev/null
  rm -f "g$i.txt" "d$i.bin"
done`

// runShellLoop runs n iterations of shellLoop in ws with the private tools.
// An unprivileged fanotify group reads pid 0 for another process's event,
// for which the writer check answers "cannot tell" and the probe never
// hashes, so the rig asks the check about the shell instead, whose
// descriptor table the probe would have read.
func runShellLoop(tb testing.TB, r *benchRig, bin, lib string, n int) {
	tb.Helper()
	cmd := exec.Command(filepath.Join(bin, "bash"), "-c", shellLoop, "bash", strconv.Itoa(n))
	cmd.Dir = r.ws
	cmd.Env = []string{"PATH=" + bin, "LD_LIBRARY_PATH=" + lib}
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		tb.Fatal(err)
	}
	r.shell.Store(uint32(cmd.Process.Pid))
	if err := cmd.Wait(); err != nil {
		tb.Fatalf("shell loop: %v: %s", err, out.String())
	}
}

func cpuTime() time.Duration {
	var ru unix.Rusage
	_ = unix.Getrusage(unix.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// BenchmarkObserver_ShellLoop runs the shell workload of the overhead
// benchmark under the observer and reports the observer's CPU per workload
// iteration (the benchmark process's CPU: the observer, its consumer and the
// rig's handle opener), the events it emitted and the closes it hashed.
// Profile it with -cpuprofile; it needs no root.
func BenchmarkObserver_ShellLoop(b *testing.B) {
	const iterations = 200
	var cpu time.Duration
	var events, hashed, scans int
	bin, lib := privateTools(b, b.TempDir())
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ws := b.TempDir()
		r := newBenchRig(b, ws, []string{bin, lib})
		b.StartTimer()
		start := cpuTime()
		runShellLoop(b, r, bin, lib, iterations)
		r.stop(b)
		cpu += cpuTime() - start
		for _, e := range r.events {
			if e.ActionType == models.FileClose && e.OutputHash != nil {
				hashed++
			}
		}
		events += len(r.events)
		scans += r.opener.scans
	}
	per := float64(b.N * iterations)
	b.ReportMetric(float64(cpu.Microseconds())/per, "cpu-us/iter")
	b.ReportMetric(float64(events)/per, "events/iter")
	b.ReportMetric(float64(hashed)/per, "hashed/iter")
	b.ReportMetric(float64(scans)/per, "rig-scans/iter")
}

// replayRecord is one synthetic record of the shell workload's shape.
type replayRecord struct {
	mask uint64
	dir  string
	name string
	file string // the file's own handle, for a content record
}

// shellIteration lists the records one iteration of shellLoop gives, in the
// kernel's shapes (P-25): a directory-entry record carries a DFID_NAME
// record, a content record a DFID_NAME and a FID record. Each command's
// exec opens its binary, the loader cache and libc.
func shellIteration(i int) []replayRecord {
	ws := "/ws"
	f, d, g := fmt.Sprintf("f%d.txt", i), fmt.Sprintf("d%d.bin", i), fmt.Sprintf("g%d.txt", i)
	exec := func(bin string) []replayRecord {
		return []replayRecord{
			{unix.FAN_OPEN, "/usr/bin", bin, "/usr/bin/" + bin},
			{unix.FAN_OPEN, "/etc", "ld.so.cache", "/etc/ld.so.cache"},
			{unix.FAN_OPEN, "/usr/lib", "libc.so.6", "/usr/lib/libc.so.6"},
		}
	}
	write := unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE
	var out []replayRecord
	out = append(out, replayRecord{unix.FAN_CREATE, ws, f, ""}, replayRecord{uint64(write), ws, f, ws + "/" + f})
	out = append(out, exec("head")...)
	out = append(out, replayRecord{unix.FAN_CREATE, ws, d, ""}, replayRecord{uint64(write), ws, d, ws + "/" + d})
	out = append(out, exec("mv")...)
	out = append(out, replayRecord{unix.FAN_MOVED_FROM, ws, f, ""}, replayRecord{unix.FAN_MOVED_TO, ws, g, ""})
	out = append(out, exec("cat")...)
	out = append(out, replayRecord{unix.FAN_OPEN, ws, g, ws + "/" + f}, replayRecord{unix.FAN_OPEN, ws, d, ws + "/" + d})
	out = append(out, exec("rm")...)
	out = append(out, replayRecord{unix.FAN_DELETE, ws, g, ""}, replayRecord{unix.FAN_DELETE, ws, d, ""})
	return out
}

// BenchmarkProcessRecords replays the records of shellLoop iterations
// through parseEvents and processRawEvent, as one batch per iteration, with
// handles resolved from a table and opened as an O_PATH fd of one file, and a
// directory cache whose rename watch guards the records' filesystem. It
// reports the cost per record and how many handle resolutions and handle
// opens each record took: in the probe each resolution is an
// open_by_handle_at, an fstat, a readlink and a close, and each open an
// open_by_handle_at and a close.
func BenchmarkProcessRecords(b *testing.B) {
	const iterations = 64
	paths := map[string]string{}
	handleOf := func(p string) []byte {
		h := []byte(fmt.Sprintf("%-16s", p))
		paths[string(h)] = p
		return h
	}
	var bufs [][]byte
	records := 0
	for i := 0; i < iterations; i++ {
		var buf []byte
		for _, r := range shellIteration(i) {
			info := buildDfidNameInfo(1, handleOf(r.dir), r.name)
			if r.file != "" {
				info = append(info, buildFidInfo(1, handleOf(r.file))...)
			}
			buf = append(buf, buildMetadata(r.mask, 4242, uint16(len(info)))...)
			buf = append(buf, info...)
			records++
		}
		bufs = append(bufs, buf)
	}
	resolves := 0
	resolve := func(_ fsID, _ int32, h []byte) string {
		resolves++
		return paths[string(h)]
	}
	target := filepath.Join(b.TempDir(), "file")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		b.Fatal(err)
	}
	opens := 0
	open := func(int, int32, []byte) (int, error) {
		opens++
		return unix.Open(target, unix.O_RDONLY|unix.O_PATH, 0)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		obs := newHashSeamObserver(b, "", func(int) (string, error) { return "", fmt.Errorf("no read") })
		obs.events = make(chan models.GroundTruthEvent, 64*iterations)
		obs.mounts = map[fsID]int{{}: 0}
		obs.openHandle = open
		obs.settleDelay = time.Hour
		w, _ := pipeWatch(b, fsID{})
		dirs := newDirCache(dirCacheSize, w)
		b.StartTimer()
		for _, buf := range bufs {
			now := time.Now()
			raw := parseEvents(buf, len(buf), resolve, dirs)
			for i := range raw {
				obs.processRawEvent(&raw[i], now.Add(time.Duration(i)))
			}
			for len(obs.events) > 0 {
				<-obs.events
			}
		}
		b.StopTimer()
		for _, pc := range obs.pendingCloses {
			if pc.pathFD >= 0 {
				_ = unix.Close(pc.pathFD)
			}
		}
		b.StartTimer()
	}
	per := float64(b.N * records)
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/per, "ns/record")
	b.ReportMetric(float64(resolves)/per, "resolves/record")
	b.ReportMetric(float64(opens)/per, "opens/record")
}
