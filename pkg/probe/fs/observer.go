package fs

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// watchMask is the set of fanotify events the observer monitors.
var watchMask = uint64(
	unix.FAN_OPEN |
		unix.FAN_MODIFY |
		unix.FAN_CLOSE_WRITE |
		unix.FAN_CREATE |
		unix.FAN_DELETE |
		unix.FAN_MOVED_FROM |
		unix.FAN_MOVED_TO)

// Config controls the observer's behavior.
type Config struct {
	// Path identifies the filesystem to watch. Every file operation on the
	// filesystem containing this path is monitored (across all mount points).
	// Its regular files are hashed at Start so the first open of each carries
	// an input hash.
	Path string

	// AllFilesystems marks every real filesystem mounted on the host, not only
	// the one holding Path, so an agent's file activity is observed wherever
	// it goes (a tmpfs /tmp, a separate /home). Pseudo filesystems, read-only
	// images and fuse mounts are skipped; Scope reports what was marked and
	// what could not be. Files outside Path are not hashed at Start, so their
	// first open carries the empty-content hash.
	AllFilesystems bool

	// PathFilter, if non-empty, restricts emitted events to paths with this
	// prefix. Useful on shared hosts to scope observation to the agent's
	// working directory. Leave empty to capture all events on the filesystem.
	PathFilter string

	// PIDFilter, if > 0, restricts emitted events to this exact process ID.
	// Useful in tests and for an agent that acts in its own process. It does
	// not follow children, so for a real agent, whose file activity happens in
	// descendants, leave it zero.
	//
	// The probe deliberately does not scope by the kernel tracked-PID set
	// (V1 first proposed that). A fanotify event is read some time
	// after the access, a short-lived child has usually left tracked_pids by
	// then, and a filter that consulted the set would drop that child's events
	// silently, which is event loss nothing counts. Every event instead carries
	// the causing PID and attribution walks the process tree in the verifier.
	PIDFilter int32

	// EventBufSize is the channel buffer size for emitted events.
	// Defaults to 4096 if zero.
	EventBufSize int
}

// Observer watches filesystem events via fanotify and emits GroundTruthEvents.
type Observer struct {
	fanotifyFD int
	// mountFD is the mount fd of the filesystem holding Config.Path; -1 in
	// tests that drive the observer without a kernel.
	mountFD int
	// mounts holds one mount fd per marked filesystem id, mountFD included.
	mounts map[fsID]int
	// marked and unmarked are the mount points the all-filesystems mark
	// covered and those it could not, for Scope.
	marked   []string
	unmarked map[string]string
	// mountTable is the mount table at New, with the mounts the probe names
	// files through marked; nil when it could not be read. mountTableFD is
	// the open mountinfo file it was read from, polled and closed at Stop,
	// which sets mountTableChanged (P-33).
	mountTable        []models.FSMounts
	mountTableFD      int
	mountTableChanged *bool
	stopR             int // read end of stop-signal pipe
	stopW             int // write end of stop-signal pipe
	events            chan models.GroundTruthEvent
	stopped           chan struct{}
	cfg               Config
	overflow          bool // true if FAN_Q_OVERFLOW was seen
	hashlessCloses    atomic.Uint64
	// undrained counts the records still queued when the stop drain ran out
	// of time (drainAtStop): event loss, a lower bound.
	undrained atomic.Uint64
	// unresolved counts the events whose path no handle resolved, one per
	// action type of each such record (V-35).
	unresolved atomic.Uint64
	// dirs names the directory of a record read after that directory was
	// removed (P-28); nil in tests that drive the observer without it.
	dirs *dirCache
	// stopDrain is how long the read loop keeps reading records after the
	// stop signal before it counts the rest instead. Defaults to
	// stopDrainBudget; tests lower it to provoke the count.
	stopDrain        time.Duration
	pendingHashOpens map[string]int
	shadowHashes     map[string]string

	// shadowHashesByInode is shadowHashes' companion index, keyed by the
	// file's (device, inode) instead of its path. A path-keyed lookup alone
	// misses a file that was renamed since it was last hashed: FAN_OPEN on
	// the new name won't find an entry under the old one, and the
	// FAN_MOVED_FROM/FAN_MOVED_TO records name the two paths but nothing
	// links them to each other. Device+inode identifies the underlying file regardless of
	// what it's currently named, since a rename never changes it, so this
	// index survives renames for free. Populated in hashSettledFD from the
	// fd it just hashed; consulted in processRawEvent as a fallback when a
	// FAN_OPEN's path isn't (yet, or ever again) a key in shadowHashes.
	shadowHashesByInode map[inodeKey]string
	// startedAt is when Start ran. A file born at or after it was created
	// during the capture, so its first open is the one that created it, and
	// the file was empty at that open (P-22).
	startedAt time.Time
	// openedInodes are the files the probe has seen opened, so that only a
	// born-here file's first open is read as its creation.
	openedInodes map[inodeKey]bool

	// pathGeneration counts write-class events (FAN_CREATE / FAN_MODIFY /
	// FAN_CLOSE_WRITE) seen per path. hashSettled snapshots the generation
	// before reading a closed file's content and re-checks it after: if the
	// file was written again in that window, the digest can no longer be
	// trusted to reflect the observed close, so no OutputHash is attached
	// (see the TOCTOU note on hashSettled). This catches a write racing
	// during one specific hash read; it is not sufficient on its own to
	// guarantee a hash reflects the file's eventual final content -- see
	// pendingCloses. Grows unboundedly for the observer's lifetime --
	// entries are never garbage collected, matching pendingHashOpens'
	// existing shape; revisit if a long-lived observer over many distinct
	// paths becomes a memory concern.
	pathGeneration map[string]uint64

	// handleGeneration counts the same write-class records per file, keyed by
	// the file handle a content record carries (handleKey), so a write under
	// another name reaches a close registered under the old one. Since P-25 a
	// record names the entry as it was named when the event happened, so the
	// close of a temporary renamed onto its target before an open of the
	// target are two paths for one file (P-26). Grows like pathGeneration.
	handleGeneration map[string]uint64

	// openGeneration counts, per path and per file handle and per process,
	// the records that hold an open and no write-class bit. Such a record
	// changes no content: a truncating open is reported with FAN_MODIFY,
	// as a record of its own or merged into the opener's (P-39). Only the
	// closing process's opens, and those of a process the record does not
	// name (pid 0), drop a pending close's hash (openedSince); another
	// process reading the file leaves it. Grows like pathGeneration.
	openGeneration map[openKey]uint64

	// writerHolds reports whether process pid still holds the file behind
	// pathFD open for writing, or whether that cannot be told. The kernel
	// merges an open, a truncation and a write by the closing process into
	// that close's record while the record is unread, so the record can hide
	// a rewrite that has begun; a process that still holds the file open for
	// writing is the trace of one that has not finished (P-26). New sets it
	// to openForWriteBy; nil, in tests that drive the settle code without a
	// kernel, skips the check.
	writerHolds func(pid uint32, pathFD int) bool

	// pendingCloses holds, per path, the most recent FileClose still
	// waiting to prove it won't be superseded before it is trusted enough
	// to hash. See registerClose and resolveSettled for the full mechanism
	// and why "nothing changed while I was reading" (pathGeneration) isn't
	// by itself enough to guarantee a hash reflects the final content.
	pendingCloses map[string]*pendingClose

	// lastWriteAt records, per path, the observer's local time when it last
	// processed a write-class event (FAN_CREATE / FAN_MODIFY /
	// FAN_CLOSE_WRITE) for that path. resolveSettled will not hash a pending
	// close until this path has been quiet for settleDelay. "Survived one
	// readLoop iteration untouched" is not sufficient on a loaded host,
	// where an unrelated fanotify wakeup -- including the observer's own
	// hash-read FAN_OPEN -- can end an iteration microseconds after it
	// began, so an intermediate close in a write burst could otherwise be
	// hashed against content the very next write truncates. Grows
	// unboundedly for the observer's lifetime, like pathGeneration and
	// pendingHashOpens.
	lastWriteAt map[string]time.Time

	// lastEmitted records, per path, the last action type emitted for it and
	// by which pid. A write-class or rename event that repeats the last one
	// on its path from the same process is not emitted again: the kernel
	// merges notifications on one object (one directory and name since
	// P-25) into one mask when nothing reads between them and delivers them
	// apart otherwise, so without this the number of file_write events for
	// one write (the truncating open and the write), or of file_rename
	// events for renames onto one name, depended on timing. Position is what
	// the verifier pairs on, so the count must not (P-18). The two halves of
	// one rename name two paths since P-25 and are two events.
	lastEmitted map[string]emitted

	// held are the removals (a file_rename of a moved-from, a file_delete)
	// of merged creation records, waiting for the record that marks their
	// place (P-27). The kernel merges a name's moved-from or delete into the
	// unread record of its creation, ahead of the file's open, write and
	// close; the removal happened after those. holdRemoval and placeHeld
	// decide; releaseHeld emits what is left at the end of a drain.
	held []heldRemoval
	// fromsInFlight counts, per pid, the moved-from records emitted in place
	// whose moved-to record has not been read, so that moved-to is not taken
	// for the place of a held one.
	fromsInFlight map[uint32]int
	// movedTo holds, per pid, the paths its moved-to records named since the
	// last release: the records a later moved-to of the same name may have
	// merged into (P-38).
	movedTo map[uint32]map[string]bool
	// lastStamp is the timestamp of the last record processed, for a release
	// at the end of a drain.
	lastStamp time.Time
	// fileNamed reports whether the file a content record's handle names is
	// still named as the record names it; nil uses namedNow. A content record
	// on a held delete's name floats ahead of the delete only when it is not,
	// since a file still there was created again after the delete.
	fileNamed func(e *rawEvent) bool
	// fileAt returns the path at which the file a content record's handle
	// names is now, "" when it does not resolve; nil uses pathNow.
	fileAt func(e *rawEvent) string

	// settleDelay is how long a path must be quiet (no write-class event,
	// see lastWriteAt) before a pending close for it is hashed. Defaults to
	// settleQuietWindow; left zero by tests that drive
	// settleSnapshot/resolveSettled directly and want an immediate resolve.
	settleDelay time.Duration

	// identities remembers, by handleKey, the device, inode and birth time a
	// file handle named (identify); bounded by identitiesSize.
	identities map[string]identity

	// self is the observer's own pid, set by assemble; zero in tests that
	// build an Observer directly, where selfPID asks the kernel.
	self int32

	// openHandle opens the file a handle names; nil uses openByHandle. The
	// benchmarks set it, since open_by_handle_at needs privilege.
	openHandle handleOpener

	// hashFile computes the content hash for a closed file. Defaults to
	// content.SHA256File; overridable in tests to control the read's outcome.
	hashFD func(int) (string, error)

	mu sync.Mutex
}

// heldRemoval is a removal held by P-27. For a held moved-from, dest is
// where its file was when the first content record on the source's name was
// read, and looked says that record came: the destination of a moved-to that
// merged into an earlier record of its name (P-38).
type heldRemoval struct {
	ev     models.GroundTruthEvent
	dest   string
	looked bool
}

// emitted is what lastEmitted remembers for a path.
type emitted struct {
	typ models.ActionType
	pid uint32
}

// pendingClose is a FileClose observed for a path but not yet resolved to a
// GroundTruthEvent. Its identity (the pointer itself) is what registerClose
// and resolveSettled use to detect whether a given close survived a settle
// cycle untouched, so a new pendingClose value is always allocated rather
// than mutating one in place.
type pendingClose struct {
	ts        time.Time
	pid       uint32
	ambiguous bool
	pathFD    int
	// gen is the path's write generation when this close was registered, after
	// the close's own event bumped it. A later write-class event on the path
	// (an open that may have truncated it, a modify) changes the generation, and
	// then the content this close described may be gone: see resolveSettled.
	gen uint64
	// handle is the file's handleKey, empty when the record carried no file
	// handle, and hgen the file's handleGeneration at registration.
	handle string
	hgen   uint64
	// opens is openedSince's count for this close at registration.
	opens uint64
}

// openKey names one process's opens of one file, by path or by handle.
type openKey struct {
	key string
	pid uint32
}

// openedSince sums the open-only records on path and on handle by process
// pid and by pid 0, the opens that may be the closing process's (P-39). The
// caller holds o.mu.
func (o *Observer) openedSince(path, handle string, pid uint32) uint64 {
	n := o.openGeneration[openKey{path, pid}] + o.openGeneration[openKey{path, 0}]
	if handle != "" {
		n += o.openGeneration[openKey{"\x00" + handle, pid}] + o.openGeneration[openKey{"\x00" + handle, 0}]
	}
	return n
}

// New creates an Observer. The caller must call Start to begin receiving
// events, and Stop to release resources.
func New(cfg Config) (*Observer, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("Config.Path is required")
	}
	if cfg.EventBufSize <= 0 {
		cfg.EventBufSize = 4096
	}
	// Events carry absolute paths, so the walked directory and the filter
	// must be absolute too, or a relative one keys the shadow hashes by
	// paths no event has and matches no event.
	abs, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("Config.Path: %w", err)
	}
	cfg.Path = abs
	if cfg.PathFilter != "" {
		if cfg.PathFilter, err = filepath.Abs(cfg.PathFilter); err != nil {
			return nil, fmt.Errorf("Config.PathFilter: %w", err)
		}
	}

	fd, err := initFanotify()
	if err != nil {
		return nil, err
	}

	// The mount table is read before anything is marked, and its fd stays
	// open so that Stop can tell whether it changed meanwhile (P-33).
	tableFD, table := readMountTable()
	fail := func(set markedSet, err error) (*Observer, error) {
		set.close()
		_ = unix.Close(fd)
		if tableFD >= 0 {
			_ = unix.Close(tableFD)
		}
		return nil, err
	}
	var set markedSet
	if cfg.AllFilesystems {
		set, err = markAll(fd, cfg.Path, watchMask, table)
	} else {
		set, err = markOne(fd, cfg.Path, watchMask)
	}
	if err != nil {
		return fail(set, err)
	}
	pathID, err := fsidOf(cfg.Path)
	if err != nil {
		return fail(set, err)
	}
	dirs := newDirCache(dirCacheSize, openRenameWatch(set.marked, unix.FAN_MARK_FILESYSTEM))
	o, err := assemble(cfg, fd, set, set.fds[pathID], dirs)
	if err != nil {
		dirs.close()
		return fail(set, err)
	}
	if table != nil {
		names := map[int]bool{}
		for _, mfd := range set.fds {
			if id, ok := mountIDOf(mfd); ok {
				names[id] = true
			}
		}
		o.mountTable, o.mountTableFD = buildMountTable(table, names), tableFD
	}
	return o, nil
}

// assemble builds an Observer around a marked fanotify group: fd, the marked
// filesystems with their mount fds, the mount fd of Config.Path's filesystem
// and the directory cache. The benchmarks build one around an inode-marked
// group the same way.
func assemble(cfg Config, fd int, set markedSet, mountFD int, dirs *dirCache) (*Observer, error) {
	// Pipe for signaling the read loop to stop.
	pipeFDs := [2]int{}
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC); err != nil {
		return nil, fmt.Errorf("pipe2: %w", err)
	}

	return &Observer{
		fanotifyFD:          fd,
		mountFD:             mountFD,
		mounts:              set.fds,
		marked:              set.marked,
		dirs:                dirs,
		unmarked:            set.unmarked,
		stopR:               pipeFDs[0],
		stopW:               pipeFDs[1],
		events:              make(chan models.GroundTruthEvent, cfg.EventBufSize),
		stopped:             make(chan struct{}),
		cfg:                 cfg,
		pendingHashOpens:    make(map[string]int),
		shadowHashes:        make(map[string]string),
		shadowHashesByInode: make(map[inodeKey]string),
		pathGeneration:      make(map[string]uint64),
		handleGeneration:    make(map[string]uint64),
		openGeneration:      make(map[openKey]uint64),
		writerHolds:         openForWriteBy,
		pendingCloses:       make(map[string]*pendingClose),
		lastWriteAt:         make(map[string]time.Time),
		lastEmitted:         make(map[string]emitted),
		settleDelay:         settleQuietWindow,
		stopDrain:           stopDrainBudget,
		hashFD:              content.SHA256FD,
		self:                int32(os.Getpid()),
		mountTableFD:        -1,
	}, nil
}

// markOne marks only the filesystem holding path.
func markOne(fanotifyFD int, path string, mask uint64) (markedSet, error) {
	set := markedSet{fds: map[fsID]int{}, unmarked: map[string]string{}}
	id, err := fsidOf(path)
	if err != nil {
		return set, err
	}
	if err := markFilesystem(fanotifyFD, path, mask); err != nil {
		return set, err
	}
	fd, err := openMountFD(path)
	if err != nil {
		return set, err
	}
	set.fds[id] = fd
	set.marked = []string{path}
	return set, nil
}

// Scope reports which filesystems the observer marked, by mount point, and
// which it could not. With AllFilesystems unset, Marked holds Config.Path.
func (o *Observer) Scope() (marked []string, unmarked map[string]string) {
	marked = append(marked, o.marked...)
	unmarked = make(map[string]string, len(o.unmarked))
	for k, v := range o.unmarked {
		unmarked[k] = v
	}
	return marked, unmarked
}

// MountTable returns the mount table read at New, every mount grouped by
// filesystem with the mounts the probe names files through marked, and
// whether the table changed before Stop (nil: not known). Call after Stop.
// A nil table means it could not be read (P-33).
func (o *Observer) MountTable() ([]models.FSMounts, *bool) {
	return o.mountTable, o.mountTableChanged
}

// selfPID returns the observer's own pid, without a system call once
// assemble has set it.
func (o *Observer) selfPID() int32 {
	if o.self != 0 {
		return o.self
	}
	return int32(os.Getpid())
}

// open opens the file a handle names as an O_PATH fd (openHandle).
func (o *Observer) open(mountFD int, handleType int32, handleData []byte) (int, error) {
	if o.openHandle != nil {
		return o.openHandle(mountFD, handleType, handleData)
	}
	return openByHandle(mountFD, handleType, handleData)
}

// mountFor returns the mount fd of the filesystem id, or -1.
func (o *Observer) mountFor(id fsID) int {
	if fd, ok := o.mounts[id]; ok {
		return fd
	}
	return -1
}

// Events returns the channel on which GroundTruthEvents are delivered.
// The channel is closed when Stop returns.
func (o *Observer) Events() <-chan models.GroundTruthEvent {
	return o.events
}

// DirCache reports what the directory cache did: how many records it named
// whose directory had been removed, and how many entries it dropped (P-28).
// Call after Stop.
func (o *Observer) DirCache() DirCacheStats {
	return o.dirs.snapshot()
}

// Overflow reports whether the kernel's fanotify queue overflowed,
// meaning some events were lost. Check after Stop returns.
func (o *Observer) Overflow() bool {
	return o.overflow
}

// CaptureCoverage reports the loss indicators for this capture. Call after
// Stop. The fs probe sends on its events channel without dropping, so a slow
// consumer shows up as backpressure and then as a kernel queue overflow, which
// is what QueueOverflow reports. UndrainedRecords counts the records the stop
// drain could not read in its time budget.
func (o *Observer) CaptureCoverage() models.ProbeCoverage {
	return models.ProbeCoverage{
		Ran:              true,
		QueueOverflow:    o.Overflow(),
		HashlessCloses:   o.hashlessCloses.Load(),
		UndrainedRecords: o.undrained.Load(),
		UnresolvedPaths:  o.unresolved.Load(),
	}
}

// Start begins reading fanotify events in a background goroutine, then hashes
// the walked directory. The read loop runs during the walk because every file
// the walk opens queues a record while the mark is active: with nothing
// reading, a directory of more files than the kernel queue holds (16384 by
// default) would overflow it before the run began. An open the read loop
// processes before the walk has hashed its file carries no input hash. The
// walk also caches every directory it passes by its handle, so a record read
// after its directory was removed can still be named (P-28).
func (o *Observer) Start() {
	o.startedAt = time.Now()
	go o.readLoop()
	walk := o.cfg.PathFilter
	if walk == "" {
		walk = o.cfg.Path
	}
	if walk != "" {
		resolve := newKernelResolver(o.mounts, o.openHandle)
		_ = filepath.Walk(walk, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				o.dirs.fillPath(path, resolve)
			}
			if err == nil && info.Mode().IsRegular() {
				if h, err := content.SHA256File(path); err == nil {
					// A hash the read loop settled meanwhile is newer than
					// this read and is kept.
					o.mu.Lock()
					if _, ok := o.shadowHashes[path]; !ok {
						o.shadowHashes[path] = h
					}
					if st, ok := info.Sys().(*syscall.Stat_t); ok {
						key := inodeKey{dev: uint64(st.Dev), ino: st.Ino}
						if _, ok := o.shadowHashesByInode[key]; !ok {
							o.shadowHashesByInode[key] = h
						}
					}
					o.mu.Unlock()
				}
			}
			return nil
		})
	}
}

// Stop signals the read loop to exit, waits for it, and releases all
// file descriptors. The events channel is closed after Stop returns.
func (o *Observer) Stop() error {
	// Signal the poll loop.
	_, _ = unix.Write(o.stopW, []byte{0})
	// Wait for readLoop to finish. Hashing is synchronous within readLoop
	// now (see hashSettled), so there are no outstanding goroutines to wait
	// on beyond readLoop itself.
	<-o.stopped

	_ = unix.Close(o.fanotifyFD)
	if o.mountTableFD >= 0 {
		o.mountTableChanged = mountTableChanged(o.mountTableFD)
		_ = unix.Close(o.mountTableFD)
		o.mountTableFD = -1
	}
	o.dirs.close()
	for _, fd := range o.mounts {
		_ = unix.Close(fd)
	}
	_ = unix.Close(o.stopR)
	_ = unix.Close(o.stopW)
	close(o.events)
	return nil
}

// pollTimeout returns how long readLoop's poll may block, in milliseconds:
// until the quiet window of the earliest pending close ends, when that close
// becomes eligible to hash purely by the passage of quiet time
// (settleQuietWindow), or without limit when no close is pending. The read
// loop therefore wakes for a record, for a settle deadline or for the stop
// signal, and not on a fixed period (P-29). A deadline that has passed gives
// zero: a close registered in the batch just read is judged on the next
// iteration, which its settle snapshot needs.
func (o *Observer) pollTimeout() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.pendingCloses) == 0 {
		return -1
	}
	var next time.Time
	for path := range o.pendingCloses {
		if d := o.lastWriteAt[path].Add(o.settleDelay); next.IsZero() || d.Before(next) {
			next = d
		}
	}
	wait := time.Until(next)
	if wait <= 0 {
		return 0
	}
	return int((wait + time.Millisecond - 1) / time.Millisecond)
}

// settleQuietWindow is the default settleDelay: a path must go this long
// with no observed write-class event before a pending FileClose for it is
// hashed. "Survived one readLoop iteration untouched" is not enough -- on a
// loaded host an unrelated fanotify wakeup (including the observer's own
// hash-read FAN_OPEN) can end an iteration microseconds after it began, so
// an intermediate close in a write burst could otherwise be hashed against
// content the next write immediately truncates (round 3's CI failure).
//
// The value is bounded on both sides: it must exceed the sub-millisecond
// gaps within a single logical rewrite (so a burst never has a quiet gap
// this long, and a hash is only ever published once the writer has actually
// been starved for this whole window -- unlikely on any real scheduler, but
// the failure mode to keep in mind when considering raising this further),
// yet stay well below the gap between an agent's distinct operations on a
// path -- once a file is written, closed, then (say) renamed or deleted a
// short time later, its content is only hashable in the interval between.
// The read loop wakes at the end of the window (pollTimeout), so total
// publish latency is the window plus at most a millisecond of rounding,
// clearing the sub-millisecond burst-gap bound by ~1000x while leaving
// ample room under cmd/simagent's 50ms fixture gap (see
// TestObserver_CloseHashSurvivesQuickRename, the regression guard for this).
const settleQuietWindow = 20 * time.Millisecond

func (o *Observer) readLoop() {
	defer close(o.stopped)

	buf := make([]byte, 4096*metadataSize)
	pollFDs := []unix.PollFd{
		{Fd: int32(o.fanotifyFD), Events: unix.POLLIN},
		{Fd: int32(o.stopR), Events: unix.POLLIN},
	}

	for {
		_, err := unix.Poll(pollFDs, o.pollTimeout())
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			o.flushPendingCloses(buf)
			return
		}

		// Stop signal received. The records the kernel queued before it
		// are part of the capture, so they are read first (drainAtStop).
		// Then no more writes will ever be observed, so it is always safe
		// to resolve whatever is still pending rather than silently
		// dropping it.
		if pollFDs[1].Revents&unix.POLLIN != 0 {
			o.drainAtStop(buf)
			o.flushPendingCloses(buf)
			return
		}

		// Snapshot before draining: resolveSettled uses this to tell which
		// pending closes survive this iteration untouched (identity-compared
		// against pendingCloses afterward), versus ones this same iteration
		// just registered or superseded. Surviving is necessary but not
		// sufficient -- resolveSettled additionally requires the path to
		// have been quiet for settleDelay before it hashes, since an
		// iteration can end almost immediately and a survivor can still be
		// superseded moments later by a write that hasn't happened yet. See
		// resolveSettled and registerClose for why this -- not pathGeneration
		// alone -- guarantees a published hash reflects the file's eventual
		// final content.
		before := o.settleSnapshot()
		if pollFDs[0].Revents&unix.POLLIN != 0 {
			o.drainNonBlocking(buf)
		}
		o.resolveSettled(before, buf, false)
	}
}

// stopDrainBudget is how long the read loop keeps reading after the stop
// signal (Observer.stopDrain). It is meant to cover a full default queue
// (16384 records, each a handle resolution and a statx), which is not
// measured; a process that keeps writing after the stop can keep the queue
// from emptying, and the budget ends the read.
const stopDrainBudget = 2 * time.Second

// stopCountBudget bounds the count of the records left once stopDrain is
// spent, against a writer that never lets the queue empty.
const stopCountBudget = 250 * time.Millisecond

// drainAtStop reads the records still queued when Stop was signalled and
// processes them like any other batch, for at most stopDrain. Records that
// remain after that are read without being processed and counted in
// undrained, so the capture says it is short instead of being silently so.
// The count skips the observer's own records and those PIDFilter excludes,
// which would never have been emitted; it does not apply PathFilter, which
// needs the path resolved, so it can count a record the filter would have
// dropped. It is a lower bound: the count stops at stopCountBudget.
func (o *Observer) drainAtStop(buf []byte) {
	defer o.releaseHeld()
	resolve := newKernelResolver(o.mounts, o.openHandle)
	deadline := time.Now().Add(o.stopDrain)
	for time.Now().Before(deadline) {
		n := o.readReady(buf)
		if n == 0 {
			return
		}
		now := time.Now()
		raw := parseEvents(buf, n, resolve, o.dirs)
		for i := range raw {
			o.processRawEvent(&raw[i], now.Add(time.Duration(i)))
		}
	}
	deadline = time.Now().Add(stopCountBudget)
	for time.Now().Before(deadline) {
		n := o.readReady(buf)
		if n == 0 {
			return
		}
		o.undrained.Add(o.countRecords(buf, n))
	}
}

// readReady reads one buffer of fanotify records if any are queued, without
// blocking, and returns its length, or zero when the queue is empty or the
// read fails.
func (o *Observer) readReady(buf []byte) int {
	pollFDs := []unix.PollFd{{Fd: int32(o.fanotifyFD), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(pollFDs, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil || pollFDs[0].Revents&unix.POLLIN == 0 {
			return 0
		}
		break
	}
	n, err := unix.Read(o.fanotifyFD, buf)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// countRecords counts the records in buf[:n] that the observer would have
// considered, without resolving their handles: not its own, and not excluded
// by PIDFilter. An overflow record sets overflow and is not counted.
func (o *Observer) countRecords(buf []byte, n int) uint64 {
	self := o.selfPID()
	var count uint64
	for offset := 0; offset+metadataSize <= n; {
		meta := readMetadata(buf[offset:])
		if meta.EventLen < metadataSize || offset+int(meta.EventLen) > n {
			break
		}
		offset += int(meta.EventLen)
		switch {
		case meta.Mask&unix.FAN_Q_OVERFLOW != 0:
			o.overflow = true
		case meta.PID == self:
		case o.cfg.PIDFilter > 0 && meta.PID != o.cfg.PIDFilter:
		default:
			count++
		}
	}
	return count
}

// drainNonBlocking processes every fanotify record currently available
// without blocking, returning once none remain (or the stop pipe becomes
// readable -- the caller's own next check notices that, so this just needs
// to not spin past it). It reports whether it emptied the queue: false when
// it returned on the stop pipe with records still queued, or on an error. Used both for readLoop's normal per-iteration
// pickup and, from hashSettled, as the synchronous catch-up that makes its
// generation check authoritative: any write whose syscall has already
// returned has its notification already enqueued here, whether or not this
// observer has gotten to it yet, so a non-blocking drain right before
// trusting a hash is not a best-effort peek, it is a real answer to "has
// anything else happened yet".
func (o *Observer) drainNonBlocking(buf []byte) bool {
	pollFDs := []unix.PollFd{
		{Fd: int32(o.fanotifyFD), Events: unix.POLLIN},
		{Fd: int32(o.stopR), Events: unix.POLLIN},
	}

	for {
		_, err := unix.Poll(pollFDs, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return false
		}
		if pollFDs[0].Revents&unix.POLLIN == 0 {
			o.releaseHeld()
			return true
		}
		if pollFDs[1].Revents&unix.POLLIN != 0 {
			return false
		}

		n, err := unix.Read(o.fanotifyFD, buf)
		if err != nil || n == 0 {
			return false
		}

		// One batch, one clock reading, and one nanosecond per record on top:
		// the verifier sorts by timestamp (stably) and pairs by position, and a
		// close is emitted only after its settle window, so without the offset
		// it sorted after every later record of its batch and lost its place
		// (P-18). A batch is read in microseconds, so the offsets never reach
		// the next batch's reading.
		now := time.Now()
		raw := parseEvents(buf, n, newKernelResolver(o.mounts, o.openHandle), o.dirs)
		for i := range raw {
			o.processRawEvent(&raw[i], now.Add(time.Duration(i)))
		}
	}
}

// pidOf returns the causing process of a raw event, or zero (not recorded)
// when the kernel reported none, as it does for events caused by the kernel
// itself.
func pidOf(e *rawEvent) uint32 {
	if e.PID <= 0 {
		return 0
	}
	return uint32(e.PID)
}

func (o *Observer) processRawEvent(e *rawEvent, ts time.Time) {
	if e.Mask&unix.FAN_Q_OVERFLOW != 0 {
		o.overflow = true
		return
	}

	// PID filter.
	if o.cfg.PIDFilter > 0 && e.PID != o.cfg.PIDFilter {
		return
	}

	// A record no handle resolved (its directory was removed before it was
	// read) is counted before the path filter, which it can never pass, so
	// the count does not depend on the filter. The observer's own records
	// are left out, as cmd/watch leaves them out of the capture.
	self := o.selfPID()
	if e.Path == "" && e.PID != self {
		o.unresolved.Add(uint64(len(maskToActionTypes(e.Mask))))
	}

	// Path filter.
	if o.cfg.PathFilter != "" && !strings.HasPrefix(e.Path, o.cfg.PathFilter) {
		return
	}

	o.mu.Lock()
	if e.PID == self && e.Mask&unix.FAN_OPEN != 0 && o.pendingHashOpens[e.Path] > 0 {
		o.pendingHashOpens[e.Path]--
		if o.pendingHashOpens[e.Path] == 0 {
			delete(o.pendingHashOpens, e.Path)
		}
		o.mu.Unlock()
		e.Mask &^= unix.FAN_OPEN
		if e.Mask == 0 {
			return
		}
	} else {
		o.mu.Unlock()
	}

	// Bump the per-path write generation before dispatching anything. A
	// write-class event (FAN_CREATE, FAN_MODIFY, FAN_CLOSE_WRITE) means the
	// file's content just changed. A record that holds an open and none of
	// those counts as an open of its process instead (openGeneration): an
	// open(O_TRUNC) truncates inside the open call and the truncation is a
	// FAN_MODIFY of the opener, merged into its record or queued after it,
	// so an open alone changes nothing; only the closing process's own open
	// still drops its close's hash (P-39, amending P-16). hashSettled
	// snapshots this value before reading a close's content and compares it
	// again afterward (via a synchronous catch-up drain, not just whatever
	// this call happened to see), to detect a write landing in the TOCTOU
	// window either before the read started or during it. This alone only
	// proves nothing changed during one specific read -- it says nothing
	// about writes that haven't happened yet -- which is why registerClose
	// below carries the real guarantee for closes. The observer's own
	// hash-read FAN_OPEN is already stripped above and never reaches here.
	handle := handleKey(e.FSID, e.HandleType, e.HandleData)
	if e.Mask&(unix.FAN_CREATE|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE) != 0 {
		o.mu.Lock()
		if o.pathGeneration == nil {
			o.pathGeneration = make(map[string]uint64)
		}
		if o.lastWriteAt == nil {
			o.lastWriteAt = make(map[string]time.Time)
		}
		o.pathGeneration[e.Path]++
		o.lastWriteAt[e.Path] = ts
		if handle != "" {
			if o.handleGeneration == nil {
				o.handleGeneration = make(map[string]uint64)
			}
			o.handleGeneration[handle]++
		}
		o.mu.Unlock()
	} else if e.Mask&unix.FAN_OPEN != 0 {
		o.mu.Lock()
		if o.openGeneration == nil {
			o.openGeneration = make(map[openKey]uint64)
		}
		pid := pidOf(e)
		o.openGeneration[openKey{e.Path, pid}]++
		if handle != "" {
			o.openGeneration[openKey{"\x00" + handle, pid}]++
		}
		o.mu.Unlock()
	}

	o.placeHeld(e, ts)
	o.locateHeld(e)
	o.lastStamp = ts
	hold := holdRemoval(e.Mask)
	for _, actionType := range maskToActionTypes(e.Mask) {
		if actionType == hold {
			o.held = append(o.held, heldRemoval{ev: models.GroundTruthEvent{
				ActionType:      actionType,
				Target:          e.Path,
				PathIsAmbiguous: e.Ambiguous,
				PID:             pidOf(e),
			}})
			continue
		}
		if o.repeats(e.Path, actionType, pidOf(e)) {
			continue
		}
		if actionType == models.FileClose {
			o.registerClose(e.Path, ts, pidOf(e), e.Ambiguous, o.mountFor(e.FSID), e.HandleType, e.HandleData, handle)
		} else {
			event := models.GroundTruthEvent{
				Timestamp:       ts,
				ActionType:      actionType,
				Target:          e.Path,
				PathIsAmbiguous: e.Ambiguous,
				PID:             pidOf(e),
			}
			if actionType == models.FileOpen {
				// No hash at all when the probe never measured the file's
				// content: a stamp would be compared as a measurement (P-22).
				if hash, ok := o.inputHash(e.Path, o.mountFor(e.FSID), e.HandleType, e.HandleData, handle); ok {
					event.InputHash = &hash
				}
			}
			o.events <- event
		}
	}
}

// dirEntryBits are the bits of a directory-entry record. The kernel never
// merges them with content bits, since a content record carries the file's
// own handle and a directory-entry record does not (P-25).
const dirEntryBits = unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO

// holdRemoval returns the removal a record's events must not emit in place,
// or "" for none: the moved-from of a creation merged with a moved-from, the
// delete of a creation merged with a delete. The kernel queues a record at
// its first event and merges a later event of the same process on the same
// name into it while it is unread, so the removal can have happened long
// after the record's place, after the open, write and close of the file,
// whose own record comes next (P-27).
func holdRemoval(mask uint64) models.ActionType {
	switch mask & dirEntryBits {
	case unix.FAN_CREATE | unix.FAN_MOVED_FROM:
		return models.FileRename
	case unix.FAN_CREATE | unix.FAN_DELETE:
		return models.FileDelete
	}
	return ""
}

// placeHeld emits, before record e, the held removals whose place e marks,
// stamped with e's timestamp so they sort before e's own events. A held
// moved-from goes before the next moved-to record of the same process,
// which the kernel queued at the rename itself, unless a moved-from emitted
// in place is still waiting for that moved-to. A held delete goes before any
// record but a content record on its name whose file has left that name (a
// write before the delete; a file still there was created again after it).
// It then counts e's own moved-from and moved-to halves.
func (o *Observer) placeHeld(e *rawEvent, ts time.Time) {
	pid := pidOf(e)
	entry := e.Mask & dirEntryBits
	if len(o.held) > 0 {
		var keep []heldRemoval
		placedRename := false
		for _, h := range o.held {
			release := false
			switch h.ev.ActionType {
			case models.FileDelete:
				release = entry != 0 || e.Path != h.ev.Target || o.stillNamed(e)
			case models.FileRename:
				if !placedRename && entry == unix.FAN_MOVED_TO && h.ev.PID == pid && o.fromsInFlight[pid] == 0 {
					release, placedRename = true, true
				}
			}
			if !release {
				keep = append(keep, h)
				continue
			}
			o.emitHeld(h.ev, ts)
		}
		o.held = keep
	}
	if o.fromsInFlight == nil {
		o.fromsInFlight = make(map[uint32]int)
	}
	switch entry {
	case unix.FAN_MOVED_FROM:
		o.fromsInFlight[pid]++
	case unix.FAN_MOVED_TO:
		if o.fromsInFlight[pid] > 0 {
			o.fromsInFlight[pid]--
		}
	}
	if e.Mask&unix.FAN_MOVED_TO != 0 && e.Path != "" {
		if o.movedTo == nil {
			o.movedTo = make(map[uint32]map[string]bool)
		}
		if o.movedTo[pid] == nil {
			o.movedTo[pid] = make(map[string]bool)
		}
		o.movedTo[pid][e.Path] = true
	}
}

// emitHeld emits a held removal at ts unless it repeats its path's last
// event (P-18).
func (o *Observer) emitHeld(h models.GroundTruthEvent, ts time.Time) {
	h.Timestamp = ts
	if !o.repeats(h.Target, h.ActionType, h.PID) {
		o.events <- h
	}
}

// locateHeld records, for each held moved-from on the name content record e
// names, by the same process, where e's file is now. The first such record
// is the file's content record that followed its merged creation (P-27); the
// file left the name by the rename, so where it is now is where the rename
// took it, unless it moved again before the read. One resolution per held
// moved-from.
func (o *Observer) locateHeld(e *rawEvent) {
	if len(o.held) == 0 || e.Mask&dirEntryBits != 0 || len(e.HandleData) == 0 {
		return
	}
	pid := pidOf(e)
	for i := range o.held {
		h := &o.held[i]
		if h.looked || h.ev.ActionType != models.FileRename || h.ev.PID != pid || h.ev.Target != e.Path {
			continue
		}
		h.looked = true
		h.dest = o.whereNow(e)
	}
}

// releaseHeld emits every held removal, in order, one nanosecond after the
// last record processed: the end of a drain, where the record that would
// have marked its place did not come (a moved-to merged into an earlier
// record of its name, or a delete with nothing after it). A held moved-from
// whose file is now at a path that a moved-to record of its process named in
// this drain is followed by a moved-to on that path: the kernel merged the
// rename's moved-to into that earlier unread record, since it merges only
// records of one process on one directory and name (P-38).
func (o *Observer) releaseHeld() {
	ts := o.lastStamp.Add(time.Nanosecond)
	for _, h := range o.held {
		o.emitHeld(h.ev, ts)
		if h.ev.ActionType == models.FileRename && h.dest != "" && h.dest != h.ev.Target && o.movedTo[h.ev.PID][h.dest] {
			to := h.ev
			to.Target = h.dest
			to.PathIsAmbiguous = false
			o.emitHeld(to, ts)
		}
	}
	o.held = nil
	o.fromsInFlight = nil
	o.movedTo = nil
}

// stillNamed reports whether the file content record e names, by its handle,
// is still at the path the record names (fileNamed, or namedNow).
func (o *Observer) stillNamed(e *rawEvent) bool {
	if o.fileNamed != nil {
		return o.fileNamed(e)
	}
	return o.namedNow(e)
}

// namedNow resolves e's file handle and compares the file's current path with
// the record's. A handle that does not resolve, a deleted file included, is
// not named there.
func (o *Observer) namedNow(e *rawEvent) bool {
	p := o.pathNow(e)
	return p != "" && p == e.Path
}

// whereNow returns the path at which the file content record e names is now
// (fileAt, or pathNow).
func (o *Observer) whereNow(e *rawEvent) string {
	if o.fileAt != nil {
		return o.fileAt(e)
	}
	return o.pathNow(e)
}

// pathNow resolves e's file handle to the file's current path through the
// probe's mount for its filesystem, or "" when it does not resolve. A file
// with no name left (the kernel's " (deleted)" suffix) has no path.
func (o *Observer) pathNow(e *rawEvent) string {
	mountFD := o.mountFor(e.FSID)
	if len(e.HandleData) == 0 || mountFD < 0 {
		return ""
	}
	fd, err := o.open(mountFD, e.HandleType, e.HandleData)
	if err != nil {
		return ""
	}
	defer func() { _ = unix.Close(fd) }()
	p, err := os.Readlink(procFD(fd))
	if err != nil || strings.HasSuffix(p, " (deleted)") {
		return ""
	}
	return p
}

// repeats records that actionType is being emitted for path by pid and
// reports whether it repeats the previous emission for that path: a
// file_write after a file_write, or a file_rename after a file_rename, by
// the same process, with no other event on the path between. Such a repeat
// is one of the kernel's unmerged halves of one operation and is dropped
// (P-18). Any other event resets the path, so two writes separated by a
// close, or by another process's event, are both emitted.
func (o *Observer) repeats(path string, actionType models.ActionType, pid uint32) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lastEmitted == nil {
		o.lastEmitted = make(map[string]emitted)
	}
	prev, ok := o.lastEmitted[path]
	o.lastEmitted[path] = emitted{typ: actionType, pid: pid}
	if !ok || prev.pid != pid || prev.typ != actionType {
		return false
	}
	return actionType == models.FileWrite || actionType == models.FileRename
}

// emptyFileHash is the InputHash of the open that created a file: a file born
// during the capture was empty when it was created (P-22).
const emptyFileHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// inputHash returns the content a FAN_OPEN on path found, when the probe
// measured it: the settled hash of the file (lookupShadowHash), or empty
// content for the open that created a file born during the capture. ok is
// false otherwise, for a file outside the walked directory that the probe never
// hashed, and the open then carries no InputHash: a claimed input on it is
// unverified, not compared against a stamp (P-22, V-29).
func (o *Observer) inputHash(path string, mountFD int, handleType int32, handleData []byte, handle string) (string, bool) {
	key, born, byHandle, identified := o.identify(path, mountFD, handleType, handleData, handle)
	first := false
	if identified {
		o.mu.Lock()
		if o.openedInodes == nil {
			o.openedInodes = make(map[inodeKey]bool)
		}
		first = !o.openedInodes[key]
		o.openedInodes[key] = true
		o.mu.Unlock()
	}
	if h, ok := o.lookupShadowHash(path, key, identified && byHandle); ok {
		return h, true
	}
	// Only the first open of a file born after Start is its creating open. A
	// file without a birth time, or born before Start, is never assumed empty.
	if identified && first && !o.startedAt.IsZero() && !born.IsZero() && !born.Before(o.startedAt) {
		return emptyFileHash, true
	}
	return "", false
}

// identify resolves the file an event names to its device and inode and its
// birth time, through the event's file handle when there is one (byHandle)
// and its path otherwise, with one open and one statx. born is zero when the
// filesystem does not report a birth time. The key is the one fstat gives
// (inodeKeyFromFD): statx reports the device as a major and minor number, and
// unix.Mkdev encodes them as stat's st_dev does.
//
// What a handle identifies is remembered by its handleKey (identities): a
// handle names one inode for its whole life, generation included, and an
// inode's device, number and birth time never change, so the shared libraries
// every command opens are identified once (P-29). A remembered file that has
// since been deleted is still identified, by the inode its handle named.
func (o *Observer) identify(path string, mountFD int, handleType int32, handleData []byte, handle string) (key inodeKey, born time.Time, byHandle, ok bool) {
	var fd int
	var err error
	byHandle = handleData != nil && mountFD >= 0
	if byHandle && handle != "" {
		o.mu.Lock()
		id, found := o.identities[handle]
		o.mu.Unlock()
		if found {
			return id.key, id.born, true, true
		}
	}
	defer func() {
		if ok && byHandle && handle != "" {
			o.mu.Lock()
			if o.identities == nil || len(o.identities) >= identitiesSize {
				o.identities = make(map[string]identity)
			}
			o.identities[handle] = identity{key: key, born: born}
			o.mu.Unlock()
		}
	}()
	if byHandle {
		fd, err = o.open(mountFD, handleType, handleData)
	} else {
		fd, err = unix.Open(path, unix.O_RDONLY|unix.O_PATH|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return inodeKey{}, time.Time{}, byHandle, false
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_BTIME, &st); err != nil {
		return inodeKey{}, time.Time{}, byHandle, false
	}
	key = inodeKey{dev: unix.Mkdev(st.Dev_major, st.Dev_minor), ino: st.Ino}
	if st.Mask&unix.STATX_BTIME != 0 {
		born = time.Unix(st.Btime.Sec, int64(st.Btime.Nsec))
	}
	return key, born, byHandle, true
}

// lookupShadowHash returns the settled hash of the file a FAN_OPEN on path
// names, and false when the probe has none. It tries shadowHashesByInode by
// the file's device and inode first, when the event's file handle gave them
// (byInode), then shadowHashes by path. The inode matters across a rename:
// shadowHashes is keyed by the path a file had when it was last hashed (at
// its FAN_CLOSE_WRITE settle), and the probe does not link a FAN_MOVED_FROM
// to its FAN_MOVED_TO, so a rename orphans the path-keyed entry. Device+inode
// identifies the file regardless of what it's currently named.
func (o *Observer) lookupShadowHash(path string, key inodeKey, byInode bool) (string, bool) {
	// The inode first: after an atomic replace the path names a new inode
	// whose hash was settled under the temporary's name, while the path's
	// own entry still holds the replaced file's hash. The path is the
	// fallback for a handle that cannot be resolved (P-20).
	o.mu.Lock()
	defer o.mu.Unlock()
	if byInode {
		if h, ok := o.shadowHashesByInode[key]; ok {
			o.shadowHashes[path] = h
			return h, true
		}
	}
	h, ok := o.shadowHashes[path]
	return h, ok
}

// identitiesSize bounds the identities cache; a full cache starts over.
const identitiesSize = 16384

// identity is what identify found for a file handle.
type identity struct {
	key  inodeKey
	born time.Time
}

// inodeKey identifies a file by device and inode number, stable across
// renames (unlike a path) and distinct across bind mounts / filesystems
// (unlike inode number alone).
type inodeKey struct {
	dev uint64
	ino uint64
}

// inodeKeyFromFD reads the (device, inode) pair identifying the file behind
// fd.
func inodeKeyFromFD(fd int) (inodeKey, bool) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return inodeKey{}, false
	}
	return inodeKey{dev: uint64(stat.Dev), ino: stat.Ino}, true
}

// handleKey identifies the file a content record's handle names, without a
// system call: the filesystem id, the handle type and the handle's bytes.
// The handle stays the same across renames, so it reaches a file that a
// name no longer does. It is empty for a record that carries no handle (a
// create, delete or rename record names only its directory and entry).
func handleKey(fsid fsID, handleType int32, handleData []byte) string {
	if len(handleData) == 0 {
		return ""
	}
	var buf [320]byte
	b := buf[:0]
	b = strconv.AppendInt(b, int64(fsid[0]), 10)
	b = append(b, ':')
	b = strconv.AppendInt(b, int64(fsid[1]), 10)
	b = append(b, ':')
	b = strconv.AppendInt(b, int64(handleType), 10)
	b = append(b, ':')
	return string(hex.AppendEncode(b, handleData))
}

// openForWriteBy reports whether process pid holds the file behind fd open
// for writing, through any of its descriptors, or whether that cannot be
// told: pid 0 (the kernel), a file that cannot be identified, or a descriptor
// table the probe may not read. A process that no longer exists holds
// nothing. It reads /proc/<pid>/fd, which is the table of every thread that
// shares it, and the flags in /proc/<pid>/fdinfo of the descriptors that name
// the file.
func openForWriteBy(pid uint32, fd int) bool {
	if pid == 0 {
		return true
	}
	key, ok := inodeKeyFromFD(fd)
	if !ok {
		return true
	}
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return !os.IsNotExist(err)
	}
	for _, entry := range entries {
		var st unix.Stat_t
		if unix.Stat(dir+"/"+entry.Name(), &st) != nil {
			continue // closed since the listing
		}
		if uint64(st.Dev) != key.dev || st.Ino != key.ino {
			continue
		}
		flags, ok := fdFlags(pid, entry.Name())
		if !ok || flags&unix.O_ACCMODE != unix.O_RDONLY {
			return true
		}
	}
	return false
}

// fdFlags reads the open flags of descriptor fd of process pid from its
// fdinfo, where the kernel writes them in octal.
func fdFlags(pid uint32, fd string) (int, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, fd))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, found := strings.CutPrefix(line, "flags:"); found {
			flags, err := strconv.ParseInt(strings.TrimSpace(rest), 8, 64)
			return int(flags), err == nil
		}
	}
	return 0, false
}

// registerClose records a newly observed FileClose for path as the pending
// one to judge on some future settle check (see resolveSettled). If a close
// was already pending for this same path, that older one is immediately
// superseded: a second close arriving proves the first's content is not the
// file's final content, so there's no point even reading it -- it is
// emitted right here with no OutputHash.
//
// This, not pathGeneration, is what actually guarantees a hash the observer
// does attach reflects the eventual final content: a close is never hashed
// until it has survived a full settle cycle with nothing superseding it.
func (o *Observer) registerClose(path string, ts time.Time, pid uint32, ambiguous bool, mountFD int, handleType int32, handleData []byte, handle string) {
	o.mu.Lock()
	if o.pendingCloses == nil {
		o.pendingCloses = make(map[string]*pendingClose)
	}
	superseded, existed := o.pendingCloses[path]
	pathFD := -1
	if handleData != nil && mountFD >= 0 {
		var err error
		if pathFD, err = o.open(mountFD, handleType, handleData); err != nil {
			pathFD = -1
		}
	} else if o.mountFD == -1 {
		pathFD, _ = unix.Open(path, unix.O_RDONLY|unix.O_PATH, 0)
	}
	o.pendingCloses[path] = &pendingClose{ts: ts, pid: pid, ambiguous: ambiguous, pathFD: pathFD, gen: o.pathGeneration[path], handle: handle, hgen: o.handleGeneration[handle], opens: o.openedSince(path, handle, pid)}
	o.mu.Unlock()

	if existed {
		if superseded.pathFD >= 0 {
			_ = unix.Close(superseded.pathFD)
		}
		o.hashlessCloses.Add(1)
		o.events <- models.GroundTruthEvent{
			Timestamp:  superseded.ts,
			ActionType: models.FileClose,
			Target:     path,
			// No OutputHash: a newer close for this path arrived before
			// this one was ever judged settled.
			PathIsAmbiguous: superseded.ambiguous,
			PID:             superseded.pid,
		}
	}
}

// settleSnapshot copies the current pendingCloses so resolveSettled can
// later tell, by pointer identity, which entries survived a settle cycle
// unchanged.
func (o *Observer) settleSnapshot() map[string]*pendingClose {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.pendingCloses) == 0 {
		return nil
	}
	snap := make(map[string]*pendingClose, len(o.pendingCloses))
	for path, entry := range o.pendingCloses {
		snap[path] = entry
	}
	return snap
}

// resolveSettled hashes and emits every entry in before that is both still
// the current pendingCloses entry for its path (survived this settle cycle
// without a newer close superseding it, see registerClose) and whose path
// has been quiet -- no write-class event -- for at least settleDelay. Such
// an entry is removed from pendingCloses and emitted, with an OutputHash
// unless hashing failed or hashSettled's own check caught a write during
// the read. An entry that was superseded, or already resolved by a
// concurrent call, is left alone (registerClose emitted it). An entry that
// is still current but not yet quiet is left in pendingCloses for a later
// cycle to judge. force skips the quiet check: at shutdown no further write
// can ever be observed, so every survivor is by definition settled.
func (o *Observer) resolveSettled(before map[string]*pendingClose, buf []byte, force bool) {
	for path, entry := range before {
		o.mu.Lock()
		current, ok := o.pendingCloses[path]
		settled := ok && current == entry
		quiet := force || time.Since(o.lastWriteAt[path]) >= o.settleDelay
		var pathFD int
		var changed bool
		if settled && quiet {
			pathFD = entry.pathFD
			// A write-class event after this close was registered means the
			// content it described may no longer be there, and so does an
			// open by the closing process: its truncation can be merged into
			// a record the probe already read (P-26), and the rule stays
			// conservative there. Quiet time does not help: a writer stalled
			// between the truncate and its write leaves the path quiet while
			// the file is empty. An open by another process changes nothing,
			// since its truncation would be a FAN_MODIFY of its own (P-39).
			// The file may have been written under another name since (P-26).
			changed = o.pathGeneration[path] != entry.gen ||
				(entry.handle != "" && o.handleGeneration[entry.handle] != entry.hgen) ||
				o.openedSince(path, entry.handle, entry.pid) != entry.opens
			delete(o.pendingCloses, path)
		}
		o.mu.Unlock()

		if !settled || !quiet {
			continue
		}

		var digest string
		hashed := false
		if !changed {
			digest, hashed = o.hashSettledFD(path, buf, pathFD, entry.pid, entry.handle)
		}
		if pathFD >= 0 {
			_ = unix.Close(pathFD)
		}
		event := models.GroundTruthEvent{
			Timestamp:  entry.ts,
			ActionType: models.FileClose,
			Target:     path,
			// OutputHash left nil below when hashing failed, when a
			// write-class event followed this close (changed), or when a
			// write raced in during the read itself (hashSettled's own
			// check). A newer close would instead have gone through
			// registerClose's supersession above.
			PathIsAmbiguous: entry.ambiguous,
			PID:             entry.pid,
		}
		if hashed {
			event.OutputHash = &digest
		} else {
			o.hashlessCloses.Add(1)
		}
		o.events <- event
	}
}

// flushPendingCloses resolves everything still pending at shutdown. Once
// the observer is stopping, no more writes will ever be observed, so every
// remaining entry is by definition settled.
func (o *Observer) flushPendingCloses(buf []byte) {
	o.releaseHeld()
	o.resolveSettled(o.settleSnapshot(), buf, true)
}

// hashSettled reads target's content and decides whether that specific read
// can be trusted, i.e. nothing changed while it was in progress. It is the
// second, narrower line of defense after registerClose/resolveSettled
// (which guarantee the close wasn't already superseded before this call):
// after hashFile returns, it drains (non-blocking) anything already sitting
// in the fanotify queue -- which, by fanotify's own ordering guarantee,
// already includes the notification for any write whose syscall has
// already completed, whether or not this observer has processed it yet --
// before comparing the path's generation against the snapshot taken before
// the read. If they differ, the file was touched again during the read and
// it cannot be trusted. The file's handleGeneration is compared the same
// way, for a write under another name, and a drain that could not empty the
// queue (the stop pipe is readable and records are still queued) cannot vouch
// for the read either (P-26).
//
// Before the read it asks whether the closing process, pid, still holds the
// file open for writing (writerHolds). The kernel merges that process's later
// open and truncation into the close's record while it is unread, so no
// later record shows them: a rewrite that has truncated the file and not yet
// written leaves the path quiet, and the generation unchanged, with the file
// empty (P-26). A rewrite that has finished is no hazard, since its content
// is a real final state, and anything the process does after this check is a
// record of its own, which the drain after the read sees.
func (o *Observer) hashSettledFD(target string, buf []byte, pathFD int, pid uint32, handle string) (digest string, ok bool) {
	o.mu.Lock()
	gen := o.pathGeneration[target]
	hgen := o.handleGeneration[handle]
	opens := o.openedSince(target, handle, pid)
	o.mu.Unlock()

	if pathFD >= 0 && o.writerHolds != nil && o.writerHolds(pid, pathFD) {
		return "", false
	}
	// Only a regular file has content to hash. Reopening a named pipe for
	// reading blocks until a writer opens it, which may be never (logind's
	// inhibitor pipes under /run/systemd/inhibit are closed by processes
	// anywhere on the host), and the read loop, and with it Stop, would wait
	// forever (P-35).
	if pathFD >= 0 && !isRegularFD(pathFD) {
		return "", false
	}

	var d string
	var err error
	var suppressPath string

	if pathFD >= 0 {
		procPath := procFD(pathFD)
		suppressPath, _ = os.Readlink(procPath)
		// The read's own FAN_OPEN names the file by its directory and name
		// (P-25), which carry no mark of a deletion.
		suppressPath = strings.TrimSuffix(suppressPath, " (deleted)")
		if suppressPath == "" {
			suppressPath = target
		}

		o.mu.Lock()
		if o.pendingHashOpens == nil {
			o.pendingHashOpens = make(map[string]int)
		}
		o.pendingHashOpens[suppressPath]++
		o.mu.Unlock()

		readFD, openErr := unix.Open(procPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if openErr == nil {
			d, err = o.hashFD(readFD)
			_ = unix.Close(readFD)
		} else {
			err = openErr
		}
	} else if o.mountFD == -1 {
		d, err = o.hashFD(-1)
	} else {
		err = fmt.Errorf("no pathFD")
	}

	emptied := o.drainNonBlocking(buf)

	o.mu.Lock()
	raced := !emptied || o.pathGeneration[target] != gen ||
		(handle != "" && o.handleGeneration[handle] != hgen) ||
		o.openedSince(target, handle, pid) != opens
	if err != nil && suppressPath != "" {
		o.pendingHashOpens[suppressPath]--
		if o.pendingHashOpens[suppressPath] == 0 {
			delete(o.pendingHashOpens, suppressPath)
		}
	}
	o.mu.Unlock()

	if err != nil || raced {
		return "", false
	}

	o.mu.Lock()
	o.shadowHashes[target] = d
	if pathFD >= 0 {
		if key, ok := inodeKeyFromFD(pathFD); ok {
			if o.shadowHashesByInode == nil {
				o.shadowHashesByInode = make(map[inodeKey]string)
			}
			o.shadowHashesByInode[key] = d
		}
	}
	o.mu.Unlock()

	return d, true
}

// actionBits are the mask bits maskToActionTypes reads, in the order of the
// index into actionTable.
var actionBits = [...]uint64{
	unix.FAN_OPEN, unix.FAN_CREATE, unix.FAN_MODIFY, unix.FAN_CLOSE_WRITE,
	unix.FAN_DELETE, unix.FAN_MOVED_FROM, unix.FAN_MOVED_TO,
}

// actionTable holds the expansion of every combination of actionBits, so
// that maskToActionTypes allocates nothing per record.
var actionTable = func() (t [1 << len(actionBits)][]models.ActionType) {
	for i := range t {
		var mask uint64
		for b, bit := range actionBits {
			if i&(1<<b) != 0 {
				mask |= bit
			}
		}
		t[i] = expandMask(mask)
	}
	return t
}()

// maskToActionTypes maps fanotify event mask bits to models.ActionType values.
// If multiple bits map to the same ActionType, only one is emitted. The
// returned slice is shared and must not be modified.
func maskToActionTypes(mask uint64) []models.ActionType {
	i := 0
	for b, bit := range actionBits {
		if mask&bit != 0 {
			i |= 1 << b
		}
	}
	return actionTable[i]
}

// expandMask builds maskToActionTypes' answer for one mask.
func expandMask(mask uint64) []models.ActionType {
	seen := make(map[models.ActionType]bool, 4)
	var types []models.ActionType

	add := func(at models.ActionType) {
		if !seen[at] {
			seen[at] = true
			types = append(types, at)
		}
	}

	// The kernel merges consecutive events on one object into a single
	// notification whose mask holds several bits, and a mask has no order. The
	// events a merged mask expands to are therefore emitted in causal order
	// (open, then write, then close), so a merged notification and the same
	// operations delivered as separate notifications produce the same sequence.
	// Without this, whether the kernel merged them decided whether a write read
	// as coming before the open that preceded it, and the verifier's alignment,
	// which pairs by position, read an honest run as a fabrication.
	if mask&unix.FAN_OPEN != 0 {
		add(models.FileOpen)
	}
	if mask&unix.FAN_CREATE != 0 {
		add(models.FileWrite)
	}
	if mask&unix.FAN_MODIFY != 0 {
		add(models.FileWrite)
	}
	if mask&unix.FAN_CLOSE_WRITE != 0 {
		add(models.FileClose)
	}
	if mask&unix.FAN_DELETE != 0 {
		add(models.FileDelete)
	}
	if mask&unix.FAN_MOVED_FROM != 0 {
		add(models.FileRename)
	}
	if mask&unix.FAN_MOVED_TO != 0 {
		add(models.FileRename)
	}
	return types
}

// isRegularFD reports whether fd, which may be an O_PATH descriptor, names a
// regular file. fstat works on an O_PATH descriptor and never blocks.
func isRegularFD(fd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG
}
