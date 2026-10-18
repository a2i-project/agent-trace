package fs

import (
	"container/list"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/sys/unix"
)

// dirCacheSize bounds the directory cache. An entry is a handle of at most
// 128 bytes and a path, so a full cache holds a few megabytes. Every resolved
// record moves its directory to the front, so the directories an agent is
// working in stay; an entry is evicted only after this many other directories
// were resolved since its own last record.
const dirCacheSize = 8192

// renameMask is the mask of the rename watch: a move of any object on the
// marked filesystems, directories included (P-28).
const renameMask = unix.FAN_MOVE_SELF | unix.FAN_ONDIR

// DirCacheStats reports what the directory cache did (P-28).
type DirCacheStats struct {
	// Watching is true when the rename watch marked at least one
	// filesystem. Without it no record is resolved through the cache.
	Watching bool
	// Resolved counts the records whose directory no longer resolved and
	// whose path was named through an entry of the start walk instead.
	Resolved uint64
	// Hits counts the records whose directory was named from an entry the
	// probe's own resolution filled, without resolving its handle again
	// (P-29); a directory removed since is among them.
	Hits uint64
	// Evicted counts the entries dropped because the cache was full.
	Evicted uint64
	// Invalidated counts the entries dropped because a directory on their
	// filesystem was renamed, or the rename watch lost records.
	Invalidated uint64
}

// dirCache maps a directory's file handle, as fanotify reports it in a
// DFID_NAME record, to the path that handle last resolved to. A record whose
// directory was removed before the probe read it no longer resolves; its
// directory's path is then taken from here and joined to the record's entry
// name (P-28).
//
// A cached path is stale once its directory, or a directory above it, has
// been renamed. The main mark has no FAN_ONDIR, so directory renames reach
// the probe only through the rename watch, a second fanotify group. Every
// lookup first reads that watch, and any directory rename on a filesystem
// drops every entry of that filesystem, so a path the cache returns was the
// directory's path when it was cached and no directory on its filesystem has
// been renamed since. The rename of a directory completes before its removal,
// and its record is queued in the rename watch before the rename returns, so
// a lookup made after a removal always sees the renames that preceded it.
type dirCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]*list.Element
	lru     *list.List
	// watch reports directory renames; nil disables lookups.
	watch *renameWatch
	stats DirCacheStats
}

// dirEntry is one cached directory.
type dirEntry struct {
	key  string
	fsid fsID
	path string
	// resolved is set when the path came from resolving the handle, as the
	// probe names a live directory, and not from the start walk, whose path
	// can name the directory through another mount or alias.
	resolved bool
}

// newDirCache returns a cache of at most max entries guarded by watch, which
// may be nil: entries are then kept but never used.
func newDirCache(max int, watch *renameWatch) *dirCache {
	return &dirCache{max: max, entries: map[string]*list.Element{}, lru: list.New(), watch: watch}
}

// dirKey identifies a directory handle: filesystem id, handle type and bytes.
func dirKey(fsid fsID, handleType int32, handleData []byte) string {
	b := make([]byte, 12, 12+len(handleData))
	binary.LittleEndian.PutUint32(b[0:4], uint32(fsid[0]))
	binary.LittleEndian.PutUint32(b[4:8], uint32(fsid[1]))
	binary.LittleEndian.PutUint32(b[8:12], uint32(handleType))
	return string(append(b, handleData...))
}

// fill records that the directory handle resolved to path.
func (c *dirCache) fill(fsid fsID, handleType int32, handleData []byte, path string) {
	c.put(fsid, handleType, handleData, path, true)
}

// put caches path for the directory handle; resolved says whether path came
// from resolving the handle (fill) or from the start walk (fillPath).
func (c *dirCache) put(fsid fsID, handleType int32, handleData []byte, path string, resolved bool) {
	if c == nil || path == "" {
		return
	}
	key := dirKey(fsid, handleType, handleData)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*dirEntry)
		if resolved || !e.resolved {
			e.path, e.resolved = path, resolved
		}
		c.lru.MoveToFront(el)
		return
	}
	c.entries[key] = c.lru.PushFront(&dirEntry{key: key, fsid: fsid, path: path, resolved: resolved})
	for c.lru.Len() > c.max {
		back := c.lru.Back()
		c.lru.Remove(back)
		delete(c.entries, back.Value.(*dirEntry).key)
		c.stats.Evicted++
	}
}

// fillPath caches the directory at path by its handle, as the start walk
// sees it. The handle name_to_handle_at gives a directory is the one fanotify
// reports for it.
func (c *dirCache) fillPath(path string) {
	if c == nil || c.watch == nil {
		return
	}
	fh, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return
	}
	id, err := fsidOf(path)
	if err != nil {
		return
	}
	c.put(id, fh.Type(), fh.Bytes(), path, false)
}

// hit returns the path of a directory handle the probe resolved before, when
// the rename watch guards its filesystem, so that the record is named without
// resolving the handle again (P-29). The caller has read the rename watch
// (sync) after reading the records it names: every event in them happened
// before that read, and every directory rename completed before it has
// dropped its filesystem's entries, so the path is the one resolving the
// handle would give, except for a rename that completes after that read,
// which resolving would see and the event predates. A directory removed since
// keeps its entry, as for lookup.
func (c *dirCache) hit(fsid fsID, handleType int32, handleData []byte) (string, bool) {
	if c == nil || c.watch == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.watch.guards(fsid) {
		return "", false
	}
	el, ok := c.entries[dirKey(fsid, handleType, handleData)]
	if !ok {
		return "", false
	}
	e := el.Value.(*dirEntry)
	if !e.resolved {
		return "", false
	}
	c.lru.MoveToFront(el)
	c.stats.Hits++
	return e.path, true
}

// lookup returns the cached path of a directory handle that no longer
// resolves, after applying every directory rename the watch has queued.
func (c *dirCache) lookup(fsid fsID, handleType int32, handleData []byte) (string, bool) {
	if c == nil || c.watch == nil {
		return "", false
	}
	c.sync()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.watch.guards(fsid) {
		return "", false
	}
	el, ok := c.entries[dirKey(fsid, handleType, handleData)]
	if !ok {
		return "", false
	}
	c.stats.Resolved++
	return el.Value.(*dirEntry).path, true
}

// sync reads the rename watch and drops the entries it invalidates.
func (c *dirCache) sync() {
	if c == nil || c.watch == nil {
		return
	}
	c.watch.drain(c)
}

// invalidate drops every entry of filesystem fsid, or every entry when all
// is set.
func (c *dirCache) invalidate(fsid fsID, all bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.lru.Front(); el != nil; {
		next := el.Next()
		if e := el.Value.(*dirEntry); all || e.fsid == fsid {
			c.lru.Remove(el)
			delete(c.entries, e.key)
			c.stats.Invalidated++
		}
		el = next
	}
}

// snapshot returns the counters.
func (c *dirCache) snapshot() DirCacheStats {
	if c == nil {
		return DirCacheStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Watching = c.watch != nil && !c.watch.broken
	return s
}

// close releases the rename watch.
func (c *dirCache) close() {
	if c != nil && c.watch != nil {
		_ = unix.Close(c.watch.fd)
	}
}

// renameWatch is a fanotify group that reports every move on the marked
// filesystems with the moved object's handle, the FAN_ONDIR bit set for a
// directory. Its records are used only to invalidate the directory cache and
// never become events. It is a group of its own because FAN_ONDIR applies to
// every event of a mark: in the main mark it would add the opens, creations
// and removals of directories to the capture.
type renameWatch struct {
	fd int
	// guarded are the filesystems the watch marked. A lookup on any other
	// filesystem misses, since a rename there would go unseen.
	guarded map[fsID]bool
	// broken is set when a read of the watch fails; lookups then miss.
	broken bool
	buf    []byte
}

// openRenameWatch creates the rename watch and marks each path with flags
// (FAN_MARK_FILESYSTEM in the probe, an inode mark in the unprivileged
// tests). It returns nil when no path could be marked.
func openRenameWatch(paths []string, flags uint) *renameWatch {
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_FID|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), unix.O_RDONLY)
	if err != nil {
		return nil
	}
	w := &renameWatch{fd: fd, guarded: map[fsID]bool{}, buf: make([]byte, 4096*metadataSize)}
	for _, p := range paths {
		id, err := fsidOf(p)
		if err != nil {
			continue
		}
		if unix.FanotifyMark(fd, unix.FAN_MARK_ADD|flags, renameMask, unix.AT_FDCWD, p) == nil {
			w.guarded[id] = true
		}
	}
	if len(w.guarded) == 0 {
		_ = unix.Close(fd)
		return nil
	}
	return w
}

// guards reports whether a directory rename on fsid would be seen.
func (w *renameWatch) guards(fsid fsID) bool {
	return !w.broken && w.guarded[fsid]
}

// drain reads every queued record of the watch without blocking. A directory
// move drops the cache entries of its filesystem; an overflow record, a
// record without a handle, or a failed read drops all of them, and a failed
// read also stops further lookups.
func (w *renameWatch) drain(c *dirCache) {
	if w.broken {
		return
	}
	for {
		n, err := unix.Read(w.fd, w.buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || (err == nil && n == 0) {
			return
		}
		if err != nil {
			c.mu.Lock()
			w.broken = true
			c.mu.Unlock()
			c.invalidate(fsID{}, true)
			return
		}
		w.apply(c, w.buf[:n])
	}
}

// apply invalidates the cache for each record in buf.
func (w *renameWatch) apply(c *dirCache, buf []byte) {
	for offset := 0; offset+metadataSize <= len(buf); {
		meta := readMetadata(buf[offset:])
		if meta.EventLen < metadataSize || offset+int(meta.EventLen) > len(buf) {
			c.invalidate(fsID{}, true)
			return
		}
		info := buf[offset+int(meta.MetadataLen) : offset+int(meta.EventLen)]
		offset += int(meta.EventLen)
		switch {
		case meta.Mask&unix.FAN_Q_OVERFLOW != 0:
			c.invalidate(fsID{}, true)
		case meta.Mask&unix.FAN_ONDIR == 0:
			// A file moved; no directory's path changed.
		case len(info) >= 12:
			c.invalidate(recordFSID(info), false)
		default:
			c.invalidate(fsID{}, true)
		}
	}
}

// isRemovedDir reports whether fd is a directory that has been removed: its
// handle can still resolve while something holds its dentry, and readlink
// then names it with a " (deleted)" mark that is not part of any path.
func isRemovedDir(fd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Nlink == 0
}
