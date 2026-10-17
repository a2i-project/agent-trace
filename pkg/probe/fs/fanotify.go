// Package fs provides a filesystem observer using Linux fanotify.
//
// The observer watches all file operations on the filesystem containing a
// given path, or on every real filesystem mounted on the host, using
// FAN_MARK_FILESYSTEM to capture events across bind mounts. It emits
// models.GroundTruthEvent values on a channel.
//
// Requires CAP_SYS_ADMIN in the initial user namespace.
package fs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// fanotify constants, from golang.org/x/sys/unix.
const (
	// reportFlags asks for file handles instead of file descriptors:
	// FAN_REPORT_FID, a record with the handle of the object itself on events
	// on a file's content, and FAN_REPORT_DFID_NAME (FAN_REPORT_DIR_FID |
	// FAN_REPORT_NAME, 0xc00), a record with the handle of the directory and
	// the entry's name on every event (P-25). Before P-25 the probe asked for
	// 0x2400, FAN_REPORT_DIR_FID | FAN_REPORT_FD_ERROR: no name, so a create,
	// delete or rename named only its directory.
	reportFlags = unix.FAN_REPORT_FID | unix.FAN_REPORT_DFID_NAME

	// Info record types.
	fanEventInfoTypeFid      = unix.FAN_EVENT_INFO_TYPE_FID       // file handle for the object itself
	fanEventInfoTypeDfidName = unix.FAN_EVENT_INFO_TYPE_DFID_NAME // parent dir handle + null-terminated name
	fanEventInfoTypeDfid     = unix.FAN_EVENT_INFO_TYPE_DFID      // parent dir handle, no name

	// Size of struct fanotify_event_metadata (24 bytes on all architectures).
	metadataSize = 24
)

// fsID is the kernel's __kernel_fsid_t: the filesystem a handle belongs to.
// fanotify writes it into every info record, and open_by_handle_at needs a
// mount fd on that same filesystem, so a probe that marks several
// filesystems keeps one mount fd per id.
type fsID [2]int32

// handleResolver maps a kernel file handle (filesystem id, type and raw
// bytes) to a filesystem path. In production this calls open_by_handle_at on
// the mount fd of that filesystem and readlink; in tests it returns a
// predetermined path from a lookup table.
type handleResolver func(fsid fsID, handleType int32, handleData []byte) string

// eventMetadata mirrors struct fanotify_event_metadata.
type eventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	FD          int32
	PID         int32
}

// rawEvent is a parsed fanotify event with a resolved filesystem path.
type rawEvent struct {
	Mask      uint64
	PID       int32
	Path      string
	Ambiguous bool
	// FID handle data if available, to open the file directly via open_by_handle_at
	HandleType int32
	HandleData []byte
	// FSID is the filesystem the FID handle belongs to.
	FSID fsID
}

// --- Kernel interaction (requires CAP_SYS_ADMIN) --------------------------

// initFanotify creates a fanotify file descriptor configured for
// notification-only FID-mode events (no permission decisions), with the
// handle and name records of reportFlags.
func initFanotify() (int, error) {
	flags := uint(unix.FAN_CLASS_NOTIF | reportFlags | unix.FAN_CLOEXEC)
	fd, err := unix.FanotifyInit(flags, 0)
	if err != nil {
		return -1, fmt.Errorf("fanotify_init: %w", err)
	}
	return fd, nil
}

// markFilesystem adds a filesystem-wide mark for the given event mask.
// All mount points of the filesystem containing path are watched.
func markFilesystem(fanotifyFD int, path string, mask uint64) error {
	flags := uint(unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM)
	if err := unix.FanotifyMark(fanotifyFD, flags, mask, unix.AT_FDCWD, path); err != nil {
		return fmt.Errorf("fanotify_mark on %s: %w", path, err)
	}
	return nil
}

// openMountFD opens a read-only directory fd for path resolution via
// open_by_handle_at. The returned fd identifies the filesystem for handle
// lookups. We avoid O_PATH because some kernels/filesystems reject it
// as the mount_fd argument to open_by_handle_at.
func openMountFD(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, fmt.Errorf("open mount fd for %s: %w", path, err)
	}
	return fd, nil
}

// fsidOf returns the filesystem id of the filesystem holding path.
func fsidOf(path string) (fsID, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsID{}, err
	}
	return fsID{st.Fsid.Val[0], st.Fsid.Val[1]}, nil
}

// mountEntry is one line of /proc/self/mountinfo the probe may mark.
type mountEntry struct {
	Point  string
	FSType string
}

// pseudoFSTypes are the filesystem types that hold no files an agent acts on,
// or that fanotify cannot mark. They are left out of an all-filesystems mark.
// squashfs and iso9660 are read-only images (snaps, media); fuse mounts are
// left out because marking one can fail or hang on an unresponsive daemon.
var pseudoFSTypes = map[string]bool{
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "devpts": true,
	"mqueue": true, "debugfs": true, "tracefs": true, "securityfs": true,
	"pstore": true, "bpf": true, "configfs": true, "fusectl": true,
	"hugetlbfs": true, "binfmt_misc": true, "autofs": true, "efivarfs": true,
	"devtmpfs": true, "rpc_pipefs": true, "nsfs": true, "squashfs": true,
	"iso9660": true, "ramfs": true, "selinuxfs": true, "apparmorfs": true,
}

// parseMountInfo reads /proc/self/mountinfo and returns the mount points of
// the filesystems worth marking, in file order. The format is
// "id parent major:minor root point options [optional...] - fstype source
// superopts"; the mount point has spaces and other characters octal-escaped.
func parseMountInfo(r io.Reader) []mountEntry {
	var out []mountEntry
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep < 5 || sep+1 >= len(fields) {
			continue
		}
		fstype := fields[sep+1]
		if pseudoFSTypes[fstype] || strings.HasPrefix(fstype, "fuse") {
			continue
		}
		out = append(out, mountEntry{Point: unescapeMountPoint(fields[4]), FSType: fstype})
	}
	return out
}

func unescapeMountPoint(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v byte
			ok := true
			for _, c := range s[i+1 : i+4] {
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + byte(c-'0')
			}
			if ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// markedSet is the result of marking filesystems: one mount fd per filesystem
// id, the mount points that were marked, and those that could not be.
type markedSet struct {
	fds      map[fsID]int
	marked   []string
	unmarked map[string]string
}

// markAll marks every real filesystem on the host once, by filesystem id,
// starting with the one holding path so it is always included. A filesystem
// that cannot be marked or opened is recorded in unmarked and skipped: the
// capture then says where it was not looking instead of failing outright.
func markAll(fanotifyFD int, path string, mask uint64) (markedSet, error) {
	set := markedSet{fds: map[fsID]int{}, unmarked: map[string]string{}}
	mark := func(point string) error {
		id, err := fsidOf(point)
		if err != nil {
			return err
		}
		if _, done := set.fds[id]; done {
			return nil
		}
		if err := markFilesystem(fanotifyFD, point, mask); err != nil {
			return err
		}
		fd, err := openMountFD(point)
		if err != nil {
			return err
		}
		set.fds[id] = fd
		set.marked = append(set.marked, point)
		return nil
	}
	// Mount points first, so the filesystem holding path is named by its
	// mount point and not by path; then path itself, in case its filesystem
	// is not listed, which must succeed.
	if f, err := os.Open("/proc/self/mountinfo"); err == nil {
		for _, m := range parseMountInfo(f) {
			if err := mark(m.Point); err != nil {
				set.unmarked[m.Point] = err.Error()
			}
		}
		_ = f.Close()
	}
	if err := mark(path); err != nil {
		return set, err
	}
	sort.Strings(set.marked)
	return set, nil
}

func (m markedSet) close() {
	for _, fd := range m.fds {
		_ = unix.Close(fd)
	}
}

// newKernelResolver returns a handleResolver that resolves file handles via
// open_by_handle_at on the mount fd of the handle's filesystem. A removed
// directory resolves to no path even when its handle still opens, since
// readlink would name it with a " (deleted)" mark inside the path; the
// directory cache names it instead (P-28).
func newKernelResolver(mounts map[fsID]int) handleResolver {
	return func(fsid fsID, handleType int32, handleData []byte) string {
		mountFD, ok := mounts[fsid]
		if !ok {
			return ""
		}
		fh := unix.NewFileHandle(handleType, handleData)
		fd, err := unix.OpenByHandleAt(mountFD, fh, unix.O_RDONLY|unix.O_PATH)
		if err != nil {
			return ""
		}
		defer func() { _ = unix.Close(fd) }()
		if isRemovedDir(fd) {
			return ""
		}

		path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			return ""
		}
		return path
	}
}

// --- Pure parsing (no kernel interaction) ----------------------------------

// parseEvents extracts rawEvents from a buffer read from the fanotify fd.
// dirs, which may be nil, names the directories that no longer resolve; it
// first applies the directory renames queued since the last batch, so the
// paths this batch caches are not dropped by a rename that preceded them.
func parseEvents(buf []byte, n int, resolve handleResolver, dirs *dirCache) []rawEvent {
	dirs.sync()
	var events []rawEvent
	offset := 0
	for offset+metadataSize <= n {
		meta := readMetadata(buf[offset:])
		if meta.EventLen < metadataSize || offset+int(meta.EventLen) > n {
			break
		}

		if meta.Mask&unix.FAN_Q_OVERFLOW != 0 {

			infoStart := offset + int(meta.MetadataLen)
			infoEnd := offset + int(meta.EventLen)
			path, ambiguous := resolveEventPath(buf[infoStart:infoEnd], resolve, dirs)
			fsid, handleType, handleData := extractFID(buf[infoStart:infoEnd])

			events = append(events, rawEvent{
				Mask:       meta.Mask,
				PID:        meta.PID,
				Path:       path,
				Ambiguous:  ambiguous,
				HandleType: handleType,
				HandleData: handleData,
				FSID:       fsid,
			})
			offset += int(meta.EventLen)
			continue
		}

		// We do NOT close the fd here. We pass it to rawEvent so the observer
		// can use it to synchronously hash the file contents, preventing TOCTOU.
		// The observer is responsible for closing it.

		// Info records follow the metadata header.
		infoStart := offset + int(meta.MetadataLen)
		infoEnd := offset + int(meta.EventLen)
		path, ambiguous := resolveEventPath(buf[infoStart:infoEnd], resolve, dirs)
		fsid, handleType, handleData := extractFID(buf[infoStart:infoEnd])

		events = append(events, rawEvent{
			Mask:       meta.Mask,
			PID:        meta.PID,
			Path:       path,
			Ambiguous:  ambiguous,
			HandleType: handleType,
			HandleData: handleData,
			FSID:       fsid,
		})

		offset += int(meta.EventLen)
	}
	return events
}

func readMetadata(buf []byte) eventMetadata {
	return eventMetadata{
		EventLen:    binary.LittleEndian.Uint32(buf[0:4]),
		Vers:        buf[4],
		Reserved:    buf[5],
		MetadataLen: binary.LittleEndian.Uint16(buf[6:8]),
		Mask:        binary.LittleEndian.Uint64(buf[8:16]),
		FD:          int32(binary.LittleEndian.Uint32(buf[16:20])),
		PID:         int32(binary.LittleEndian.Uint32(buf[20:24])),
	}
}

// resolveEventPath iterates all info records and resolves the best available
// filesystem path. Preference order:
//  1. DFID_NAME (type 2): parent directory handle + entry name (full path)
//  2. FID (type 1): file handle resolved directly via open_by_handle_at
//  3. DFID (type 3): parent directory handle only (no filename)
//
// The kernel takes the name in a DFID_NAME record when the event happens, so
// case 1 names the entry as it was then; a FID record resolves to wherever
// the file is when the record is read. With reportFlags every record carries
// a DFID_NAME record (P-25), and on kernel 6.17 none carried a DFID-only one;
// a directory that no longer resolves is named by the directory cache when it
// can be (P-28), and FID is the fallback after that. A capture made
// with the flags before P-25 had no names, so its create, delete and rename
// records resolved through case 3.
//
// The second return value, ambiguous, is true only when the DFID-only
// fallback (case 3) is what actually produced the returned path, leaving only
// a directory, or when nothing resolved. It is false whenever DFID_NAME or
// FID resolved a specific path. Callers use this to restrict the "directory
// covers any file inside it" matching leniency to genuinely coarse-resolution
// events, not to every ground-truth event whose target happens to be a
// directory.
func resolveEventPath(infoData []byte, resolve handleResolver, dirs *dirCache) (path string, ambiguous bool) {
	var fidPath, dfidNamePath, dfidPath string

	offset := 0
	for offset+4 <= len(infoData) {
		infoType := infoData[offset]
		infoLen := int(binary.LittleEndian.Uint16(infoData[offset+2 : offset+4]))
		if infoLen < 4 || offset+infoLen > len(infoData) {
			break
		}

		record := infoData[offset : offset+infoLen]
		switch infoType {
		case fanEventInfoTypeDfidName:
			dfidNamePath = parseDfidName(record, resolve, dirs)
		case fanEventInfoTypeFid:
			fidPath = parseHandleToPath(record, resolve)
		case fanEventInfoTypeDfid:
			dfidPath = parseHandleToPath(record, resolve)
		}

		offset += infoLen
	}

	if dfidNamePath != "" {
		return dfidNamePath, false
	}
	if fidPath != "" {
		return fidPath, false
	}
	return dfidPath, true
}

// parseDfidName extracts a directory file handle and entry name from a
// FAN_EVENT_INFO_TYPE_DFID_NAME record and resolves them to a full path.
//
// Record layout:
//
//	header   (4 bytes): info_type, pad, len
//	fsid     (8 bytes): filesystem ID
//	file_handle:
//	  handle_bytes (4 bytes)
//	  handle_type  (4 bytes)
//	  f_handle     (handle_bytes bytes)
//	name     (remaining): null-terminated entry name
//
// A directory that resolves is recorded in dirs; one that does not, because
// it was removed before the record was read, is looked up there (P-28). A
// cached path is exact: the directory's path when it last resolved, with no
// directory renamed on its filesystem since.
func parseDfidName(record []byte, resolve handleResolver, dirs *dirCache) string {
	// Minimum: header(4) + fsid(8) + handle_bytes(4) + handle_type(4) = 20
	if len(record) < 20 {
		return ""
	}

	handleBytes := int(binary.LittleEndian.Uint32(record[12:16]))
	handleType := int32(binary.LittleEndian.Uint32(record[16:20]))

	handleDataEnd := 20 + handleBytes
	if handleDataEnd > len(record) {
		return ""
	}

	handleData := make([]byte, handleBytes)
	copy(handleData, record[20:handleDataEnd])

	// Entry name follows the handle data, null-terminated with possible padding.
	var name string
	if handleDataEnd < len(record) {
		nameBytes := record[handleDataEnd:]
		if idx := bytes.IndexByte(nameBytes, 0); idx > 0 {
			name = string(nameBytes[:idx])
		} else if len(nameBytes) > 0 && nameBytes[0] != 0 {
			name = string(nameBytes)
		}
	}

	fsid := recordFSID(record)
	dirPath := resolve(fsid, handleType, handleData)
	if dirPath != "" {
		dirs.fill(fsid, handleType, handleData, dirPath)
	} else if cached, ok := dirs.lookup(fsid, handleType, handleData); ok {
		dirPath = cached
	}

	// An unresolved directory yields no path, not the bare entry name: a
	// relative name would read as a path and escape the unresolved count.
	// resolveEventPath then falls back to the other records.
	if dirPath == "" {
		return ""
	}
	if name == "" {
		return dirPath
	}
	return filepath.Join(dirPath, name)
}

// parseHandleToPath extracts a file handle from an info record (FID or DFID)
// and resolves it to a path via the provided resolver.
//
// Record layout (same for type 1 and type 3):
//
//	header   (4 bytes): info_type, pad, len
//	fsid     (8 bytes): filesystem ID
//	file_handle:
//	  handle_bytes (4 bytes)
//	  handle_type  (4 bytes)
//	  f_handle     (handle_bytes bytes)
func parseHandleToPath(record []byte, resolve handleResolver) string {
	if len(record) < 20 {
		return ""
	}

	handleBytes := int(binary.LittleEndian.Uint32(record[12:16]))
	handleType := int32(binary.LittleEndian.Uint32(record[16:20]))

	handleDataEnd := 20 + handleBytes
	if handleDataEnd > len(record) {
		return ""
	}

	handleData := make([]byte, handleBytes)
	copy(handleData, record[20:handleDataEnd])

	return resolve(recordFSID(record), handleType, handleData)
}

// recordFSID reads the filesystem id at bytes 4 to 12 of an info record.
func recordFSID(record []byte) fsID {
	return fsID{int32(binary.LittleEndian.Uint32(record[4:8])), int32(binary.LittleEndian.Uint32(record[8:12]))}
}

// extractFID extracts the FID (type 1) handle and its filesystem id from the
// info records.
func extractFID(infoData []byte) (fsID, int32, []byte) {
	offset := 0
	for offset+4 <= len(infoData) {
		infoType := infoData[offset]
		infoLen := int(binary.LittleEndian.Uint16(infoData[offset+2 : offset+4]))
		if infoLen < 4 || offset+infoLen > len(infoData) {
			break
		}

		if infoType == fanEventInfoTypeFid {
			record := infoData[offset : offset+infoLen]
			if len(record) >= 20 {
				handleBytes := int(binary.LittleEndian.Uint32(record[12:16]))
				handleType := int32(binary.LittleEndian.Uint32(record[16:20]))
				if 20+handleBytes <= len(record) {
					handleData := make([]byte, handleBytes)
					copy(handleData, record[20:20+handleBytes])
					return recordFSID(record), handleType, handleData
				}
			}
		}
		offset += infoLen
	}
	return fsID{}, 0, nil
}
