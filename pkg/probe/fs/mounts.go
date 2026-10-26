package fs

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// mountLine is one line of /proc/self/mountinfo: "id parent major:minor root
// point options [optional...] - fstype source superopts". Root and Point are
// unescaped.
type mountLine struct {
	ID, Parent  int
	Device      string
	Root, Point string
	FSType      string
}

// parseMountTable reads every well-formed line of a mountinfo file, in file
// order. A line it cannot read is skipped, so the table may be short; the
// matcher that uses it only ever refuses on a path it cannot trace (P-33).
func parseMountTable(r io.Reader) []mountLine {
	var out []mountLine
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || sep+1 >= len(fields) {
			continue
		}
		id, err1 := strconv.Atoi(fields[0])
		parent, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil || !strings.Contains(fields[2], ":") {
			continue
		}
		out = append(out, mountLine{
			ID: id, Parent: parent, Device: fields[2],
			Root: unescapeMountPoint(fields[3]), Point: unescapeMountPoint(fields[4]),
			FSType: fields[sep+1],
		})
	}
	return out
}

// markable returns the mounts of the filesystems worth marking, in table
// order. A pseudo filesystem holds no files an agent acts on, or fanotify
// cannot mark it (pseudoFSTypes, and fuse).
func markable(lines []mountLine) []mountEntry {
	var out []mountEntry
	for _, l := range lines {
		if pseudoFSTypes[l.FSType] || strings.HasPrefix(l.FSType, "fuse") {
			continue
		}
		out = append(out, mountEntry{Point: l.Point, FSType: l.FSType, Root: l.Root})
	}
	return out
}

// markOrder orders the mounts markAll tries: every mount of a whole
// filesystem (root "/") before any bind of a subdirectory, each group in
// table order. The first mount marked for a filesystem is the one the probe
// names its files through (P-30), and through a whole-filesystem mount every
// file of it has a name; through a bind of a subdirectory a file outside it
// has none (P-33).
func markOrder(entries []mountEntry) []mountEntry {
	out := append([]mountEntry(nil), entries...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Root == "/" && out[j].Root != "/" })
	return out
}

// buildMountTable groups the table by filesystem, in order of first
// appearance, and marks the mounts whose id is in names: the mounts the probe
// names files through.
func buildMountTable(lines []mountLine, names map[int]bool) []models.FSMounts {
	var out []models.FSMounts
	at := map[string]int{}
	for _, l := range lines {
		i, ok := at[l.Device]
		if !ok {
			i = len(out)
			at[l.Device] = i
			out = append(out, models.FSMounts{Device: l.Device, FSType: l.FSType})
		}
		out[i].Mounts = append(out[i].Mounts, models.Mount{ID: l.ID, Parent: l.Parent, Root: l.Root, Point: l.Point, Names: names[l.ID]})
	}
	return out
}

// readMountTable opens /proc/self/mountinfo and reads it. The returned fd stays
// open: polled at Stop for POLLPRI, it reports whether the namespace's mount
// table changed since it was opened (mountTableChanged). On error the fd is -1
// and the table nil.
func readMountTable() (fd int, lines []mountLine) {
	fd, err := unix.Open("/proc/self/mountinfo", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil
	}
	var b strings.Builder
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			_ = unix.Close(fd)
			return -1, nil
		}
		if n == 0 {
			break
		}
		b.Write(buf[:n])
	}
	return fd, parseMountTable(strings.NewReader(b.String()))
}

// mountTableChanged polls the mountinfo fd readMountTable opened: the kernel
// raises POLLPRI (with POLLERR) on it once any mount in the namespace was
// added, removed, moved or remounted since it was opened or last polled. Nil
// means the poll failed, so nothing is known.
func mountTableChanged(fd int) *bool {
	if fd < 0 {
		return nil
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLPRI}}
	for {
		_, err := unix.Poll(pfd, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil
		}
		changed := pfd[0].Revents&(unix.POLLPRI|unix.POLLERR) != 0
		return &changed
	}
}

// mountIDOf returns the id of the mount fd lies on, as mountinfo numbers it.
func mountIDOf(fd int) (int, bool) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st); err != nil || st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, false
	}
	return int(st.Mnt_id), true
}

// isProcessRoot reports whether fd is the process's root directory. readlink
// names an object outside the mount it was opened through ("escaped", as a
// file outside a bind of a subdirectory is when its handle is opened through
// the bind) as "/" (fs/d_path.c, prepend_path; Verified on kernel 6.17), the
// name the root directory itself has, so only the object's identity tells the
// two apart.
func isProcessRoot(fd int) bool {
	var obj, root unix.Stat_t
	if unix.Fstat(fd, &obj) != nil || unix.Stat("/", &root) != nil {
		return false
	}
	return obj.Dev == root.Dev && obj.Ino == root.Ino
}
