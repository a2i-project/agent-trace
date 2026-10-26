package fs

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func TestParseMountTable(t *testing.T) {
	const sample = `28 1 259:7 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p7 rw
40 28 0:35 / /tmp rw,nosuid - tmpfs tmpfs rw
41 28 0:35 /src /mnt/my\040alias rw shared:5 master:2 - tmpfs tmpfs rw
42 28 0:36 /gone//deleted /mnt/gone rw - tmpfs tmpfs rw
43 28 0:5 / /proc rw - proc proc rw
x 28 0:5 / /bad rw - proc proc rw
44 28 05 / /bad rw - proc proc rw
45 28 0:5 / /short - proc
garbage line
`
	got := parseMountTable(strings.NewReader(sample))
	want := []mountLine{
		{ID: 28, Parent: 1, Device: "259:7", Root: "/", Point: "/", FSType: "ext4"},
		{ID: 40, Parent: 28, Device: "0:35", Root: "/", Point: "/tmp", FSType: "tmpfs"},
		{ID: 41, Parent: 28, Device: "0:35", Root: "/src", Point: "/mnt/my alias", FSType: "tmpfs"},
		{ID: 42, Parent: 28, Device: "0:36", Root: "/gone//deleted", Point: "/mnt/gone", FSType: "tmpfs"},
		{ID: 43, Parent: 28, Device: "0:5", Root: "/", Point: "/proc", FSType: "proc"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// The probe names a filesystem's files through the first mount it marks for
// it, so a whole-filesystem mount must come before any bind of a
// subdirectory, whatever the table order (P-33).
func TestMarkOrder_WholeFilesystemMountsFirst(t *testing.T) {
	in := []mountEntry{
		{Point: "/ws", FSType: "tmpfs", Root: "/src"},
		{Point: "/", FSType: "ext4", Root: "/"},
		{Point: "/home", FSType: "btrfs", Root: "/@home"},
		{Point: "/fs", FSType: "tmpfs", Root: "/"},
	}
	got := markOrder(in)
	var points []string
	for _, e := range got {
		points = append(points, e.Point)
	}
	if want := []string{"/", "/fs", "/ws", "/home"}; !reflect.DeepEqual(points, want) {
		t.Errorf("order %v, want %v", points, want)
	}
	if in[0].Point != "/ws" {
		t.Error("markOrder reordered its input")
	}
}

func TestBuildMountTable_GroupsByFilesystem(t *testing.T) {
	lines := []mountLine{
		{ID: 28, Parent: 1, Device: "259:7", Root: "/", Point: "/", FSType: "ext4"},
		{ID: 40, Parent: 28, Device: "0:35", Root: "/", Point: "/fs", FSType: "tmpfs"},
		{ID: 41, Parent: 28, Device: "259:7", Root: "/home", Point: "/h", FSType: "ext4"},
		{ID: 42, Parent: 28, Device: "0:35", Root: "/src", Point: "/alias", FSType: "tmpfs"},
	}
	got := buildMountTable(lines, map[int]bool{28: true, 40: true})
	want := []models.FSMounts{
		{Device: "259:7", FSType: "ext4", Mounts: []models.Mount{
			{ID: 28, Parent: 1, Root: "/", Point: "/", Names: true},
			{ID: 41, Parent: 28, Root: "/home", Point: "/h"},
		}},
		{Device: "0:35", FSType: "tmpfs", Mounts: []models.Mount{
			{ID: 40, Parent: 28, Root: "/", Point: "/fs", Names: true},
			{ID: 42, Parent: 28, Root: "/src", Point: "/alias"},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// The table read from this process's own mountinfo holds the mount of "/",
// and statx names the same mount for an fd on "/". Unprivileged.
func TestReadMountTable_FindsTheRootMount(t *testing.T) {
	fd, lines := readMountTable()
	if fd < 0 {
		t.Skip("no /proc/self/mountinfo")
	}
	defer func() { _ = unix.Close(fd) }()
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rootFD) }()
	id, ok := mountIDOf(rootFD)
	if !ok {
		t.Skip("statx does not report a mount id")
	}
	found := false
	for _, l := range lines {
		if l.ID == id {
			found = true
			if l.Point != "/" {
				t.Errorf("the mount of / is listed at %q", l.Point)
			}
		}
	}
	if !found {
		t.Errorf("mount id %d of / is not in the table of %d mounts", id, len(lines))
	}
	if c := mountTableChanged(fd); c == nil {
		t.Error("polling the mountinfo fd failed")
	}
}

func TestMountTableChanged_NoFDIsUnknown(t *testing.T) {
	if mountTableChanged(-1) != nil {
		t.Error("no fd must read as not measured")
	}
}

func TestIsProcessRoot(t *testing.T) {
	for _, tt := range []struct {
		path string
		want bool
	}{{"/", true}, {os.TempDir(), false}} {
		fd, err := unix.Open(tt.path, unix.O_PATH, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := isProcessRoot(fd); got != tt.want {
			t.Errorf("isProcessRoot(%s) = %v, want %v", tt.path, got, tt.want)
		}
		_ = unix.Close(fd)
	}
}
