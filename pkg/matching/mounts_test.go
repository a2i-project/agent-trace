package matching

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// row is one mount of a test table: id, parent, device, root, point, and
// whether the probe names its filesystem through it.
type row struct {
	id, parent  int
	dev, root   string
	point       string
	probeNames  bool
	fstypeLabel string
}

func scopeOf(changed *bool, rows ...row) *models.FSScope {
	s := &models.FSScope{MountTableChanged: changed}
	at := map[string]int{}
	for _, r := range rows {
		i, ok := at[r.dev]
		if !ok {
			i = len(s.Filesystems)
			at[r.dev] = i
			s.Filesystems = append(s.Filesystems, models.FSMounts{Device: r.dev, FSType: r.fstypeLabel})
		}
		s.Filesystems[i].Mounts = append(s.Filesystems[i].Mounts, models.Mount{ID: r.id, Parent: r.parent, Root: r.root, Point: r.point, Names: r.probeNames})
	}
	return s
}

func boolp(b bool) *bool { return &b }

// host is a mount table with the shapes the alias rule must handle: a tmpfs
// (0:40) mounted whole at /fs, where the probe names it, bound by a
// subdirectory at /alias and /deepalias and mounted whole a second time at
// /ro; a non-recursive bind of the root filesystem at /rootbind; a second
// filesystem at /mnt/data; an overlay at /merged whose upper directory is on
// the root filesystem; two tmpfs instances at /t1 and /t2; and /proc, which
// the probe does not mark.
var host = []row{
	{20, 1, "8:1", "/", "/", true, "ext4"},
	{21, 20, "0:40", "/", "/fs", true, "tmpfs"},
	{22, 20, "0:40", "/src", "/alias", false, "tmpfs"},
	{23, 20, "8:1", "/", "/rootbind", false, "ext4"},
	{24, 20, "0:41", "/", "/mnt/data", true, "ext4"},
	{25, 20, "0:50", "/", "/merged", true, "overlay"},
	{26, 20, "0:40", "/", "/ro", false, "tmpfs"},
	{27, 20, "0:42", "/", "/t1", true, "tmpfs"},
	{28, 20, "0:43", "/", "/t2", true, "tmpfs"},
	{29, 20, "0:5", "/", "/proc", false, "proc"},
	{30, 20, "0:40", "/src/deep", "/deepalias", false, "tmpfs"},
}

func with(base []row, extra ...row) []row {
	return append(append([]row(nil), base...), extra...)
}

func TestMounts_AliasRule(t *testing.T) {
	stable := boolp(false)
	tests := []struct {
		name      string
		scope     *models.FSScope
		action    models.ActionType
		claim     string
		event     string
		ambiguous bool
		want      bool
	}{
		// What the rule is for.
		{"a bind of a subdirectory names the same file", scopeOf(stable, host...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, true},
		{"a bind of a deeper subdirectory names the same file", scopeOf(stable, host...), models.FileWrite, "/deepalias/x/f.txt", "/fs/src/deep/x/f.txt", false, true},
		{"the filesystem mounted twice with other options names the same file", scopeOf(stable, host...), models.FileWrite, "/ro/src/f.txt", "/fs/src/f.txt", false, true},
		{"the probe's own name still matches", scopeOf(stable, host...), models.FileWrite, "/fs/src/f.txt", "/fs/src/f.txt", false, true},
		{"the alias's mount point is its root directory", scopeOf(stable, host...), models.FileOpen, "/alias", "/fs/src", false, true},
		{"a directory-level event covers a file named through the alias", scopeOf(stable, host...), models.FileWrite, "/alias/f.txt", "/fs/src", true, true},
		{"an exact directory event does not cover a file named through the alias", scopeOf(stable, host...), models.FileWrite, "/alias/f.txt", "/fs/src", false, false},

		// A different file that merely shares a suffix.
		{"same name in another directory of the filesystem", scopeOf(stable, host...), models.FileWrite, "/alias/f.txt", "/fs/other/f.txt", false, false},
		{"same path within another tmpfs instance", scopeOf(stable, host...), models.FileWrite, "/t2/f.txt", "/t1/f.txt", false, false},
		{"same suffix under another filesystem's mount", scopeOf(stable, host...), models.FileWrite, "/alias/f.txt", "/mnt/data/src/f.txt", false, false},
		{"a non-recursive bind of / reaches the directory under /fs, not the tmpfs", scopeOf(stable, host...), models.FileWrite, "/rootbind/fs/src/f.txt", "/fs/src/f.txt", false, false},
		{"a non-recursive bind of / reaches no file under /proc's mount", scopeOf(stable, host...), models.FileRead, "/rootbind/proc/1/status", "/proc/1/status", false, false},

		// Symbolic links and "..".
		{"a symbolic link in the claim is read as a directory", scopeOf(stable, host...), models.FileWrite, "/alias/link/f.txt", "/fs/src/real/f.txt", false, false},
		{"a claim with .. is not traced through a mount", scopeOf(stable, host...), models.FileWrite, "/alias/link/../f.txt", "/fs/src/f.txt", false, false},

		// Overlay: its own filesystem, never its upper directory's.
		{"an overlay file is not its upper directory's file", scopeOf(stable, host...), models.FileWrite, "/merged/f.txt", "/var/lib/upper/f.txt", false, false},
		{"an upper directory's file is not the overlay's file", scopeOf(stable, host...), models.FileWrite, "/var/lib/upper/f.txt", "/merged/f.txt", false, false},

		// A stale or unknown table.
		{"the table changed during the capture", scopeOf(boolp(true), host...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},
		{"whether the table changed is not known", scopeOf(nil, host...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},
		{"a mount added after the start is not in a table that changed", scopeOf(boolp(true), host...), models.FileWrite, "/fs/src/new/f.txt", "/mnt/data/f.txt", false, false},
		{"no table: the capture predates it", &models.FSScope{Rule: models.FSScopeTreeOrWorkspace}, models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},
		{"no record at all", nil, models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},

		// Paths the table cannot trace.
		{"a relative claim", scopeOf(stable, host...), models.FileWrite, "alias/f.txt", "/fs/src/f.txt", false, false},
		{"a filesystem the probe did not mark", scopeOf(stable, with(host, row{31, 20, "0:5", "/", "/proc2", false, "proc"})...), models.FileRead, "/proc2/1/status", "/proc/1/status", false, false},
		{"a table with no root mount", scopeOf(stable, host[1:]...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},
		{"a table with duplicate mount ids", scopeOf(stable, with(host, row{22, 20, "0:40", "/src", "/alias2", false, "tmpfs"})...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},

		// A bind of a subdirectory as the probe's mount (P-30's case).
		{"a file outside the probe's bind has no probe name", scopeOf(stable,
			row{20, 1, "8:1", "/", "/", true, "ext4"},
			row{40, 20, "0:40", "/src", "/ws", true, "tmpfs"},
			row{41, 20, "0:40", "/", "/full", false, "tmpfs"}), models.FileWrite, "/full/other/f.txt", "/f.txt", false, false},
		{"nor is it named relative to the filesystem's root", scopeOf(stable,
			row{20, 1, "8:1", "/", "/", true, "ext4"},
			row{40, 20, "0:40", "/src", "/ws", true, "tmpfs"},
			row{41, 20, "0:40", "/", "/full", false, "tmpfs"}), models.FileWrite, "/full/other/f.txt", "/other/f.txt", false, false},
		{"a file inside the probe's bind is named through it", scopeOf(stable,
			row{20, 1, "8:1", "/", "/", true, "ext4"},
			row{40, 20, "0:40", "/src", "/ws", true, "tmpfs"},
			row{41, 20, "0:40", "/", "/full", false, "tmpfs"}), models.FileWrite, "/full/src/f.txt", "/ws/f.txt", false, true},

		// Covered names: the same string would name another file.
		{"the probe's mount is covered by a later mount", scopeOf(stable, with(host, row{32, 21, "0:44", "/", "/fs", true, "tmpfs"})...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},
		{"the probe's name passes under another mount", scopeOf(stable, with(host, row{33, 21, "0:45", "/", "/fs/src", true, "tmpfs"})...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},
		{"two mounts on one point: which is on top is unknown", scopeOf(stable, with(host, row{34, 20, "0:46", "/", "/fs", true, "tmpfs"})...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},
		{"a mount stacked on the alias wins the walk", scopeOf(stable, with(host, row{35, 22, "0:41", "/", "/alias", false, "ext4"})...), models.FileWrite, "/alias/f.txt", "/mnt/data/f.txt", false, true},
		{"and its files are not the covered alias's", scopeOf(stable, with(host, row{35, 22, "0:41", "/", "/alias", false, "ext4"})...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},

		// Deleted mounts and ambiguous probe mounts.
		{"a bind whose source was deleted", scopeOf(stable, with(host, row{36, 20, "0:40", "/gone//deleted", "/gonealias", false, "tmpfs"})...), models.FileWrite, "/gonealias/f.txt", "/fs/gone/f.txt", false, false},
		{"a bind whose source was deleted is not read as a live directory", scopeOf(stable, with(host, row{36, 20, "0:40", "/gone//deleted", "/gonealias", false, "tmpfs"})...), models.FileWrite, "/gonealias/f.txt", "/fs/gone/deleted/f.txt", false, false},
		{"a filesystem the probe names through two mounts", scopeOf(stable, with(host, row{37, 20, "0:40", "/", "/fs2", true, "tmpfs"})...), models.FileWrite, "/alias/f.txt", "/fs/src/f.txt", false, false},
		{"nor through the other of the two", scopeOf(stable, with(host, row{37, 20, "0:40", "/", "/fs2", true, "tmpfs"})...), models.FileWrite, "/alias/f.txt", "/fs2/src/f.txt", false, false},

		// Other lanes are not traced.
		{"a command is compared as a string", scopeOf(stable, host...), models.ProcessExec, "/alias/tool", "/fs/src/tool", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMounts(tt.scope)
			c := models.TrajectoryEntry{ActionType: tt.action, Target: tt.claim}
			g := models.GroundTruthEvent{ActionType: tt.action, Target: tt.event, PathIsAmbiguous: tt.ambiguous}
			if got := m.TargetsMatch(c, g); got != tt.want {
				n, ok := m.Canonical(tt.claim)
				t.Errorf("TargetsMatch(%q, %q) = %v, want %v (canonical %q, %v)", tt.claim, tt.event, got, tt.want, n, ok)
			}
		})
	}
}

// Without a table, the method is TargetsMatch: a capture without the record
// matches exactly as before.
func TestMounts_NilIsTargetsMatch(t *testing.T) {
	var m *Mounts
	pairs := []struct{ claim, event string }{
		{"/ws/a.txt", "/ws/a.txt"},
		{"/ws/./a.txt", "/ws/a.txt"},
		{"/ws/sub/../a.txt", "/ws/a.txt"},
		{"/alias/a.txt", "/fs/src/a.txt"},
	}
	for _, p := range pairs {
		c := models.TrajectoryEntry{ActionType: models.FileWrite, Target: p.claim}
		g := models.GroundTruthEvent{ActionType: models.FileWrite, Target: p.event}
		if m.TargetsMatch(c, g) != TargetsMatch(c, g) {
			t.Errorf("%q vs %q: nil Mounts differs from TargetsMatch", p.claim, p.event)
		}
	}
}

func TestMounts_Canonical(t *testing.T) {
	m := NewMounts(scopeOf(boolp(false), host...))
	if m == nil {
		t.Fatal("NewMounts returned nil for a well-formed, stable table")
	}
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/alias/f.txt", "/fs/src/f.txt", true},
		{"/alias//f.txt", "/fs/src/f.txt", true},
		{"/alias/./f.txt", "/fs/src/f.txt", true},
		{"/ro", "/fs", true},
		{"/home/u/f.txt", "/home/u/f.txt", true},
		{"/", "/", true},
		{"/merged/f.txt", "/merged/f.txt", true},
		{"/alias/../f.txt", "", false},
		{"/proc/1/status", "", false},
		{"/rootbind/fs/x", "", false},
		{"/rootbind/home/u/f.txt", "/home/u/f.txt", true},
	}
	for _, tt := range tests {
		got, ok := m.Canonical(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Canonical(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
