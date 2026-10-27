package proc

import (
	"reflect"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// names packs path names leaf first, each NUL-terminated, as walk_path in
// proc.bpf.c writes them.
func names(leafFirst ...string) []byte {
	var b []byte
	for _, n := range leafFirst {
		b = append(b, n...)
		b = append(b, 0)
	}
	return b
}

// The kernel walks a path from the dentry up and writes the names leaf
// first; a whole walk is an absolute path, a cut one keeps the root-side
// names it has without a leading slash (P-36). Runs without root.
func TestWalkedPath(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		cut  bool
		want string
	}{
		{"the root itself", nil, false, "/"},
		{"one name", names("tmp"), false, "/tmp"},
		{"names come leaf first", names("ws", "carmine", "home"), false, "/home/carmine/ws"},
		{"a cut walk has no leading slash", names("c", "b"), true, "b/c"},
		{"a cut walk with no names is not recorded", nil, true, ""},
		{"a name cut by the record's end", append(names("leaf"), "par"...), true, "par/leaf"},
		{"a name with spaces", names("my dir", "tmp"), false, "/tmp/my dir"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := walkedPath(c.b, c.cut); got != c.want {
				t.Errorf("walkedPath = %q, want %q", got, c.want)
			}
		})
	}
}

// The kernel's filename differs from the entry read only when the caller's
// memory changed; an exec through a descriptor and an execveat path relative
// to a directory descriptor are named differently by design (P-36).
func TestFilenameChanged(t *testing.T) {
	for _, c := range []struct {
		name, entry, kernel string
		viaFD               bool
		want                bool
	}{
		{"the same path", "/bin/true", "/bin/true", false, false},
		{"a relative path", "./x", "./x", false, false},
		{"another path", "/bin/true", "/bin/false", false, true},
		{"an exec through a descriptor", "(fexecve)", "/dev/fd/3", true, false},
		{"relative to a directory descriptor", "bin/true", "/dev/fd/5/bin/true", false, false},
		{"a descriptor path that is not the entry's", "bin/true", "/dev/fd/5/bin/false", false, true},
		{"an absolute entry is never under /dev/fd", "/bin/true", "/dev/fd/5//bin/true", false, true},
		{"no entry filename", "", "/bin/true", false, false},
		{"no kernel filename", "/bin/true", "", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := filenameChanged(c.entry, c.viaFD, c.kernel); got != c.want {
				t.Errorf("filenameChanged(%q, %v, %q) = %v, want %v", c.entry, c.viaFD, c.kernel, got, c.want)
			}
		})
	}
}

// A success record's payload: the kernel's filename, the interpreter when
// args_size says there is one, and the program's path. A header-only record
// has no image.
func TestExecImage(t *testing.T) {
	payload := func(fn, interp string, path []byte) []byte {
		b := make([]byte, 2*filenameLen)
		copy(b, fn)
		copy(b[filenameLen:], interp)
		return append(b, path...)
	}
	for _, c := range []struct {
		name    string
		hdr     bpfEventHdr
		payload []byte
		want    *models.ExecImage
	}{
		{"a header-only record", bpfEventHdr{}, nil, nil},
		{
			"an ELF",
			bpfEventHdr{PathSize: 13},
			payload("/bin/true", "", names("true", "bin", "usr")),
			&models.ExecImage{Filename: "/bin/true", Program: "/usr/bin/true"},
		},
		{
			"a script",
			bpfEventHdr{ArgsSize: 8, PathSize: 13},
			payload("./run.sh", "/bin/sh", names("dash", "bin", "usr")),
			&models.ExecImage{Filename: "./run.sh", Interpreter: "/bin/sh", Program: "/usr/bin/dash"},
		},
		{
			"an exec through a descriptor",
			bpfEventHdr{PathSize: 13},
			payload("/dev/fd/3", "stale", names("true", "bin", "usr")),
			&models.ExecImage{Filename: "/dev/fd/3", Program: "/usr/bin/true"},
		},
		{
			"a cut program path",
			bpfEventHdr{PathSize: 9, PathTruncated: 1},
			payload("/x", "", names("true", "bin")),
			&models.ExecImage{Filename: "/x", Program: "bin/true", Truncated: true},
		},
		{
			"a cut filename",
			bpfEventHdr{ArgsTruncated: 1, PathSize: 2},
			payload("/a", "", names("a")),
			&models.ExecImage{Filename: "/a", Program: "/a", Truncated: true},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := execImage(&c.hdr, c.payload); !reflect.DeepEqual(got, c.want) {
				t.Errorf("execImage = %+v, want %+v", got, c.want)
			}
		})
	}
}

// holdStep is one record as readLoop hands it to the holder.
type holdStep struct {
	kind      string // "exec", "ok", "exit", "fork" or "flush"
	pid, tid  uint32
	target    string
	viaFD     bool
	kernelArg string // "ok": the kernel's filename
}

// released is what the holder let out: a target and whether it carries an
// image.
type released struct {
	target  string
	image   bool
	changed bool
}

// An exec event waits for its outcome: its success record attaches the
// kernel's record, and any record that shows the attempt over releases it
// without one, in the order held (P-36). Runs without root; the privileged
// tests in context_test.go check the kernel side.
func TestHolder_ReleasesEachExecWithItsOutcome(t *testing.T) {
	for _, c := range []struct {
		name  string
		steps []holdStep
		want  []released
	}{
		{
			name:  "a successful exec carries its image",
			steps: []holdStep{{kind: "exec", pid: 10, tid: 10, target: "/bin/true a"}, {kind: "ok", pid: 10, tid: 10, kernelArg: "/bin/true"}},
			want:  []released{{"/bin/true a", true, false}},
		},
		{
			name: "a PATH search: the failed attempts go out without an image, in order",
			steps: []holdStep{
				{kind: "exec", pid: 10, tid: 10, target: "/usr/local/bin/git status"},
				{kind: "exec", pid: 10, tid: 10, target: "/usr/bin/git status"},
				{kind: "ok", pid: 10, tid: 10, kernelArg: "/usr/bin/git"},
			},
			want: []released{{"/usr/local/bin/git status", false, false}, {"/usr/bin/git status", true, false}},
		},
		{
			name:  "an attempt that failed is released at its process's exit",
			steps: []holdStep{{kind: "exec", pid: 10, tid: 10, target: "/nonexistent a"}, {kind: "exit", pid: 10}},
			want:  []released{{"/nonexistent a", false, false}},
		},
		{
			name:  "an attempt still held at Stop is released",
			steps: []holdStep{{kind: "exec", pid: 10, tid: 10, target: "/nonexistent a"}, {kind: "flush"}},
			want:  []released{{"/nonexistent a", false, false}},
		},
		{
			name: "a new process with the pid ends the old process's attempt",
			steps: []holdStep{
				{kind: "exec", pid: 10, tid: 10, target: "/nonexistent a"},
				{kind: "fork", pid: 10},
			},
			want: []released{{"/nonexistent a", false, false}},
		},
		{
			name: "another process's records release nothing",
			steps: []holdStep{
				{kind: "exec", pid: 10, tid: 10, target: "/bin/true a"},
				{kind: "exit", pid: 11}, {kind: "fork", pid: 12},
				{kind: "ok", pid: 11, tid: 11},
				{kind: "ok", pid: 10, tid: 10, kernelArg: "/bin/true"},
			},
			want: []released{{"/bin/true a", true, false}},
		},
		{
			name: "a thread's exec ends the other threads' attempts first",
			steps: []holdStep{
				{kind: "exec", pid: 10, tid: 12, target: "/nonexistent u"},
				{kind: "exec", pid: 10, tid: 11, target: "/bin/true t"},
				{kind: "ok", pid: 10, tid: 11, kernelArg: "/bin/true"},
			},
			want: []released{{"/nonexistent u", false, false}, {"/bin/true t", true, false}},
		},
		{
			name: "the caller changed the filename between the read and the exec",
			steps: []holdStep{
				{kind: "exec", pid: 10, tid: 10, target: "/bin/true a"},
				{kind: "ok", pid: 10, tid: 10, kernelArg: "/bin/false"},
			},
			want: []released{{"/bin/true a", true, true}},
		},
		{
			name: "an exec through a descriptor is never a changed filename",
			steps: []holdStep{
				{kind: "exec", pid: 10, tid: 10, target: "(fexecve) a", viaFD: true},
				{kind: "ok", pid: 10, tid: 10, kernelArg: "/dev/fd/3"},
			},
			want: []released{{"(fexecve) a", true, false}},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := &holder{}
			var got []released
			out := func(es []models.GroundTruthEvent) {
				for _, e := range es {
					got = append(got, released{e.Target, e.Image != nil, e.Image != nil && e.Image.FilenameChanged})
				}
			}
			for _, s := range c.steps {
				switch s.kind {
				case "exec":
					filename, _, _ := strings.Cut(s.target, " ")
					out(h.hold(heldExec{
						event:    models.GroundTruthEvent{ActionType: models.ProcessExec, Target: s.target, PID: s.pid},
						tid:      s.tid,
						filename: filename,
						viaFD:    s.viaFD,
					}))
				case "ok":
					out(h.succeeded(s.pid, s.tid, &models.ExecImage{Filename: s.kernelArg}))
				case "exit", "fork":
					out(h.process(s.pid))
				case "flush":
					out(h.flush())
				}
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("released %+v, want %+v", got, c.want)
			}
			if len(h.held) != 0 && c.steps[len(c.steps)-1].kind == "flush" {
				t.Errorf("%d still held after the flush", len(h.held))
			}
		})
	}
}
