package proc

import "testing"

// joinStep is one record as readLoop hands it to the joiner.
type joinStep struct {
	kind      string // "attempt", "ok" or "exit"
	tgid, tid uint32
	target    string
}

// The exit record names the image that exited: the command line of the last
// exec that took effect for the process (P-31). The cases run without root;
// the privileged tests in observer_test.go check the kernel side.
func TestJoiner_ExitNamesTheLastImageThatTookEffect(t *testing.T) {
	cases := []struct {
		name  string
		steps []joinStep
		want  string // "" means no exit record
	}{
		{
			name: "one exec",
			steps: []joinStep{
				{"attempt", 10, 10, "/bin/true a"}, {"ok", 10, 10, ""}, {"exit", 10, 0, ""},
			},
			want: "/bin/true a",
		},
		{
			name: "a failed attempt after a successful exec does not replace the image",
			steps: []joinStep{
				{"attempt", 10, 10, "/usr/bin/python3 -c x"}, {"ok", 10, 10, ""},
				{"attempt", 10, 10, "/nonexistent b"},
				{"exit", 10, 0, ""},
			},
			want: "/usr/bin/python3 -c x",
		},
		{
			name: "a PATH search: failed attempts, then the one that succeeds",
			steps: []joinStep{
				{"attempt", 10, 10, "/usr/local/bin/git status"},
				{"attempt", 10, 10, "/usr/bin/git status"}, {"ok", 10, 10, ""},
				{"exit", 10, 0, ""},
			},
			want: "/usr/bin/git status",
		},
		{
			name: "a shell that execs twice exits as its last image",
			steps: []joinStep{
				{"attempt", 10, 10, "/bin/sh -c cd x && git status"}, {"ok", 10, 10, ""},
				{"attempt", 10, 10, "/usr/bin/git status"}, {"ok", 10, 10, ""},
				{"exit", 10, 0, ""},
			},
			want: "/usr/bin/git status",
		},
		{
			name: "a process whose only attempts failed has no exit record",
			steps: []joinStep{
				{"attempt", 10, 10, "/nonexistent a"}, {"exit", 10, 0, ""},
			},
		},
		{
			name: "a non-leader thread's exec takes effect under the tgid",
			steps: []joinStep{
				{"attempt", 10, 10, "/usr/bin/python3 -c x"}, {"ok", 10, 10, ""},
				{"attempt", 10, 11, "/bin/true t"}, {"ok", 10, 11, ""},
				{"exit", 10, 0, ""},
			},
			want: "/bin/true t",
		},
		{
			name: "another thread's concurrent failed attempt does not name the exit",
			steps: []joinStep{
				{"attempt", 10, 10, "/usr/bin/python3 -c x"}, {"ok", 10, 10, ""},
				{"attempt", 10, 11, "/bin/true t"},
				{"attempt", 10, 12, "/nonexistent u"},
				{"ok", 10, 11, ""},
				{"exit", 10, 0, ""},
			},
			want: "/bin/true t",
		},
		{
			// The attempt record was lost (a ring drop, counted): the old
			// image is gone, so the exit is not emitted rather than named
			// after it.
			name: "a success whose attempt this reader never saw clears the image",
			steps: []joinStep{
				{"attempt", 10, 10, "/bin/sh -c x"}, {"ok", 10, 10, ""},
				{"ok", 10, 10, ""},
				{"exit", 10, 0, ""},
			},
		},
		{
			name: "the exit forgets the process, so a recycled pid starts afresh",
			steps: []joinStep{
				{"attempt", 10, 10, "/bin/true a"}, {"ok", 10, 10, ""}, {"exit", 10, 0, ""},
				{"exit", 10, 0, ""},
			},
			want: "/bin/true a",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j := newJoiner()
			var got []execLine
			for _, s := range c.steps {
				switch s.kind {
				case "attempt":
					j.attempt(s.tid, execLine{target: s.target})
				case "ok":
					j.succeeded(s.tgid, s.tid)
				case "exit":
					if l, ok := j.exit(s.tgid); ok {
						got = append(got, l)
					}
				}
			}
			switch {
			case c.want == "" && len(got) != 0:
				t.Errorf("exit records %+v, want none", got)
			case c.want != "" && (len(got) != 1 || got[0].target != c.want):
				t.Errorf("exit records %+v, want one naming %q", got, c.want)
			}
		})
	}
}

// The truncation flag travels with the image's command line.
func TestJoiner_ExitKeepsTheImagesTruncationFlag(t *testing.T) {
	j := newJoiner()
	j.attempt(10, execLine{target: "/bin/sh -c long", truncated: true})
	j.succeeded(10, 10)
	j.attempt(10, execLine{target: "/nonexistent"})
	l, ok := j.exit(10)
	if !ok || l.target != "/bin/sh -c long" || !l.truncated {
		t.Errorf("exit = %+v, %v; want the cut shell command line, flagged", l, ok)
	}
}
