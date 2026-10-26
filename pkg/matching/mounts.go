package matching

import (
	"path"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Mounts is a capture's mount table read for matching (V-46): it lets a claim
// that names a file through one mount match an event the probe named through
// another, when the table proves both paths reach the same file. A nil
// *Mounts matches exactly as TargetsMatch does.
type Mounts struct {
	children map[int][]*mount
	root     *mount
	// namer holds, per filesystem, the one mount the probe names its files
	// through. A filesystem with none, or with more than one, is absent.
	namer map[string]*mount
}

type mount struct {
	id          int
	device      string
	root, point string
	// gone is true for a mount whose root or point the kernel marked
	// "//deleted": the path it shows no longer names what it exposes.
	gone bool
}

// NewMounts reads a capture's fs_scope record. It returns nil, which matches
// by path only, when the record holds no mount table, when the table is not
// known to have stayed the same for the whole capture (a stale table could
// trace a claim to a file it did not reach), or when the table is malformed:
// duplicate mount ids, or not exactly one root mount at "/".
func NewMounts(s *models.FSScope) *Mounts {
	if s == nil || len(s.Filesystems) == 0 || s.MountTableChanged == nil || *s.MountTableChanged {
		return nil
	}
	m := &Mounts{children: map[int][]*mount{}, namer: map[string]*mount{}}
	byID := map[int]*mount{}
	parents := map[int]int{}
	names := map[string]int{}
	for _, fs := range s.Filesystems {
		for _, r := range fs.Mounts {
			if _, dup := byID[r.ID]; dup {
				return nil
			}
			mt := &mount{id: r.ID, device: fs.Device, root: r.Root, point: r.Point,
				gone: strings.HasSuffix(r.Root, "//deleted") || strings.HasSuffix(r.Point, "//deleted")}
			byID[r.ID], parents[r.ID] = mt, r.Parent
			if r.Names {
				names[fs.Device]++
				m.namer[fs.Device] = mt
			}
		}
	}
	for dev, n := range names {
		if n != 1 {
			delete(m.namer, dev)
		}
	}
	for id, mt := range byID {
		p := parents[id]
		if _, ok := byID[p]; ok && p != id {
			m.children[p] = append(m.children[p], mt)
			continue
		}
		if mt.point != "/" || m.root != nil {
			return nil
		}
		m.root = mt
	}
	if m.root == nil {
		return nil
	}
	return m
}

// TargetsMatch is TargetsMatch, plus the alias rule of V-46 for a file
// claim: the claim also matches when Canonical traces its path to a name
// that matches the event's.
func (m *Mounts) TargetsMatch(t models.TrajectoryEntry, g models.GroundTruthEvent) bool {
	if TargetsMatch(t, g) {
		return true
	}
	if m == nil || !isFileAction(t.ActionType) {
		return false
	}
	n, ok := m.Canonical(t.Target)
	return ok && targetsMatch(t.ActionType, n, g.Target, g.PathIsAmbiguous)
}

// Canonical returns the name the fs probe gives the file p reaches, when the
// mount table proves it. p is traced through the table as the kernel walks
// a path, component by component, taking at each prefix the mount on top of
// that point: this gives the mount p is under and the path within its
// filesystem. That path is then named through the mount the probe names the
// filesystem through, and the name is traced back through the table, which
// must lead to the same mount and path. ok is false when any step fails: p is
// relative or holds "..", which a symbolic link resolves differently from
// the lexical reading; the walk meets two mounts at one point; p's mount or
// the probe's was deleted; the filesystem has no single probe mount (not
// marked, or several); the file lies outside the probe mount's root, where
// the probe gives it no name; or the name is covered by another mount, so
// the same string would name another file.
//
// The table describes the probe's mount namespace when the capture started.
// Symbolic links are not followed: a link in p is read as a directory, and a
// path through one reaches a file whose probe name differs, so it does not
// match.
func (m *Mounts) Canonical(p string) (string, bool) {
	if m == nil || !path.IsAbs(p) {
		return "", false
	}
	for _, el := range strings.Split(p, "/") {
		if el == ".." {
			return "", false
		}
	}
	p = path.Clean(p)
	at, rel, ok := m.resolve(p)
	if !ok || at.gone {
		return "", false
	}
	namer := m.namer[at.device]
	if namer == nil || namer.gone {
		return "", false
	}
	inFS := join(at.root, rel)
	q, ok := under(inFS, namer.root)
	if !ok {
		return "", false
	}
	name := join(namer.point, q)
	back, backRel, ok := m.resolve(name)
	if !ok || back != namer || backRel != q {
		return "", false
	}
	return name, true
}

// resolve walks p (absolute, clean) from the root mount and returns the mount
// it ends under and p's path relative to that mount's point ("" for the
// point itself). At each prefix it descends into the mounts stacked on it; ok
// is false when one mount has two children on one point, since which is on
// top is then not known.
func (m *Mounts) resolve(p string) (*mount, string, bool) {
	cur, ok := m.descend(m.root, "/")
	if !ok {
		return nil, "", false
	}
	prefix := ""
	for _, el := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if el == "" {
			continue
		}
		prefix += "/" + el
		if cur, ok = m.descend(cur, prefix); !ok {
			return nil, "", false
		}
	}
	rel, _ := under(p, cur.point)
	return cur, rel, true
}

// descend follows the mounts stacked on point above cur, to the top one. A
// stack taller than the table is a cycle in a malformed table.
func (m *Mounts) descend(cur *mount, point string) (*mount, bool) {
	for range len(m.children) + 1 {
		var next *mount
		for _, c := range m.children[cur.id] {
			if c.point != point {
				continue
			}
			if next != nil {
				return nil, false
			}
			next = c
		}
		if next == nil {
			return cur, true
		}
		cur = next
	}
	return nil, false
}

// under returns p relative to dir, "" for dir itself, and whether p is dir or
// inside it. Both are absolute and clean.
func under(p, dir string) (string, bool) {
	switch {
	case dir == "/":
		return strings.TrimPrefix(p, "/"), true
	case p == dir:
		return "", true
	case strings.HasPrefix(p, dir+"/"):
		return p[len(dir)+1:], true
	}
	return "", false
}

// join appends a relative path to an absolute directory.
func join(dir, rel string) string {
	if rel == "" {
		return dir
	}
	return path.Join(dir, rel)
}
