package proc

import (
	"strconv"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// walkedPath turns the path the kernel walked (P-36) into a string: names
// leaf first, each NUL-terminated, from a dentry up to the process's root.
// A whole walk is an absolute path ("/" for the root itself); a cut one
// keeps the names it read, from the root side, without a leading slash.
// An empty cut walk is "", not recorded.
func walkedPath(b []byte, cut bool) string {
	var names []string
	for len(b) > 0 {
		end := 0
		for end < len(b) && b[end] != 0 {
			end++
		}
		names = append(names, string(b[:end]))
		if end == len(b) {
			break
		}
		b = b[end+1:]
	}
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
		names[i], names[j] = names[j], names[i]
	}
	p := strings.Join(names, "/")
	if cut {
		return p
	}
	return "/" + p
}

// filenameChanged reports whether the kernel's filename differs from the one
// the probe read at syscall entry. An exec through a descriptor has no entry
// filename. An execveat path relative to a directory descriptor reaches the
// kernel as /dev/fd/N/<path>, which is the same path.
func filenameChanged(entry string, viaFD bool, kernel string) bool {
	if viaFD || entry == "" || kernel == "" || entry == kernel {
		return false
	}
	if rest, ok := strings.CutPrefix(kernel, "/dev/fd/"); ok && !strings.HasPrefix(entry, "/") {
		if fd, path, ok := strings.Cut(rest, "/"); ok && path == entry {
			if _, err := strconv.Atoi(fd); err == nil {
				return false
			}
		}
	}
	return true
}

// heldExec is an exec event waiting for its outcome.
type heldExec struct {
	event    models.GroundTruthEvent
	tid      uint32
	filename string // the filename read at syscall entry
	viaFD    bool
}

// holder keeps each exec event until its outcome is known, so the event of
// an exec that took effect carries the kernel's record of it (P-36). The
// exec record is read at syscall entry; the success record follows within
// the same syscall when the exec takes effect, and never when it fails.
// An event is released with its image at its success record, and without
// one at the first record that shows its attempt over: another attempt of
// the same thread, another thread's exec taking effect in its process, the
// exit of its process, or the fork of a new process with its pid. The rest
// are released at Stop. Events are released in the order they were held.
type holder struct {
	held []heldExec
}

// hold keeps an exec event of thread tid, and returns the events it
// releases: the thread's previous attempt, which failed or whose success
// record was lost.
func (h *holder) hold(x heldExec) []models.GroundTruthEvent {
	out := h.thread(x.tid)
	h.held = append(h.held, x)
	return out
}

// thread releases the attempt of thread tid, which made another one.
func (h *holder) thread(tid uint32) []models.GroundTruthEvent {
	return h.release(func(y heldExec) bool { return y.tid == tid })
}

// succeeded releases the attempt of thread tid with img attached, after the
// attempts of other threads of process tgid, which the exec ended. It
// returns nil for an attempt it does not hold (filtered, or lost).
func (h *holder) succeeded(tgid, tid uint32, img *models.ExecImage) []models.GroundTruthEvent {
	var out []models.GroundTruthEvent
	kept := h.held[:0]
	var mine *heldExec
	for i := range h.held {
		y := h.held[i]
		switch {
		case y.tid == tid && mine == nil:
			m := y
			mine = &m
		case y.event.PID == tgid:
			out = append(out, y.event)
		default:
			kept = append(kept, y)
		}
	}
	h.held = kept
	if mine != nil {
		e := mine.event
		if img != nil {
			im := *img
			im.FilenameChanged = filenameChanged(mine.filename, mine.viaFD, im.Filename)
			e.Image = &im
		}
		out = append(out, e)
	}
	return out
}

// process releases every attempt of process pid: it exited, or a new
// process took its pid.
func (h *holder) process(pid uint32) []models.GroundTruthEvent {
	return h.release(func(y heldExec) bool { return y.event.PID == pid })
}

// flush releases everything, at Stop.
func (h *holder) flush() []models.GroundTruthEvent {
	return h.release(func(heldExec) bool { return true })
}

func (h *holder) release(match func(heldExec) bool) []models.GroundTruthEvent {
	var out []models.GroundTruthEvent
	kept := h.held[:0]
	for _, y := range h.held {
		if match(y) {
			out = append(out, y.event)
		} else {
			kept = append(kept, y)
		}
	}
	h.held = kept
	return out
}
