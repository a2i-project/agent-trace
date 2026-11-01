package tlsoffset

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// ErrNoAnchor means a locator did not find the anchors it needs in the
// executable: the library is absent, or built in a way the locator does not
// know. A caller refuses the content method instead of guessing (N-38).
var ErrNoAnchor = errors.New("tlsoffset: anchors not found")

// rX86_64Relative is the relocation type of a pointer a static-pie fills in
// at load: base + addend.
const rX86_64Relative = 8

// image is an executable read for the anchor locators (N-38). Every section
// is read through ReadAt in windows of scanChunk, as Scan reads (N-35); the
// function table of .eh_frame_hdr is binary-searched in place.
type image struct {
	f      *elf.File
	text   *elf.Section
	rodata *elf.Section
	rela   *elf.Section // .rela.dyn; nil without one
	eh     *elf.Section // .eh_frame_hdr
	// The search table of .eh_frame_hdr: fdeCount entries of two signed
	// 32-bit values, relative to the section's address, from tableOff.
	fdeCount int
	tableOff int
}

// newImage opens the sections the locators read. It needs .text, .rodata
// and an .eh_frame_hdr whose search table it can read; the function starts
// come from that table, not from a guess at prologues.
func newImage(f *elf.File) (*image, error) {
	im := &image{f: f, text: f.Section(".text"), rodata: f.Section(".rodata"), rela: f.Section(".rela.dyn"), eh: f.Section(".eh_frame_hdr")}
	if im.text == nil || im.rodata == nil {
		return nil, fmt.Errorf("%w: no .text or .rodata section", ErrNoAnchor)
	}
	if im.eh == nil {
		return nil, fmt.Errorf("%w: no .eh_frame_hdr, so no function table", ErrNoAnchor)
	}
	hdr, err := sectionOf(im.eh).read(0, 12)
	if err != nil || len(hdr) < 12 {
		return nil, fmt.Errorf("%w: unreadable .eh_frame_hdr", ErrNoAnchor)
	}
	// version 1; eh_frame_ptr pcrel|sdata4 (0x1b) or udata4/sdata4; the
	// count udata4 (0x03); the table datarel|sdata4 (0x3b), the encodings
	// GNU ld, gold and lld write.
	if hdr[0] != 1 || hdr[2] != 0x03 || hdr[3] != 0x3b {
		return nil, fmt.Errorf("%w: .eh_frame_hdr encoding %#x/%#x/%#x not supported", ErrNoAnchor, hdr[0], hdr[2], hdr[3])
	}
	switch hdr[1] & 0x0f {
	case 0x03, 0x0b: // udata4, sdata4
	default:
		return nil, fmt.Errorf("%w: .eh_frame_hdr pointer encoding %#x not supported", ErrNoAnchor, hdr[1])
	}
	im.fdeCount = int(binary.LittleEndian.Uint32(hdr[8:12]))
	im.tableOff = 12
	if im.tableOff+8*im.fdeCount > int(im.eh.Size) {
		return nil, fmt.Errorf("%w: .eh_frame_hdr table larger than its section", ErrNoAnchor)
	}
	return im, nil
}

// fdeStart returns the function start of table entry i.
func (im *image) fdeStart(i int) (uint64, error) {
	b, err := sectionOf(im.eh).read(im.tableOff+8*i, im.tableOff+8*i+4)
	if err != nil {
		return 0, err
	}
	return uint64(int64(im.eh.Addr) + int64(int32(binary.LittleEndian.Uint32(b)))), nil
}

// function returns the start and end of the function that holds va, from
// the sorted table of .eh_frame_hdr: the last entry at or below va, ending
// at the next entry. ok is false for an address before the first entry or
// a read error.
func (im *image) function(va uint64) (start, end uint64, ok bool) {
	lo, hi := 0, im.fdeCount // first entry above va is in [lo, hi]
	for lo < hi {
		mid := (lo + hi) / 2
		s, err := im.fdeStart(mid)
		if err != nil {
			return 0, 0, false
		}
		if s <= va {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return 0, 0, false
	}
	start, err := im.fdeStart(lo - 1)
	if err != nil {
		return 0, 0, false
	}
	end = im.text.Addr + im.text.Size
	if lo < im.fdeCount {
		if e, err := im.fdeStart(lo); err == nil {
			end = e
		}
	}
	return start, end, true
}

// readVA reads n bytes at virtual address va from the allocated section
// that holds them.
func (im *image) readVA(va uint64, n int) ([]byte, error) {
	for _, s := range im.f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS || va < s.Addr || va >= s.Addr+s.Size {
			continue
		}
		off := int(va - s.Addr)
		b, err := sectionOf(s).read(off, off+n)
		if err != nil {
			return nil, err
		}
		if len(b) < n {
			return nil, fmt.Errorf("read %d bytes at %#x: past the end of %s", n, va, s.Name)
		}
		return b, nil
	}
	return nil, fmt.Errorf("address %#x is in no section", va)
}

// sectionAt returns the allocated section that holds va, or nil.
func (im *image) sectionAt(va uint64) *elf.Section {
	for _, s := range im.f.Sections {
		if s.Flags&elf.SHF_ALLOC != 0 && va >= s.Addr && va < s.Addr+s.Size {
			return s
		}
	}
	return nil
}

// executable reports whether va lies in an executable PT_LOAD segment's
// file-backed part, so that a uprobe at its file offset (vaToFileOff) is
// at the same byte the process runs.
func (im *image) executable(va uint64) bool {
	for _, p := range im.f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && va >= p.Vaddr && va < p.Vaddr+p.Filesz {
			return true
		}
	}
	// A file without program headers (the tests' synthetic ELF): its
	// .text section is the code.
	return len(im.f.Progs) == 0 && im.inText(va)
}

func (im *image) inText(va uint64) bool {
	return va >= im.text.Addr && va < im.text.Addr+im.text.Size
}

// textSlack is how many bytes past the positions it owns a .text window
// carries, more than the longest pattern the locators read at a position.
const textSlack = 16

// scanText calls fn with each window of .text: w holds the bytes from
// address base, and fn owns the positions in [base, base+owned); the bytes
// after them are slack, so a pattern that starts at an owned position is
// seen whole.
func (im *image) scanText(fn func(w []byte, base uint64, owned int)) error {
	s := sectionOf(im.text)
	for start := 0; start < s.size; start += scanChunk {
		end := min(start+scanChunk, s.size)
		w, err := s.read(start, end+textSlack)
		if err != nil {
			return err
		}
		fn(w, im.text.Addr+uint64(start), end-start)
	}
	return nil
}

// ripRef is one RIP-relative reference found in .text: the instruction's
// address, its target and its kind.
type ripRef struct {
	site, target uint64
	op           byte // 0x8d lea, 0xe8 call, 0xe9 jmp
}

// leaRefs returns every RIP-relative lea (REX.W, any register) in .text
// whose target is in targets.
func (im *image) leaRefs(targets map[uint64]bool) ([]ripRef, error) {
	var out []ripRef
	err := im.scanText(func(w []byte, base uint64, owned int) {
		for i := 0; i < owned && i+7 <= len(w); i++ {
			if (w[i] != 0x48 && w[i] != 0x4c) || w[i+1] != 0x8d || w[i+2]&0xc7 != 0x05 {
				continue
			}
			disp := int32(binary.LittleEndian.Uint32(w[i+3 : i+7]))
			site := base + uint64(i)
			t := uint64(int64(site) + 7 + int64(disp))
			if targets[t] {
				out = append(out, ripRef{site: site, target: t, op: 0x8d})
			}
		}
	})
	return out, err
}

// branchRefs returns every direct call (e8) and jump (e9) with a 32-bit
// displacement in .text whose target is in targets. A match inside another
// instruction's bytes is possible; the caller keeps only sites that the
// function table places inside a function, and validation at run time
// decides (N-D4).
func (im *image) branchRefs(targets map[uint64]bool) ([]ripRef, error) {
	var out []ripRef
	err := im.scanText(func(w []byte, base uint64, owned int) {
		for i := 0; i < owned && i+5 <= len(w); i++ {
			if w[i] != 0xe8 && w[i] != 0xe9 {
				continue
			}
			disp := int32(binary.LittleEndian.Uint32(w[i+1 : i+5]))
			site := base + uint64(i)
			t := uint64(int64(site) + 5 + int64(disp))
			if targets[t] {
				out = append(out, ripRef{site: site, target: t, op: w[i]})
			}
		}
	})
	return out, err
}

// functionsOf maps each reference to the function holding it, by target.
func (im *image) functionsOf(refs []ripRef) map[uint64]map[uint64]bool {
	out := map[uint64]map[uint64]bool{}
	for _, r := range refs {
		start, _, ok := im.function(r.site)
		if !ok {
			continue
		}
		if out[r.target] == nil {
			out[r.target] = map[uint64]bool{}
		}
		out[r.target][start] = true
	}
	return out
}

// forEachRelative calls fn with the offset and addend of every
// R_X86_64_RELATIVE relocation in .rela.dyn: in a static-pie, every pointer
// stored in data (a vtable slot, a panic location's file name, a GOT slot)
// is one. Without .rela.dyn it does nothing.
func (im *image) forEachRelative(fn func(off, addend uint64)) error {
	if im.rela == nil {
		return nil
	}
	s := sectionOf(im.rela)
	chunk := scanChunk - scanChunk%24
	if chunk < 24 {
		chunk = 24
	}
	for start := 0; start < s.size; start += chunk {
		w, err := s.read(start, start+chunk)
		if err != nil {
			return err
		}
		for i := 0; i+24 <= len(w); i += 24 {
			if binary.LittleEndian.Uint64(w[i+8:i+16])&0xffffffff != rX86_64Relative {
				continue
			}
			fn(binary.LittleEndian.Uint64(w[i:i+8]), binary.LittleEndian.Uint64(w[i+16:i+24]))
		}
	}
	return nil
}

// stringsAt returns the address of every occurrence of each needle followed
// by a NUL in .rodata. A linker that merges string tails may place the
// needle inside a longer string; the address is the needle's own.
func (im *image) stringsAt(needles ...string) (map[string][]uint64, error) {
	s := sectionOf(im.rodata)
	out := map[string][]uint64{}
	longest := 0
	for _, n := range needles {
		longest = max(longest, len(n)+1)
	}
	for start := 0; start < s.size; start += scanChunk {
		w, err := s.read(start, start+scanChunk+longest-1)
		if err != nil {
			return nil, err
		}
		for _, n := range needles {
			pat := append([]byte(n), 0)
			for i := 0; ; {
				j := bytes.Index(w[i:], pat)
				if j < 0 {
					break
				}
				at := i + j
				if at < scanChunk || start+scanChunk >= s.size {
					out[n] = append(out[n], im.rodata.Addr+uint64(start+at))
				}
				i = at + 1
			}
		}
	}
	for _, n := range needles {
		sort.Slice(out[n], func(i, j int) bool { return out[n][i] < out[n][j] })
		out[n] = dedupSorted(out[n])
	}
	return out, nil
}

// regexpAt is a match of a pattern in .rodata: its address range and
// submatches.
type regexpAt struct {
	start, end uint64
	groups     []string
}

// regexpsAt returns every match of re in .rodata, a match being at most
// maxLen bytes long so that windows overlapping by maxLen see each whole.
func (im *image) regexpsAt(re *regexp.Regexp, maxLen int) ([]regexpAt, error) {
	s := sectionOf(im.rodata)
	seen := map[uint64]bool{}
	var out []regexpAt
	for start := 0; start < s.size; start += scanChunk {
		w, err := s.read(start, start+scanChunk+maxLen)
		if err != nil {
			return nil, err
		}
		for _, m := range re.FindAllSubmatchIndex(w, -1) {
			at := im.rodata.Addr + uint64(start+m[0])
			if seen[at] {
				continue
			}
			seen[at] = true
			g := make([]string, 0, len(m)/2-1)
			for k := 2; k+1 < len(m); k += 2 {
				if m[k] < 0 {
					g = append(g, "")
					continue
				}
				g = append(g, string(w[m[k]:m[k+1]]))
			}
			out = append(out, regexpAt{start: at, end: im.rodata.Addr + uint64(start+m[1]), groups: g})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out, nil
}

func dedupSorted(v []uint64) []uint64 {
	out := v[:0]
	for i, x := range v {
		if i == 0 || x != v[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func setOf(vs ...map[uint64]bool) map[uint64]bool {
	out := map[uint64]bool{}
	for _, v := range vs {
		for k := range v {
			out[k] = true
		}
	}
	return out
}
