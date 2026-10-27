package tlsoffset

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// Target represents the validated offsets of one build. SSLRead is zero
// when no SSL_read offset was validated for it.
type Target struct {
	Path     string `json:"path"`
	BuildID  string `json:"build_id"`
	SSLWrite uint64 `json:"ssl_write_file_offset"`
	SSLRead  uint64 `json:"ssl_read_file_offset,omitempty"`
}

// Candidate represents a potential SSL_write or SSL_read location.
type Candidate struct {
	VA      uint64
	FileOff uint64
	Score   int
}

// Result holds the candidates Scan found for both functions.
type Result struct {
	BuildID string
	Write   []Candidate // SSL_write
	Read    []Candidate // SSL_read
}

// ScanELF analyzes a stripped executable to find SSL_write candidates.
func ScanELF(path string) ([]Candidate, string, error) {
	r, err := Scan(path)
	return r.Write, r.BuildID, err
}

// Scan finds SSL_write and SSL_read candidates in one pass. A function with
// a symbol has that symbol as its only candidate. Otherwise both lists are
// the functions that reference the ssl_lib.cc string, ranked by the number
// of references: SSL_write and SSL_read both sit in that cluster, and only
// runtime validation tells them apart (N-D4). Read is empty, without an
// error, when SSL_write has a symbol, SSL_read has none and the cluster
// cannot be scanned.
func Scan(path string) (Result, error) {
	f, err := elf.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open elf: %w", err)
	}
	defer func() { _ = f.Close() }()

	res := Result{BuildID: getBuildID(f)}

	// 1. Try symbols first
	for _, get := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		syms, err := get()
		if err != nil {
			continue
		}
		for _, s := range syms {
			if s.Value == 0 {
				continue
			}
			c := []Candidate{{VA: s.Value, FileOff: vaToFileOff(f, s.Value), Score: 100}}
			switch {
			case s.Name == "SSL_write" && res.Write == nil:
				res.Write = c
			case s.Name == "SSL_read" && res.Read == nil:
				res.Read = c
			}
		}
	}
	if res.Write != nil && res.Read != nil {
		return res, nil
	}

	cluster, err := scanCluster(f)
	if err != nil {
		if res.Write != nil {
			return res, nil
		}
		return res, err
	}
	if res.Write == nil {
		res.Write = cluster
	}
	if res.Read == nil {
		res.Read = append([]Candidate(nil), cluster...)
	}
	return res, nil
}

// scanCluster returns the functions that reference the ssl_lib.cc string,
// ranked by reference count.
func scanCluster(f *elf.File) ([]Candidate, error) {
	// 2. Locate ssl_lib.cc string
	strVA, err := findString(f, "ssl_lib.cc")
	if err != nil {
		return nil, fmt.Errorf("find string: %w", err)
	}

	text := f.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}

	// 3. Scan .text for xrefs to strVA, and 4. find their function starts,
	// reading the section a window at a time (N-35).
	funcStarts, err := scanText(text, strVA)
	if err != nil {
		return nil, fmt.Errorf("read .text: %w", err)
	}

	var candidates []Candidate
	for va, score := range funcStarts {
		candidates = append(candidates, Candidate{
			VA:      va,
			FileOff: vaToFileOff(f, va),
			Score:   score,
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].VA < candidates[j].VA
	})

	return candidates, nil
}

func scanLEA(code []byte, base, target uint64) []uint64 {
	var out []uint64
	for i := 0; i+7 <= len(code); i++ {
		rex := code[i]
		if rex != 0x48 && rex != 0x4c {
			continue
		}
		if code[i+1] != 0x8d {
			continue
		}
		modrm := code[i+2]
		if modrm&0xC7 != 0x05 {
			continue
		}
		disp := int32(binary.LittleEndian.Uint32(code[i+3 : i+7]))
		next := base + uint64(i) + 7
		if uint64(int64(next)+int64(disp)) == target {
			out = append(out, base+uint64(i))
		}
	}
	return out
}

func scanAbsolute(code []byte, base, target uint64) []uint64 {
	if target > 0xffffffff {
		return nil
	}
	var want [4]byte
	binary.LittleEndian.PutUint32(want[:], uint32(target))

	var out []uint64
	for i := 0; i+4 <= len(code); i++ {
		if code[i] != want[0] || code[i+1] != want[1] || code[i+2] != want[2] || code[i+3] != want[3] {
			continue
		}
		if classifyImmediate(code, i) {
			out = append(out, base+uint64(i))
		}
	}
	return out
}

func classifyImmediate(code []byte, i int) bool {
	if i >= 2 && i+8 <= len(code) && code[i+4] == 0 && code[i+5] == 0 && code[i+6] == 0 && code[i+7] == 0 {
		if rex := code[i-2]; (rex == 0x48 || rex == 0x49) && code[i-1] >= 0xb8 && code[i-1] <= 0xbf {
			return true
		}
	}
	if i >= 3 && (code[i-3] == 0x48 || code[i-3] == 0x49) && code[i-2] == 0xc7 && code[i-1]&0xf8 == 0xc0 {
		return true
	}
	if i >= 2 && code[i-2] == 0x41 && code[i-1] >= 0xb8 && code[i-1] <= 0xbf {
		return true
	}
	if i >= 1 && code[i-1] >= 0xb8 && code[i-1] <= 0xbf {
		return true
	}
	if i >= 1 && code[i-1] == 0x68 {
		return true
	}
	return false
}

func findFunctionStart(code []byte, base, site uint64, maxBack int) uint64 {
	off := int(site - base)
	limit := off - maxBack
	if limit < 0 {
		limit = 0
	}
	for i := off; i >= limit+4; i-- {
		if code[i] == 0xf3 && code[i+1] == 0x0f && code[i+2] == 0x1e && code[i+3] == 0xfa {
			if i == 0 || code[i-1] == 0xcc || code[i-1] == 0x90 {
				return base + uint64(i)
			}
		}
	}
	for i := off; i > limit; i-- {
		if code[i] == 0xcc && code[i+1] != 0xcc && code[i+1] != 0x90 {
			return base + uint64(i+1)
		}
	}
	return 0
}

func findString(f *elf.File, needle string) (uint64, error) {
	for _, s := range f.Sections {
		if s.Type != elf.SHT_PROGBITS || s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		start, ok, err := stringStart(sectionOf(s), []byte(needle))
		if err != nil || !ok {
			continue
		}
		return s.Addr + uint64(start), nil
	}
	return 0, fmt.Errorf("string %q not found", needle)
}

// scanChunk is how much of a section the scan reads at once (N-35). Reading
// a whole section held the harness's .text (86 MB in Claude Code 2.1.306)
// and its .rodata in memory at once, which made the scan the largest part
// of watch's resident set. A variable so that tests can make it small.
var scanChunk = 4 << 20

// section is a section's bytes read through ReadAt, or, for a section that
// offers none (a compressed one), its data held whole.
type section struct {
	r    io.ReaderAt
	size int
}

func sectionOf(s *elf.Section) section {
	if s.ReaderAt != nil && s.Type != elf.SHT_NOBITS {
		return section{r: s.ReaderAt, size: int(s.Size)}
	}
	data, err := s.Data()
	if err != nil {
		return section{r: errReader{err}, size: int(s.Size)}
	}
	return section{r: bytes.NewReader(data), size: len(data)}
}

type errReader struct{ err error }

func (e errReader) ReadAt([]byte, int64) (int, error) { return 0, e.err }

// read returns the section's bytes in [from, to), clipped to the section.
func (s section) read(from, to int) ([]byte, error) {
	if from < 0 {
		from = 0
	}
	if to > s.size {
		to = s.size
	}
	if to <= from {
		return nil, nil
	}
	buf := make([]byte, to-from)
	n, err := s.r.ReadAt(buf, int64(from))
	if n == len(buf) {
		return buf, nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return nil, err
}

// stringStart finds the first occurrence of needle in the section and
// returns the offset of the NUL-terminated string that holds it, as
// bytes.Index over the whole section and a walk back to the previous NUL
// would. Windows overlap by len(needle)-1 bytes, so no occurrence is split.
func stringStart(s section, needle []byte) (int, bool, error) {
	if len(needle) == 0 {
		return 0, false, nil
	}
	for start := 0; start < s.size; start += scanChunk {
		w, err := s.read(start, start+scanChunk+len(needle)-1)
		if err != nil {
			return 0, false, err
		}
		i := bytes.Index(w, needle)
		if i < 0 {
			continue
		}
		at := start + i
		for at > 0 {
			from := at - 4096
			b, err := s.read(from, at)
			if err != nil {
				return 0, false, err
			}
			z := bytes.LastIndexByte(b, 0)
			if z >= 0 {
				return at - len(b) + z + 1, true, nil
			}
			at -= len(b)
		}
		return 0, true, nil
	}
	return 0, false, nil
}

// scanText is steps 3 and 4 of scanCluster over the .text section a window
// at a time: the LEA and immediate references to target in each window, and
// the function start of each, counted. A window carries 3 bytes before and 8
// after the positions it owns, the most an instruction pattern reads around
// a position, so every position is judged on the bytes the whole section
// would show it; a function start is looked for in the 4096 bytes before
// its reference and the 4 after.
func scanText(text *elf.Section, target uint64) (map[uint64]int, error) {
	return scanSection(sectionOf(text), text.Addr, target)
}

func scanSection(s section, addr, target uint64) (map[uint64]int, error) {
	var sites []uint64
	for start := 0; start < s.size; start += scanChunk {
		end := min(start+scanChunk, s.size)
		from := max(start-3, 0)
		w, err := s.read(from, end+8)
		if err != nil {
			return nil, err
		}
		base := addr + uint64(from)
		lo, hi := addr+uint64(start), addr+uint64(end)
		for _, found := range [][]uint64{scanLEA(w, base, target), scanAbsolute(w, base, target)} {
			for _, site := range found {
				if site >= lo && site < hi {
					sites = append(sites, site)
				}
			}
		}
	}
	funcStarts := make(map[uint64]int)
	for _, site := range sites {
		off := int(site - addr)
		from := max(off-4096, 0)
		w, err := s.read(from, off+4)
		if err != nil {
			return nil, err
		}
		if funcVA := findFunctionStart(w, addr+uint64(from), site, 4096); funcVA != 0 {
			funcStarts[funcVA]++
		}
	}
	return funcStarts, nil
}

func getBuildID(f *elf.File) string {
	sect := f.Section(".note.gnu.build-id")
	if sect == nil {
		return ""
	}
	data, _ := sect.Data()
	if len(data) < 16 {
		return ""
	}
	return fmt.Sprintf("%x", data[16:])
}

func vaToFileOff(f *elf.File, va uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && va >= prog.Vaddr && va < prog.Vaddr+prog.Filesz {
			return va - prog.Vaddr + prog.Off
		}
	}
	for _, sec := range f.Sections {
		if sec.Flags&elf.SHF_ALLOC != 0 && va >= sec.Addr && va < sec.Addr+sec.Size {
			return va - sec.Addr + sec.Offset
		}
	}
	return va
}
