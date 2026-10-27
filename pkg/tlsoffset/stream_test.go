package tlsoffset

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"reflect"
	"testing"
)

// wholeScan is steps 3 and 4 of scanCluster over the section held whole, as
// they were before N-35: the reference the windowed scan must reproduce.
func wholeScan(code []byte, addr, target uint64) map[uint64]int {
	var sites []uint64
	sites = append(sites, scanLEA(code, addr, target)...)
	sites = append(sites, scanAbsolute(code, addr, target)...)
	starts := map[uint64]int{}
	for _, site := range sites {
		if va := findFunctionStart(code, addr, site, 4096); va != 0 {
			starts[va]++
		}
	}
	return starts
}

// plantedCode is random code with functions (endbr64 after int3 padding)
// whose bodies reference target by a RIP-relative LEA or a mov immediate, at
// positions that straddle every window boundary of a small chunk.
func plantedCode(rng *rand.Rand, size int, addr, target uint64, chunk int) []byte {
	code := make([]byte, size)
	for i := range code {
		code[i] = byte(rng.Intn(256))
	}
	put := func(at int, b ...byte) {
		if at >= 0 && at+len(b) <= size {
			copy(code[at:], b)
		}
	}
	for at := 64; at < size-64; at += chunk / 3 {
		for _, d := range []int{-9, -4, -2, 0, 1, 3} {
			p := at + d
			put(p-40, 0xcc, 0xf3, 0x0f, 0x1e, 0xfa)
			if rng.Intn(2) == 0 {
				disp := int32(int64(target) - int64(addr+uint64(p)+7))
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], uint32(disp))
				put(p, 0x48, 0x8d, 0x05, b[0], b[1], b[2], b[3])
			} else {
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], uint32(target))
				put(p-1, 0xb8, b[0], b[1], b[2], b[3])
			}
		}
	}
	return code
}

// The windowed scan finds exactly the function starts and counts the scan
// over the whole section finds (N-35), with references and function starts
// on and around every window boundary.
func TestScanSectionAgreesWithTheWholeSection(t *testing.T) {
	defer func(c int) { scanChunk = c }(scanChunk)
	const addr, target = 0x401000, 0x200123
	for _, chunk := range []int{64, 97, 1000, 4096, 1 << 14} {
		scanChunk = chunk
		for seed := int64(1); seed <= 4; seed++ {
			rng := rand.New(rand.NewSource(seed))
			code := plantedCode(rng, 40000+int(seed)*7, addr, target, chunk)
			want := wholeScan(code, addr, target)
			got, err := scanSection(section{r: bytes.NewReader(code), size: len(code)}, addr, target)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) == 0 {
				t.Fatalf("chunk %d seed %d: the planted code has no reference", chunk, seed)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("chunk %d seed %d: windowed %d starts, whole %d", chunk, seed, len(got), len(want))
			}
		}
	}
}

// The windowed string search returns the start of the NUL-terminated string
// holding the first occurrence, as an index over the whole section would,
// for a needle split across windows and a string that begins windows before.
func TestStringStartAgreesWithTheWholeSection(t *testing.T) {
	defer func(c int) { scanChunk = c }(scanChunk)
	needle := []byte("ssl_lib.cc")
	whole := func(data []byte) (int, bool) {
		idx := bytes.Index(data, needle)
		if idx < 0 {
			return 0, false
		}
		start := idx
		for start > 0 && data[start-1] != 0 {
			start--
		}
		return start, true
	}
	for _, chunk := range []int{4, 7, 16, 100} {
		scanChunk = chunk
		for _, data := range [][]byte{
			[]byte("\x00abc\x00../ssl/ssl_lib.cc\x00more ssl_lib.cc\x00"),
			[]byte("third_party/boringssl/ssl/ssl_lib.cc"),
			append(bytes.Repeat([]byte("x"), 9000), []byte("ssl_lib.cc\x00")...),
			append(append(bytes.Repeat([]byte("y"), 300), 0), bytes.Repeat([]byte("z"), 5000)...),
			[]byte(""),
		} {
			want, wantOK := whole(data)
			got, ok, err := stringStart(section{r: bytes.NewReader(data), size: len(data)}, needle)
			if err != nil || got != want || ok != wantOK {
				t.Errorf("chunk %d, %d bytes: got %d %v %v, want %d %v", chunk, len(data), got, ok, err, want, wantOK)
			}
		}
	}
}
