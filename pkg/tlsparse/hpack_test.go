package tlsparse

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeAll(t *testing.T, d *hpackDecoder, block []byte) []hpackField {
	t.Helper()
	var out []hpackField
	if err := d.decode(block, func(n, v string) { out = append(out, hpackField{n, v}) }); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// The request examples with Huffman coding of RFC 7541, Appendix C.4, on
// one decoder: the second and third blocks index entries the first added.
func TestHPACK_RFC7541RequestsHuffman(t *testing.T) {
	d := newHPACKDecoder()
	steps := []struct {
		block string
		want  []hpackField
		size  int
	}{
		{"8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff", []hpackField{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}}, 57},
		{"8286 84be 5886 a8eb 1064 9cbf", []hpackField{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}, {"cache-control", "no-cache"}}, 110},
		{"8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf", []hpackField{{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"}, {":authority", "www.example.com"}, {"custom-key", "custom-value"}}, 164},
	}
	for i, s := range steps {
		got := decodeAll(t, d, unhex(t, s.block))
		if !reflect.DeepEqual(got, s.want) {
			t.Errorf("block %d: got %v, want %v", i+1, got, s.want)
		}
		if d.size != s.size {
			t.Errorf("block %d: table size %d, want %d", i+1, d.size, s.size)
		}
	}
	want := []hpackField{{"custom-key", "custom-value"}, {"cache-control", "no-cache"}, {":authority", "www.example.com"}}
	for i, f := range want {
		if got, _ := d.at(uint64(62 + i)); got != f {
			t.Errorf("index %d = %v, want %v", 62+i, got, f)
		}
	}
}

// The response examples with Huffman coding of RFC 7541, Appendix C.6, on a
// 256-byte table: the second block evicts the oldest entry.
func TestHPACK_RFC7541ResponsesEviction(t *testing.T) {
	d := newHPACKDecoder()
	d.maxSize = 256
	b1 := "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3"
	got := decodeAll(t, d, unhex(t, b1))
	want := []hpackField{{":status", "302"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:21 GMT"}, {"location", "https://www.example.com"}}
	if !reflect.DeepEqual(got, want) || d.size != 222 {
		t.Fatalf("block 1: got %v size %d", got, d.size)
	}
	got = decodeAll(t, d, unhex(t, "4883 640e ffc1 c0bf"))
	want[0] = hpackField{":status", "307"}
	if !reflect.DeepEqual(got, want) || d.size != 222 {
		t.Fatalf("block 2: got %v size %d", got, d.size)
	}
	if len(d.dyn) != 4 || d.dyn[0].value != "private" {
		t.Errorf("table after the eviction: %v", d.dyn)
	}
}

// encodeLiteral writes a literal field with incremental indexing and a
// literal name, its strings raw or Huffman-coded.
func encodeLiteral(name, value string, huff bool) []byte {
	out := []byte{0x40}
	out = append(out, encodeString(name, huff)...)
	return append(out, encodeString(value, huff)...)
}

func encodeString(s string, huff bool) []byte {
	b := []byte(s)
	flag := byte(0)
	if huff {
		b, flag = huffmanEncode(s), 0x80
	}
	return append(encodeInt(uint64(len(b)), 7, flag), b...)
}

func encodeInt(v uint64, n uint, flag byte) []byte {
	mask := uint64(1)<<n - 1
	if v < mask {
		return []byte{flag | byte(v)}
	}
	out := []byte{flag | byte(mask)}
	v -= mask
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func huffmanEncode(s string) []byte {
	var out []byte
	var acc uint64
	nbits := 0
	for i := 0; i < len(s); i++ {
		acc = acc<<huffmanLen[s[i]] | uint64(huffmanCode[s[i]])
		nbits += int(huffmanLen[s[i]])
		for nbits >= 8 {
			out = append(out, byte(acc>>(nbits-8)))
			nbits -= 8
		}
	}
	if nbits > 0 {
		out = append(out, byte(acc<<(8-nbits))|byte(0xff>>nbits))
	}
	return out
}

// Every byte value survives a Huffman round trip, and the decoder refuses
// bad padding and the end-of-string code.
func TestHuffman_RoundTripAndRefusals(t *testing.T) {
	var all strings.Builder
	for i := 0; i < 256; i++ {
		all.WriteByte(byte(i))
	}
	for _, s := range []string{"", "a", "www.example.com", all.String(), strings.Repeat("\x00\xff", 40)} {
		got, err := huffmanDecode(huffmanEncode(s))
		if err != nil || got != s {
			t.Errorf("round trip of %q: %q %v", s, got, err)
		}
	}
	for name, b := range map[string][]byte{
		"padding of zeros":    {0x00}, // '0' (00000) then 000 padding
		"padding of 8 ones":   append(huffmanEncode("a"), 0xff),
		"end-of-string code":  {0xff, 0xff, 0xff, 0xfc},
		"code cut in the end": {0xfe},
	} {
		if _, err := huffmanDecode(b); !errors.Is(err, ErrHPACK) {
			t.Errorf("%s: err %v, want ErrHPACK", name, err)
		}
	}
}

// Size updates, an entry larger than the table, never-indexed literals and
// the refusals of bad blocks.
func TestHPACK_TableRules(t *testing.T) {
	d := newHPACKDecoder()
	block := append(encodeLiteral("x-a", "1", false), encodeLiteral("x-b", "2", true)...)
	decodeAll(t, d, block)
	if len(d.dyn) != 2 {
		t.Fatalf("dyn %v", d.dyn)
	}
	// A size update to 40 evicts all but the newest (x-b: 3+1+32 = 36).
	got := decodeAll(t, d, append(encodeInt(40, 5, 0x20), 0xbe))
	if !reflect.DeepEqual(got, []hpackField{{"x-b", "2"}}) || len(d.dyn) != 1 {
		t.Fatalf("after the update: %v, table %v", got, d.dyn)
	}
	// An entry larger than the table empties it and is not kept.
	decodeAll(t, d, encodeLiteral("x-long", strings.Repeat("v", 50), false))
	if len(d.dyn) != 0 || d.size != 0 {
		t.Fatalf("table %v size %d", d.dyn, d.size)
	}
	// Never indexed, literal name: not added.
	nev := append([]byte{0x10}, append(encodeString("secret", false), encodeString("s", true)...)...)
	if got := decodeAll(t, d, nev); !reflect.DeepEqual(got, []hpackField{{"secret", "s"}}) || len(d.dyn) != 0 {
		t.Fatalf("never indexed: %v", got)
	}
	for name, b := range map[string][]byte{
		"index 0":                {0x80},
		"index past the table":   {0xc0},
		"update after a field":   append([]byte{0x82}, encodeInt(100, 5, 0x20)...),
		"update over the bound":  encodeInt(hpackMaxTable+1, 5, 0x20),
		"string past the block":  {0x40, 0x05, 'a'},
		"integer that never end": {0xff, 0x80, 0x80, 0x80, 0x80, 0x80},
	} {
		if err := newHPACKDecoder().decode(b, func(string, string) {}); !errors.Is(err, ErrHPACK) {
			t.Errorf("%s: err %v, want ErrHPACK", name, err)
		}
	}
}

func FuzzHPACKDecode(f *testing.F) {
	f.Add(unhex(&testing.T{}, "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"))
	f.Add(encodeLiteral("a", "b", true))
	f.Fuzz(func(t *testing.T, b []byte) {
		d := newHPACKDecoder()
		_ = d.decode(b, func(string, string) {})
		if d.size > d.maxSize || d.maxSize > hpackMaxTable {
			t.Fatalf("table size %d over %d", d.size, d.maxSize)
		}
	})
}
