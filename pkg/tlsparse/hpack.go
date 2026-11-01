package tlsparse

import (
	"errors"
	"sync"
)

// HPACK header block decoding (RFC 7541) for the HTTP/2 layer (N-46). Each
// direction of a connection has its own decoder, whose dynamic table must
// see every header block of that direction from the start of the
// connection: a block decoded against a table that missed one is wrong, so
// any error ends the direction.

// ErrHPACK means a header block did not decode: a bad index, integer or
// string, a Huffman code that is not one, a table size update out of place
// or above the bound, or a decoded header list over its bound.
var ErrHPACK = errors.New("tlsparse: malformed HPACK header block")

const (
	// hpackDefaultTable is the dynamic table's size before any update, the
	// initial value of SETTINGS_HEADER_TABLE_SIZE.
	hpackDefaultTable = 4096
	// hpackMaxTable bounds the size an encoder may set; a larger update is
	// refused, since the table is kept in memory.
	hpackMaxTable = 1 << 20
	// hpackMaxList bounds the decoded names and values of one block.
	hpackMaxList = 1 << 20
)

type hpackField struct{ name, value string }

// hpackStatic is the static table (RFC 7541, Appendix A); index 1 is the
// first entry.
var hpackStatic = [...]hpackField{
	{":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"},
	{":path", "/index.html"}, {":scheme", "http"}, {":scheme", "https"}, {":status", "200"},
	{":status", "204"}, {":status", "206"}, {":status", "304"}, {":status", "400"},
	{":status", "404"}, {":status", "500"}, {"accept-charset", ""}, {"accept-encoding", "gzip, deflate"},
	{"accept-language", ""}, {"accept-ranges", ""}, {"accept", ""}, {"access-control-allow-origin", ""},
	{"age", ""}, {"allow", ""}, {"authorization", ""}, {"cache-control", ""},
	{"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""}, {"content-length", ""},
	{"content-location", ""}, {"content-range", ""}, {"content-type", ""}, {"cookie", ""},
	{"date", ""}, {"etag", ""}, {"expect", ""}, {"expires", ""},
	{"from", ""}, {"host", ""}, {"if-match", ""}, {"if-modified-since", ""},
	{"if-none-match", ""}, {"if-range", ""}, {"if-unmodified-since", ""}, {"last-modified", ""},
	{"link", ""}, {"location", ""}, {"max-forwards", ""}, {"proxy-authenticate", ""},
	{"proxy-authorization", ""}, {"range", ""}, {"referer", ""}, {"refresh", ""},
	{"retry-after", ""}, {"server", ""}, {"set-cookie", ""}, {"strict-transport-security", ""},
	{"transfer-encoding", ""}, {"user-agent", ""}, {"vary", ""}, {"via", ""},
	{"www-authenticate", ""},
}

// hpackDecoder holds one direction's dynamic table.
type hpackDecoder struct {
	dyn     []hpackField // oldest first; the newest is index 62
	size    int          // sum of the entries' sizes (name, value and 32)
	maxSize int
}

func newHPACKDecoder() *hpackDecoder {
	return &hpackDecoder{maxSize: hpackDefaultTable}
}

// decode decodes one complete header block, passing each field to emit in
// order. A size update is accepted only before the first field.
func (d *hpackDecoder) decode(block []byte, emit func(name, value string)) error {
	list := 0
	fields := false
	for len(block) > 0 {
		b := block[0]
		var f hpackField
		var err error
		switch {
		case b&0x80 != 0: // indexed field
			var idx uint64
			if idx, block, err = hpackInt(block, 7); err != nil {
				return err
			}
			if f, err = d.at(idx); err != nil {
				return err
			}
		case b&0xc0 == 0x40: // literal with incremental indexing
			if f, block, err = d.literal(block, 6); err != nil {
				return err
			}
			d.add(f)
		case b&0xe0 == 0x20: // dynamic table size update
			if fields {
				return ErrHPACK
			}
			var n uint64
			if n, block, err = hpackInt(block, 5); err != nil {
				return err
			}
			if n > hpackMaxTable {
				return ErrHPACK
			}
			d.maxSize = int(n)
			d.evict(0)
			continue
		default: // literal without indexing (0000) or never indexed (0001)
			if f, block, err = d.literal(block, 4); err != nil {
				return err
			}
		}
		fields = true
		if list += len(f.name) + len(f.value); list > hpackMaxList {
			return ErrHPACK
		}
		emit(f.name, f.value)
	}
	return nil
}

// at returns the field at a static or dynamic index.
func (d *hpackDecoder) at(idx uint64) (hpackField, error) {
	switch {
	case idx == 0:
		return hpackField{}, ErrHPACK
	case idx <= uint64(len(hpackStatic)):
		return hpackStatic[idx-1], nil
	}
	i := idx - uint64(len(hpackStatic)) - 1
	if i >= uint64(len(d.dyn)) {
		return hpackField{}, ErrHPACK
	}
	return d.dyn[len(d.dyn)-1-int(i)], nil
}

// literal reads a literal field whose name index has an n-bit prefix: an
// index, or 0 and a name string; then the value string.
func (d *hpackDecoder) literal(b []byte, n uint) (hpackField, []byte, error) {
	idx, b, err := hpackInt(b, n)
	if err != nil {
		return hpackField{}, nil, err
	}
	var f hpackField
	if idx == 0 {
		if f.name, b, err = hpackString(b); err != nil {
			return hpackField{}, nil, err
		}
	} else {
		named, err := d.at(idx)
		if err != nil {
			return hpackField{}, nil, err
		}
		f.name = named.name
	}
	if f.value, b, err = hpackString(b); err != nil {
		return hpackField{}, nil, err
	}
	return f, b, nil
}

// add inserts f as the newest entry, evicting the oldest ones to make room;
// an entry larger than the table empties it and is not kept (RFC 7541,
// section 4.4).
func (d *hpackDecoder) add(f hpackField) {
	sz := len(f.name) + len(f.value) + 32
	d.evict(sz)
	if sz > d.maxSize {
		return
	}
	d.dyn = append(d.dyn, f)
	d.size += sz
}

// evict removes the oldest entries until room more bytes fit.
func (d *hpackDecoder) evict(room int) {
	n := 0
	for d.size+room > d.maxSize && n < len(d.dyn) {
		d.size -= len(d.dyn[n].name) + len(d.dyn[n].value) + 32
		n++
	}
	if n > 0 {
		d.dyn = append(d.dyn[:0], d.dyn[n:]...)
	}
}

// hpackInt reads an integer with an n-bit prefix (RFC 7541, section 5.1),
// at most 2^32.
func hpackInt(b []byte, n uint) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, nil, ErrHPACK
	}
	mask := uint64(1)<<n - 1
	v := uint64(b[0]) & mask
	b = b[1:]
	if v < mask {
		return v, b, nil
	}
	for shift := uint(0); ; shift += 7 {
		if len(b) == 0 || shift > 28 {
			return 0, nil, ErrHPACK
		}
		c := b[0]
		b = b[1:]
		v += uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			break
		}
	}
	if v > 1<<32 {
		return 0, nil, ErrHPACK
	}
	return v, b, nil
}

// hpackString reads a string literal, Huffman-coded when its first bit is
// set.
func hpackString(b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", nil, ErrHPACK
	}
	huff := b[0]&0x80 != 0
	n, b, err := hpackInt(b, 7)
	if err != nil || n > uint64(len(b)) {
		return "", nil, ErrHPACK
	}
	raw := b[:n]
	b = b[n:]
	if !huff {
		return string(raw), b, nil
	}
	s, err := huffmanDecode(raw)
	if err != nil {
		return "", nil, err
	}
	return s, b, nil
}

// huffNode is a node of the Huffman decoding tree: an inner node's two
// children, or a leaf's symbol.
type huffNode struct {
	child [2]int32 // -1 when absent
	sym   int16    // -1 for an inner node
}

var (
	huffTree     []huffNode
	huffTreeOnce sync.Once
)

func buildHuffTree() {
	huffTree = []huffNode{{child: [2]int32{-1, -1}, sym: -1}}
	for sym := 0; sym < 256; sym++ {
		code, n := huffmanCode[sym], int(huffmanLen[sym])
		at := 0
		for i := n - 1; i >= 0; i-- {
			bit := (code >> uint(i)) & 1
			if huffTree[at].child[bit] < 0 {
				huffTree = append(huffTree, huffNode{child: [2]int32{-1, -1}, sym: -1})
				huffTree[at].child[bit] = int32(len(huffTree) - 1)
			}
			at = int(huffTree[at].child[bit])
		}
		huffTree[at].sym = int16(sym)
	}
}

// huffmanDecode decodes a Huffman-coded string. The padding after the last
// symbol must be at most 7 bits, all ones (a prefix of the end-of-string
// code), and the end-of-string code itself is an error (RFC 7541, section
// 5.2): the tree has no leaf for it.
func huffmanDecode(src []byte) (string, error) {
	huffTreeOnce.Do(buildHuffTree)
	out := make([]byte, 0, len(src)*8/5+1)
	at, depth, ones := 0, 0, true
	for _, c := range src {
		for i := 7; i >= 0; i-- {
			bit := (c >> uint(i)) & 1
			next := huffTree[at].child[bit]
			if next < 0 {
				return "", ErrHPACK
			}
			at = int(next)
			depth++
			ones = ones && bit == 1
			if s := huffTree[at].sym; s >= 0 {
				out = append(out, byte(s))
				at, depth, ones = 0, 0, true
			}
		}
	}
	if depth > 7 || !ones {
		return "", ErrHPACK
	}
	return string(out), nil
}
