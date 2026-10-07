package gemini

import (
	"errors"
	"fmt"
)

// The step payload is protobuf and no .proto is available, so fields are read
// by number with a wire-format walker. The numbers were read off real
// conversations and are version-sensitive by construction: every lookup that
// must find a field returns an error naming the path when it does not, so a
// version that moves a field fails loudly and never yields an empty
// trajectory (docs/architecture/30_agent_adapters.md).

type wireType uint8

const (
	wireVarint  wireType = 0
	wireFixed64 wireType = 1
	wireBytes   wireType = 2
	wireFixed32 wireType = 5
)

type field struct {
	num  int
	wire wireType
	// u is the value of a varint or fixed field, b the bytes of a length
	// delimited one.
	u uint64
	b []byte
}

var errTruncated = errors.New("truncated protobuf")

func readVarint(b []byte) (v uint64, n int, err error) {
	var shift uint
	for i := 0; i < len(b); i++ {
		if i == 10 {
			return 0, 0, errors.New("varint longer than 10 bytes")
		}
		c := b[i]
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, errTruncated
}

// fields decodes every top-level field of a message. It fails on malformed
// data rather than returning a partial list.
func fields(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		key, n, err := readVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		f := field{num: int(key >> 3), wire: wireType(key & 7)}
		if f.num == 0 {
			return nil, errors.New("field number 0")
		}
		switch f.wire {
		case wireVarint:
			v, n, err := readVarint(b)
			if err != nil {
				return nil, err
			}
			f.u, b = v, b[n:]
		case wireFixed64:
			if len(b) < 8 {
				return nil, errTruncated
			}
			for i := 7; i >= 0; i-- {
				f.u = f.u<<8 | uint64(b[i])
			}
			b = b[8:]
		case wireFixed32:
			if len(b) < 4 {
				return nil, errTruncated
			}
			for i := 3; i >= 0; i-- {
				f.u = f.u<<8 | uint64(b[i])
			}
			b = b[4:]
		case wireBytes:
			l, n, err := readVarint(b)
			if err != nil {
				return nil, err
			}
			b = b[n:]
			if uint64(len(b)) < l {
				return nil, errTruncated
			}
			f.b, b = b[:l], b[l:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out, nil
}

// pathError says which field was missing.
type pathError struct {
	path []int
	why  string
}

func (e *pathError) Error() string {
	s := ""
	for i, n := range e.path {
		if i > 0 {
			s += "."
		}
		s += fmt.Sprint(n)
	}
	return fmt.Sprintf("field %s: %s", s, e.why)
}

// submessages returns every length-delimited field at path, descending through
// repeated and nested messages. A missing field yields none and no error: the
// caller decides whether absence is acceptable, which is how a step with no
// tool call differs from a step whose layout changed.
func submessages(b []byte, path ...int) ([][]byte, error) {
	cur := [][]byte{b}
	for depth, num := range path {
		var next [][]byte
		for _, m := range cur {
			fs, err := fields(m)
			if err != nil {
				return nil, &pathError{path: path[:depth], why: err.Error()}
			}
			for _, f := range fs {
				if f.num == num && f.wire == wireBytes {
					next = append(next, f.b)
				}
			}
		}
		cur = next
	}
	return cur, nil
}

// bytesField returns the first length-delimited field numbered num in a message.
func bytesField(m []byte, num int) ([]byte, bool, error) {
	fs, err := fields(m)
	if err != nil {
		return nil, false, err
	}
	for _, f := range fs {
		if f.num == num && f.wire == wireBytes {
			return f.b, true, nil
		}
	}
	return nil, false, nil
}

// timestampField reads a google.protobuf.Timestamp-shaped submessage (seconds
// as field 1, nanos as field 2) at path.
func timestampAt(b []byte, path ...int) (sec, nanos int64, found bool, err error) {
	subs, err := submessages(b, path...)
	if err != nil || len(subs) == 0 {
		return 0, 0, false, err
	}
	fs, err := fields(subs[0])
	if err != nil {
		return 0, 0, false, &pathError{path: path, why: err.Error()}
	}
	for _, f := range fs {
		if f.wire != wireVarint {
			continue
		}
		switch f.num {
		case 1:
			sec, found = int64(f.u), true
		case 2:
			nanos = int64(f.u)
		}
	}
	return sec, nanos, found, nil
}
