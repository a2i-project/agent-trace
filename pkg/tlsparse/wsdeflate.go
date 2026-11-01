package tlsparse

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// permessage-deflate (RFC 7692), the one WebSocket extension the parser
// decodes (N-43). The accept's Sec-WebSocket-Extensions names the agreed
// parameters; a message whose first frame sets RSV1 is the DEFLATE data of
// its whole payload with the trailing 0x00 0x00 0xff 0xff of a sync flush
// removed. Without "no_context_takeover" for a direction, its compressor
// keeps its sliding window across messages, so a message may refer back
// into the earlier messages' bytes: the decoder keeps the last 32 KiB of
// what it decoded as the next message's dictionary. A smaller
// max_window_bits only shortens how far back the sender refers, which a
// 32 KiB dictionary covers.

// Errors of the decompression. ErrWSTooLarge ends a direction whose
// message the parser does not decode (a bound, not a fault of the stream);
// ErrWSInflate one whose data is not valid DEFLATE for the agreed
// parameters.
var (
	ErrWSTooLarge = errors.New("tlsparse: compressed WebSocket message over the decoder's bound")
	ErrWSInflate  = errors.New("tlsparse: WebSocket message did not decompress")
)

// Bounds of the decoder: the compressed bytes of one message are buffered
// until its last frame, and the decoded bytes are streamed through the hash
// and counted.
const (
	maxWSCompressed = 64 << 20
	maxWSInflated   = 256 << 20
	wsWindow        = 32 << 10 // the largest DEFLATE window (max_window_bits 15)
)

// WSDeflate is the permessage-deflate an accept agreed to.
type WSDeflate struct {
	ServerNoContextTakeover bool
	ClientNoContextTakeover bool
	// ServerMaxWindowBits and ClientMaxWindowBits are 8 to 15, 0 when the
	// accept states none.
	ServerMaxWindowBits int
	ClientMaxWindowBits int
}

// WSExtensionError says why an accept's extensions are refused: the
// parser decodes permessage-deflate alone, with the parameters RFC 7692
// defines.
type WSExtensionError struct{ Reason string }

func (e *WSExtensionError) Error() string {
	return "tlsparse: WebSocket extension refused: " + e.Reason
}

var windowBits = regexp.MustCompile(`^(8|9|1[0-5])$`)

// ParseWSExtensions reads the Sec-WebSocket-Extensions of an accept, as
// Response.Extensions holds it (lowercased, "?" for a header too long or
// not printable). It returns nil for no extension, the agreed
// permessage-deflate, or a *WSExtensionError naming what it cannot honour.
func ParseWSExtensions(h string) (*WSDeflate, error) {
	h = strings.TrimSpace(h)
	switch h {
	case "":
		return nil, nil
	case "?":
		return nil, &WSExtensionError{"the extensions header is longer than 128 bytes or not printable"}
	}
	exts := strings.Split(h, ",")
	if len(exts) > 1 {
		return nil, &WSExtensionError{fmt.Sprintf("%d extensions negotiated: %q", len(exts), h)}
	}
	parts := strings.Split(exts[0], ";")
	if name := strings.TrimSpace(parts[0]); name != "permessage-deflate" {
		return nil, &WSExtensionError{fmt.Sprintf("unsupported extension %q", name)}
	}
	d := &WSDeflate{}
	seen := map[string]bool{}
	for _, p := range parts[1:] {
		k, v, hasValue := strings.Cut(strings.TrimSpace(p), "=")
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"`)
		if seen[k] {
			return nil, &WSExtensionError{fmt.Sprintf("permessage-deflate parameter %q stated twice", k)}
		}
		seen[k] = true
		switch k {
		case "server_no_context_takeover", "client_no_context_takeover":
			if hasValue {
				return nil, &WSExtensionError{fmt.Sprintf("permessage-deflate parameter %q with a value", k)}
			}
			if k == "server_no_context_takeover" {
				d.ServerNoContextTakeover = true
			} else {
				d.ClientNoContextTakeover = true
			}
		case "server_max_window_bits", "client_max_window_bits":
			if !hasValue || !windowBits.MatchString(v) {
				return nil, &WSExtensionError{fmt.Sprintf("permessage-deflate parameter %q without a window size of 8 to 15", k)}
			}
			bits := int(v[0] - '0')
			if len(v) == 2 {
				bits = 10 + int(v[1]-'0')
			}
			if k == "server_max_window_bits" {
				d.ServerMaxWindowBits = bits
			} else {
				d.ClientMaxWindowBits = bits
			}
		default:
			return nil, &WSExtensionError{fmt.Sprintf("unsupported permessage-deflate parameter %q", k)}
		}
	}
	return d, nil
}

// wsInflater decodes the compressed messages of one direction.
type wsInflater struct {
	noTakeover bool
	dict       []byte // the last 32 KiB decoded, with context takeover
}

// deflateTail ends a message's DEFLATE data: the removed end of the sync
// flush (RFC 7692, 7.2.2), then an empty final stored block, so the reader
// reaches the end of the stream instead of waiting for more.
var deflateTail = []byte{0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff}

// inflate decodes one message's compressed payload, passing the decoded
// bytes to out in order.
func (z *wsInflater) inflate(data []byte, out func([]byte)) error {
	if len(data) == 0 {
		return nil // an empty message
	}
	src := io.MultiReader(bytes.NewReader(data), bytes.NewReader(deflateTail))
	var r io.ReadCloser
	if !z.noTakeover && len(z.dict) > 0 {
		r = flate.NewReaderDict(src, z.dict)
	} else {
		r = flate.NewReader(src)
	}
	defer func() { _ = r.Close() }()
	buf := make([]byte, wsWindow)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxWSInflated {
				return ErrWSTooLarge
			}
			out(buf[:n])
			if !z.noTakeover {
				z.dict = append(z.dict, buf[:n]...)
				if len(z.dict) > 2*wsWindow {
					z.dict = append(z.dict[:0], z.dict[len(z.dict)-wsWindow:]...)
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrWSInflate
		}
	}
	if len(z.dict) > wsWindow {
		z.dict = append(z.dict[:0], z.dict[len(z.dict)-wsWindow:]...)
	}
	return nil
}
