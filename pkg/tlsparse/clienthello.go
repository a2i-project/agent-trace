// Package tlsparse parses TLS ClientHello records and HTTP/1.1 requests from
// captured plaintext. It is pure Go with no eBPF and no syscalls, so its
// tests run unprivileged; it exists to be called from pkg/probe/net's
// correlator, which owns all kernel interaction.
package tlsparse

import "errors"

// ErrNotClientHello means the input is not a TLS handshake record carrying a
// ClientHello -- wrong content type, or a handshake message type other than
// client_hello (1). The correlator should mark the connection non-TLS and
// move on; this is not a transient condition that more bytes would fix.
var ErrNotClientHello = errors.New("tlsparse: not a TLS ClientHello")

// ErrTruncated means the input looks like the start of a ClientHello but
// ends before the mandatory fixed-size fields (through the compression
// methods list) are fully present. Unlike ErrNotClientHello, this can be a
// capture artifact: a capture that stopped early. Truncation inside the
// extensions block is not an error at all; see the doc comment on
// ParseClientHello.
var ErrTruncated = errors.New("tlsparse: truncated ClientHello")

// ClientHello holds the fields this package extracts from a ClientHello.
// Everything else in the message (cipher suites, key shares, supported
// groups, ...) is parsed only far enough to skip past it.
type ClientHello struct {
	// ServerName is the SNI host_name entry, if present. Empty otherwise.
	ServerName string
	// ALPN is the client's offered protocol list, in offered order (e.g.
	// ["h2", "http/1.1"]). Empty when the extension is absent.
	ALPN []string
}

// ParseClientHello extracts the SNI hostname and ALPN protocol list from the
// first bytes a client sent on a connection.
//
// The ClientHello is read from the handshake records at the start of data,
// joined: a ClientHello larger than one record, or one a client fragments on
// purpose, spans several (N-31). Joining stops at the end of data, at a
// record that is not a handshake record, or once the message is complete.
//
// The fixed-size ClientHello prefix (legacy version, random, session ID,
// cipher suites, compression methods) must be fully present or this returns
// ErrTruncated: that prefix is a few dozen bytes and any real capture should
// contain it whole. The extensions block that follows has no such guarantee:
// a capture that stopped early can cut it off mid-extension. Truncation there
// is therefore not an error: parsing stops at the first incomplete extension
// and returns whatever was found in the extensions read so far.
func ParseClientHello(data []byte) (ClientHello, error) {
	msg, _, err := handshakeMessage(data)
	if err != nil {
		return ClientHello{}, err
	}
	c := &cursor{buf: msg}

	msgType, err := c.u8()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if msgType != handshakeTypeClientHello {
		return ClientHello{}, ErrNotClientHello
	}
	if _, err := c.u24(); err != nil { // handshake body length; handshakeMessage already bounded msg by it
		return ClientHello{}, ErrTruncated
	}

	if _, err := c.u16(); err != nil { // legacy client version
		return ClientHello{}, ErrTruncated
	}
	if _, err := c.bytes(32); err != nil { // random
		return ClientHello{}, ErrTruncated
	}
	sessionIDLen, err := c.u8()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if _, err := c.bytes(int(sessionIDLen)); err != nil {
		return ClientHello{}, ErrTruncated
	}
	cipherSuitesLen, err := c.u16()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if _, err := c.bytes(int(cipherSuitesLen)); err != nil {
		return ClientHello{}, ErrTruncated
	}
	compressionLen, err := c.u8()
	if err != nil {
		return ClientHello{}, ErrTruncated
	}
	if _, err := c.bytes(int(compressionLen)); err != nil {
		return ClientHello{}, ErrTruncated
	}

	var hello ClientHello

	// Everything from here on is best-effort: absence or truncation is not
	// an error, per the doc comment above.
	extensionsLen, err := c.u16()
	if err != nil {
		return hello, nil
	}

	remaining := int(extensionsLen)
	for remaining >= 4 && c.remaining() >= 4 {
		extType, err := c.u16()
		if err != nil {
			break
		}
		extLen, err := c.u16()
		if err != nil {
			break
		}
		remaining -= 4
		extData, err := c.bytes(int(extLen))
		if err != nil {
			break
		}
		remaining -= int(extLen)

		switch extType {
		case extTypeSNI:
			if name, ok := parseSNIExtension(extData); ok {
				hello.ServerName = name
			}
		case extTypeALPN:
			hello.ALPN = parseALPNExtension(extData)
		}
	}

	return hello, nil
}

// ClientHelloComplete reports whether data holds a whole ClientHello: the
// handshake records at its start carry the complete first handshake message.
// It is false for bytes that are not a TLS handshake record at all.
func ClientHelloComplete(data []byte) bool {
	_, complete, err := handshakeMessage(data)
	return err == nil && complete
}

// handshakeMessage joins the payloads of the handshake records at the start
// of data and returns the first handshake message, cut to its stated length
// when complete, else as much of it as data holds. The record version's major
// byte must be 3 (a ClientHello record commonly carries 0x0301 whatever
// version is negotiated, so nothing stricter is checked).
func handshakeMessage(data []byte) (msg []byte, complete bool, err error) {
	if len(data) < 1 {
		return nil, false, ErrTruncated
	}
	if data[0] != recordTypeHandshake {
		return nil, false, ErrNotClientHello
	}
	if len(data) < 3 {
		return nil, false, ErrTruncated
	}
	if data[1] != 3 {
		return nil, false, ErrNotClientHello
	}
	if len(data) < recordHeaderLen {
		return nil, false, ErrTruncated
	}
	for pos := 0; pos+recordHeaderLen <= len(data); {
		if data[pos] != recordTypeHandshake || data[pos+1] != 3 {
			break
		}
		n := int(data[pos+3])<<8 | int(data[pos+4])
		end := pos + recordHeaderLen + n
		whole := end <= len(data)
		if !whole {
			end = len(data)
		}
		if msg == nil && whole && end == len(data) {
			msg = data[pos+recordHeaderLen : end : end] // one record: no copy
		} else {
			msg = append(msg, data[pos+recordHeaderLen:end]...)
		}
		if len(msg) >= 4 {
			if want := 4 + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])); len(msg) >= want {
				return msg[:want], true, nil
			}
		}
		if !whole {
			break
		}
		pos = end
	}
	return msg, false, nil
}

const (
	recordHeaderLen          = 5
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	extTypeSNI               = 0x0000
	extTypeALPN              = 0x0010
	sniNameTypeHostName      = 0x00
)

// parseSNIExtension extracts the first host_name entry from a
// server_name_list extension body. Returns ok=false on any malformed input
// rather than an error: a broken SNI extension should not fail the whole
// ClientHello parse.
func parseSNIExtension(data []byte) (string, bool) {
	c := &cursor{buf: data}
	listLen, err := c.u16()
	if err != nil {
		return "", false
	}
	end := int(listLen)
	if end > len(data)-2 {
		end = len(data) - 2
	}
	for c.pos < 2+end {
		nameType, err := c.u8()
		if err != nil {
			return "", false
		}
		nameLen, err := c.u16()
		if err != nil {
			return "", false
		}
		name, err := c.bytes(int(nameLen))
		if err != nil {
			return "", false
		}
		if nameType == sniNameTypeHostName {
			return string(name), true
		}
	}
	return "", false
}

// parseALPNExtension extracts the protocol_name_list from an ALPN extension
// body, in offered order. A malformed entry stops iteration and returns
// whatever was parsed so far rather than erroring.
func parseALPNExtension(data []byte) []string {
	c := &cursor{buf: data}
	if _, err := c.u16(); err != nil { // protocol_name_list length, unused: bounded by data itself
		return nil
	}
	var protos []string
	for c.remaining() > 0 {
		n, err := c.u8()
		if err != nil {
			break
		}
		name, err := c.bytes(int(n))
		if err != nil {
			break
		}
		protos = append(protos, string(name))
	}
	return protos
}

// cursor is a bounds-checked reader over a byte slice.
type cursor struct {
	buf []byte
	pos int
}

func (c *cursor) remaining() int {
	return len(c.buf) - c.pos
}

func (c *cursor) bytes(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, errShortRead
	}
	b := c.buf[c.pos : c.pos+n]
	c.pos += n
	return b, nil
}

func (c *cursor) u8() (uint8, error) {
	b, err := c.bytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) u16() (uint16, error) {
	b, err := c.bytes(2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (c *cursor) u24() (uint32, error) {
	b, err := c.bytes(3)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
}

var errShortRead = errors.New("tlsparse: short read")
