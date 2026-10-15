package net

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// DNS question parsing for net_dns targets (N-27). The bytes come from a
// tracked process, so they are parsed defensively: every read is bounded by
// the captured prefix, a compression pointer may only point backwards into
// the message, the number of pointers followed and the name length are
// capped, and anything that does not parse is counted by the caller, never
// trusted.

const (
	dnsHeaderLen   = 12
	dnsMaxName     = 255 // wire length of a name, RFC 1035 section 2.3.4
	dnsMaxLabel    = 63
	dnsMaxPointers = 16
	sockStream     = 1 // SOCK_STREAM, as net.bpf.c reports it
	sockDgram      = 2 // SOCK_DGRAM
)

var (
	errDNSShort     = errors.New("dns: message too short")
	errDNSNotQuery  = errors.New("dns: not a standard query")
	errDNSNoQ       = errors.New("dns: no question")
	errDNSLabel     = errors.New("dns: bad label")
	errDNSPointer   = errors.New("dns: bad compression pointer")
	errDNSNameLong  = errors.New("dns: name too long")
	errDNSTCPLength = errors.New("dns: bad TCP length prefix")
)

// dnsQuestion is the first question of a DNS query.
type dnsQuestion struct {
	Name  string // presentation form, see dnsName
	Type  uint16
	Class uint16
}

// String renders the question as it appears in a net_dns target, before the
// "@resolver" suffix: "<name>/<type>", with "/<class>" appended when the
// class is not IN.
func (q dnsQuestion) String() string {
	s := q.Name + "/" + dnsTypeName(q.Type)
	if q.Class != 1 {
		s += "/" + dnsClassName(q.Class)
	}
	return s
}

// parseDNSQuery parses the first question of a DNS query message. stream
// says the bytes were sent on a stream socket, where every message carries a
// two-byte length prefix (RFC 1035 section 4.2.2). When the socket type is
// unknown (0) the message is tried as a datagram first, then as a stream.
// The message may be cut short by the probe's capture: only the header and
// the first question must be present.
func parseDNSQuery(b []byte, sotype uint16) (dnsQuestion, error) {
	switch sotype {
	case sockStream:
		return parseDNSStream(b)
	case sockDgram:
		return parseDNSMessage(b)
	}
	q, err := parseDNSMessage(b)
	if err == nil {
		return q, nil
	}
	if q2, err2 := parseDNSStream(b); err2 == nil {
		return q2, nil
	}
	return dnsQuestion{}, err
}

func parseDNSStream(b []byte) (dnsQuestion, error) {
	if len(b) < 2 {
		return dnsQuestion{}, errDNSShort
	}
	n := int(binary.BigEndian.Uint16(b))
	if n < dnsHeaderLen {
		return dnsQuestion{}, errDNSTCPLength
	}
	msg := b[2:]
	if len(msg) > n {
		msg = msg[:n] // the capture may hold the start of the next message
	}
	return parseDNSMessage(msg)
}

func parseDNSMessage(msg []byte) (dnsQuestion, error) {
	if len(msg) < dnsHeaderLen {
		return dnsQuestion{}, errDNSShort
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 != 0 || (flags>>11)&0xf != 0 {
		return dnsQuestion{}, errDNSNotQuery // a response, or an opcode other than QUERY
	}
	if binary.BigEndian.Uint16(msg[4:]) == 0 {
		return dnsQuestion{}, errDNSNoQ
	}
	name, end, err := dnsName(msg, dnsHeaderLen)
	if err != nil {
		return dnsQuestion{}, err
	}
	if end+4 > len(msg) {
		return dnsQuestion{}, errDNSShort
	}
	return dnsQuestion{
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[end:]),
		Class: binary.BigEndian.Uint16(msg[end+2:]),
	}, nil
}

// dnsName reads the name starting at off and returns its presentation form
// and the offset just past it in the message (past the first pointer, if the
// name is compressed). Label bytes other than letters, digits, '-' and '_'
// are written as \DDD (RFC 1035 section 5.1), so the result never contains
// '.', '/', '@', '\' or a non-printable byte except as separator or escape,
// and the target it ends up in stays one unambiguous line. The root name is
// ".".
func dnsName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1
	wire := 0
	pointers := 0
	for {
		if off >= len(msg) {
			return "", 0, errDNSShort
		}
		l := int(msg[off])
		switch l & 0xc0 {
		case 0xc0:
			if off+1 >= len(msg) {
				return "", 0, errDNSShort
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
			// A pointer must point backwards, and not into the header: a
			// forward or self pointer could loop, and the header holds no
			// name.
			if ptr >= off || ptr < dnsHeaderLen {
				return "", 0, errDNSPointer
			}
			pointers++
			if pointers > dnsMaxPointers {
				return "", 0, errDNSPointer
			}
			if end < 0 {
				end = off + 2
			}
			off = ptr
			continue
		case 0x40, 0x80:
			return "", 0, errDNSLabel // extended or reserved label types
		}
		wire += l + 1
		if wire > dnsMaxName {
			return "", 0, errDNSNameLong
		}
		if l == 0 {
			if end < 0 {
				end = off + 1
			}
			break
		}
		if l > dnsMaxLabel {
			return "", 0, errDNSLabel
		}
		if off+1+l > len(msg) {
			return "", 0, errDNSShort
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range msg[off+1 : off+1+l] {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				sb.WriteByte(c)
				continue
			}
			sb.WriteByte('\\')
			d := strconv.Itoa(int(c))
			sb.WriteString(strings.Repeat("0", 3-len(d)))
			sb.WriteString(d)
		}
		off += 1 + l
	}
	if sb.Len() == 0 {
		return ".", end, nil
	}
	return sb.String(), end, nil
}

var dnsTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
	16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY",
	64: "SVCB", 65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY",
	257: "CAA",
}

// dnsTypeName is the mnemonic of a query type, or TYPE<n> (RFC 3597).
func dnsTypeName(t uint16) string {
	if s, ok := dnsTypes[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// dnsClassName is the mnemonic of a query class, or CLASS<n> (RFC 3597).
func dnsClassName(c uint16) string {
	switch c {
	case 1:
		return "IN"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 255:
		return "ANY"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// dnsTarget is the target of a net_dns event that carries its question:
// "<name>/<type>[/<class>]@<resolver ip:port>". A net_dns event without a
// question (an older capture, or bytes that did not parse) has the bare
// resolver address as target.
func dnsTarget(q dnsQuestion, resolver string) string {
	return q.String() + "@" + resolver
}
