package net

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// dnsMsg builds a query message: a header with the given flags and question
// count, then body (the question section as raw bytes).
func dnsMsg(flags, qdcount uint16, body []byte) []byte {
	h := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(h[0:], 0x1234)
	binary.BigEndian.PutUint16(h[2:], flags)
	binary.BigEndian.PutUint16(h[4:], qdcount)
	return append(h, body...)
}

// wireName encodes dotted labels; "" is the root.
func wireName(name string) []byte {
	var b []byte
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	return append(b, 0)
}

func question(name string, qtype, qclass uint16) []byte {
	b := wireName(name)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(b, qtype), qclass)
}

func TestParseDNSQuery(t *testing.T) {
	const rd = 0x0100                                  // recursion desired, what stub resolvers send
	edns := []byte{0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0} // an OPT record after the question
	long63 := strings.Repeat("a", 63)
	tcp := func(m []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(m))), m...) }
	glibcA := dnsMsg(rd, 1, append(question("example.com", 1, 1), edns...))

	// A question whose name is a pointer back to a name in an earlier
	// question: legal compression, in a message with two questions.
	twoQ := dnsMsg(rd, 2, append(question("example.com", 1, 1), 0xc0, 12, 0, 28, 0, 1))
	// A compressed first question: label "www" then a pointer to
	// "example.com" placed in the message before it cannot happen (the
	// question starts right after the header), so a pointer in the first
	// name can only point into the header or forward.
	ptrIntoHeader := dnsMsg(rd, 1, []byte{3, 'w', 'w', 'w', 0xc0, 4, 0, 1, 0, 1})
	ptrForward := dnsMsg(rd, 1, []byte{0xc0, 14, 0, 1, 0, 1, 3, 'c', 'o', 'm', 0})
	ptrSelf := dnsMsg(rd, 1, []byte{0xc0, 12, 0, 1, 0, 1})

	tests := []struct {
		name    string
		b       []byte
		sotype  uint16
		want    string // dnsQuestion.String(), or "" for an error
		wantErr error
	}{
		{"glibc A with EDNS", glibcA, sockDgram, "example.com/A", nil},
		{"AAAA", dnsMsg(rd, 1, question("example.com", 28, 1)), sockDgram, "example.com/AAAA", nil},
		{"unknown type", dnsMsg(rd, 1, question("x.test", 4242, 1)), sockDgram, "x.test/TYPE4242", nil},
		{"chaos class", dnsMsg(0, 1, question("version.bind", 16, 3)), sockDgram, "version.bind/TXT/CH", nil},
		{"odd class", dnsMsg(0, 1, question("x.test", 1, 77)), sockDgram, "x.test/A/CLASS77", nil},
		{"root", dnsMsg(rd, 1, question("", 2, 1)), sockDgram, "./NS", nil},
		{"case kept", dnsMsg(rd, 1, question("ExAmPle.COM", 1, 1)), sockDgram, "ExAmPle.COM/A", nil},
		{"label bytes escaped", dnsMsg(rd, 1, question("a@b/c\\d e\x00.f.g", 16, 1)), sockDgram, `a\064b\047c\092d\032e\000.f.g/TXT`, nil},
		{"dot inside a label", dnsMsg(rd, 1, append([]byte{3, 'a', '.', 'b', 0}, 0, 1, 0, 1)), sockDgram, `a\046b/A`, nil},
		{"63-byte label", dnsMsg(rd, 1, question(long63+".test", 1, 1)), sockDgram, long63 + ".test/A", nil},
		{"tcp framing", tcp(glibcA), sockStream, "example.com/A", nil},
		{"tcp framing with the next message captured", append(tcp(glibcA), tcp(glibcA)...), sockStream, "example.com/A", nil},
		{"unknown socket type, datagram", glibcA, 0, "example.com/A", nil},
		{"unknown socket type, stream", tcp(glibcA), 0, "example.com/A", nil},
		{"second question compressed, first read", twoQ, sockDgram, "example.com/A", nil},

		{"empty", nil, sockDgram, "", errDNSShort},
		{"header only", dnsMsg(rd, 1, nil), sockDgram, "", errDNSShort},
		{"response", dnsMsg(0x8000|rd, 1, question("example.com", 1, 1)), sockDgram, "", errDNSNotQuery},
		{"update opcode", dnsMsg(5<<11, 1, question("example.com", 6, 1)), sockDgram, "", errDNSNotQuery},
		{"no question", dnsMsg(rd, 0, question("example.com", 1, 1)), sockDgram, "", errDNSNoQ},
		{"name runs off the end", dnsMsg(rd, 1, []byte{7, 'e', 'x', 'a'}), sockDgram, "", errDNSShort},
		{"no terminating label", dnsMsg(rd, 1, []byte{3, 'c', 'o', 'm'}), sockDgram, "", errDNSShort},
		{"type cut off", dnsMsg(rd, 1, append(wireName("example.com"), 0, 1)), sockDgram, "", errDNSShort},
		{"64-byte label", dnsMsg(rd, 1, question(long63+"a", 1, 1)), sockDgram, "", errDNSLabel},
		{"extended label type", dnsMsg(rd, 1, []byte{0x41, 0, 0, 1, 0, 1}), sockDgram, "", errDNSLabel},
		{"name over 255 bytes", dnsMsg(rd, 1, question(strings.Repeat(long63+".", 4)+"x", 1, 1)), sockDgram, "", errDNSNameLong},
		{"pointer into the header", ptrIntoHeader, sockDgram, "", errDNSPointer},
		{"forward pointer", ptrForward, sockDgram, "", errDNSPointer},
		{"self pointer", ptrSelf, sockDgram, "", errDNSPointer},
		{"pointer cut off", dnsMsg(rd, 1, []byte{0xc0}), sockDgram, "", errDNSShort},
		{"tcp length below a header", append([]byte{0, 4}, glibcA...), sockStream, "", errDNSTCPLength},
		{"tcp one byte", []byte{0}, sockStream, "", errDNSShort},
		{"datagram read as stream", glibcA, sockStream, "", nil},
		{"binary junk", []byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03junk-junk-junk"), 0, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q, err := parseDNSQuery(tc.b, tc.sotype)
			if tc.want != "" {
				if err != nil {
					t.Fatalf("err = %v, want %q", err, tc.want)
				}
				if got := q.String(); got != tc.want {
					t.Errorf("got %q, want %q", got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("parsed %q from malformed bytes", q.String())
			}
			if tc.wantErr != nil && err != tc.wantErr {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// A compression loop that stays backwards at every hop (a pointer back to a
// label sequence that runs into the same pointer again) is cut by the pointer
// budget, not followed forever.
func TestParseDNSQuery_BackwardLoopIsBounded(t *testing.T) {
	// Second question at offset 12+len(q1): label "a", then a pointer back to
	// that label, which leads to the same pointer again.
	q1 := question("x", 1, 1)
	off := dnsHeaderLen + len(q1)
	body := append(append([]byte{}, q1...), 1, 'a', 0xc0, byte(off))
	msg := dnsMsg(0, 2, body)
	if _, _, err := dnsName(msg, off); err == nil {
		t.Fatal("a pointer loop parsed")
	}
	// A legal backward pointer: the second question names the first's
	// name, and the offset after it is just past the pointer.
	twoQ := dnsMsg(0, 2, append(append([]byte{}, q1...), 0xc0, dnsHeaderLen, 0, 28, 0, 1))
	name, end, err := dnsName(twoQ, off)
	if err != nil || name != "x" || end != off+2 {
		t.Errorf("compressed name = %q, %d, %v; want \"x\", %d", name, end, err, off+2)
	}
}

// Fuzzing the parser on arbitrary bytes must never panic, and anything it
// accepts renders to a single line without the target's separators.
func FuzzParseDNSQuery(f *testing.F) {
	f.Add(dnsMsg(0x0100, 1, question("example.com", 1, 1)), uint16(0))
	f.Add([]byte{0, 12}, uint16(1))
	f.Fuzz(func(t *testing.T, b []byte, sotype uint16) {
		q, err := parseDNSQuery(b, sotype)
		if err != nil {
			return
		}
		if strings.ContainsAny(q.Name, "@/ \n\x00") {
			t.Errorf("name %q holds a separator or control byte", q.Name)
		}
	})
}

func TestDNSTarget(t *testing.T) {
	q := dnsQuestion{Name: "example.com", Type: 28, Class: 1}
	if got := dnsTarget(q, "[::1]:53"); got != "example.com/AAAA@[::1]:53" {
		t.Errorf("target = %q", got)
	}
}

// dnsEvents drives handleNetRecord with records of socket sock and returns
// the emitted events as "type target" lines.
func dnsEvents(t *testing.T, recs ...netRecord) ([]string, *Observer) {
	t.Helper()
	o := &Observer{events: make(chan models.GroundTruthEvent, 32), conns: map[uint64]*connection{}}
	for _, r := range recs {
		o.handleNetRecord(r)
	}
	o.flushOpenConnections()
	close(o.events)
	var got []string
	for e := range o.events {
		if e.PID != 7 {
			t.Errorf("%s %s has PID %d, want 7", e.ActionType, e.Target, e.PID)
		}
		got = append(got, string(e.ActionType)+" "+e.Target)
	}
	return got, o
}

func netRec(typ uint8, sock uint64, port uint16, sotype uint16, payload []byte) netRecord {
	return netRecord{
		hdr:     bpfNetEventHdr{Type: typ, Tgid: 7, Fd: 3, Sock: sock, Family: afInet, Addr: [16]byte{10, 0, 0, 53}, Port: port, Sotype: sotype, TsNs: 1},
		payload: payload,
	}
}

// A DNS query on a connected port-53 socket is a net_dns event that names
// the question and the resolver, one per datagram; the close adds nothing
// (N-27).
func TestHandleNetRecord_DNSQueriesCarryTheirQuestion(t *testing.T) {
	qa := dnsMsg(0x0100, 1, question("example.com", 1, 1))
	qaaaa := dnsMsg(0x0100, 1, question("example.com", 28, 1))
	tcpq := append([]byte{0, byte(len(qa))}, qa...)
	tests := []struct {
		name string
		recs []netRecord
		want []string
	}{
		{"udp, two queries", []netRecord{
			netRec(netConnect, 1, 53, sockDgram, nil),
			netRec(netHello, 1, 53, sockDgram, qa),
			netRec(netHello, 1, 53, sockDgram, qaaaa),
			netRec(netClose, 1, 53, sockDgram, nil),
		}, []string{"net_dns example.com/A@10.0.0.53:53", "net_dns example.com/AAAA@10.0.0.53:53"}},
		{"tcp with length prefix", []netRecord{
			netRec(netConnect, 2, 53, sockStream, nil),
			netRec(netHello, 2, 53, sockStream, tcpq),
			netRec(netClose, 2, 53, sockStream, nil),
		}, []string{"net_dns example.com/A@10.0.0.53:53"}},
		{"unparsed then parsed", []netRecord{
			netRec(netConnect, 3, 53, sockDgram, nil),
			netRec(netHello, 3, 53, sockDgram, []byte("not dns")),
			netRec(netHello, 3, 53, sockDgram, qa),
			netRec(netClose, 3, 53, sockDgram, nil),
		}, []string{"net_dns example.com/A@10.0.0.53:53"}},
		{"nothing parsed: the resolver alone at the close", []netRecord{
			netRec(netConnect, 4, 53, sockDgram, nil),
			netRec(netHello, 4, 53, sockDgram, []byte("not dns")),
			netRec(netClose, 4, 53, sockDgram, nil),
		}, []string{"net_dns 10.0.0.53:53"}},
		{"a faulted read: the resolver alone", []netRecord{
			netRec(netConnect, 5, 53, sockDgram, nil),
			netRec(netSend, 5, 53, sockDgram, nil),
			netRec(netClose, 5, 53, sockDgram, nil),
		}, []string{"net_dns 10.0.0.53:53"}},
		// Go's address selection connects a datagram socket to port 53 of
		// each candidate address and sends nothing: a dial, not DNS.
		{"nothing sent: a dial", []netRecord{
			netRec(netConnect, 6, 53, sockDgram, nil),
			netRec(netClose, 6, 53, sockDgram, nil),
		}, []string{"net_dial 10.0.0.53:53"}},
		{"a record from before N-27 (no socket type)", []netRecord{
			netRec(netConnect, 7, 53, 0, nil),
			netRec(netHello, 7, 53, 0, tcpq),
		}, []string{"net_dns example.com/A@10.0.0.53:53"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := dnsEvents(t, tc.recs...)
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("emitted\n  %v\nwant\n  %v", got, tc.want)
			}
		})
	}
}

// A datagram sent to an explicit address is the connection a connect() to
// that address followed by the send would be (N-28): to port 53 a net_dns
// event per datagram, with its question when it parses; to another port a
// net_connect by address, once per socket and destination, whatever the
// kernel repeats; port 0 is not address selection here, since bytes went.
func TestHandleNetRecord_AddressedDatagrams(t *testing.T) {
	qa := dnsMsg(0x0100, 1, question("a.example", 1, 1))
	qb := dnsMsg(0x0100, 1, question("b.example", 16, 1))
	got, o := dnsEvents(t,
		netRec(netDgram, 1, 53, sockDgram, qa),
		netRec(netDgram, 1, 53, sockDgram, qb),
		netRec(netDgram, 1, 53, sockDgram, []byte("junk")),
		netRec(netDgram, 1, 443, sockDgram, []byte("quic")),
		netRec(netDgram, 1, 443, sockDgram, []byte("quic")), // an LRU eviction repeated it
		netRec(netDgram, 2, 443, sockDgram, []byte("quic")), // another socket
		netRec(netDgram, 2, 0, 3, nil),                      // a raw socket, empty datagram
	)
	want := []string{
		"net_dns a.example/A@10.0.0.53:53",
		"net_dns b.example/TXT@10.0.0.53:53",
		"net_dns 10.0.0.53:53",
		"net_connect 10.0.0.53:443",
		"net_connect 10.0.0.53:443",
		"net_connect 10.0.0.53:0",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("emitted\n  %v\nwant\n  %v", got, want)
	}
	c := o.coverage
	if c.DNS != 3 || c.DNSNamed != 2 || c.DNSUnparsed != 1 || c.Datagrams != 6 || c.AddressProbes != 0 || c.Connections != 0 {
		t.Errorf("coverage = %+v", c)
	}
}
