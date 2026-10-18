package net

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Tests for ClientHellos larger than one capture or split across sends
// (N-31). The unprivileged ones drive handleNetRecord with the records the
// kernel emits; the privileged one sends such hellos from a tracked process.

// bigHello returns a single-record ClientHello for host whose SNI extension
// follows a padding extension of pad bytes, so a pad of 1 KiB or more puts
// the name past byte 1024, where Chrome's extension permutation puts it about
// half the time (N-31). It offers h2 and http/1.1 by ALPN.
func bigHello(host string, pad int) []byte {
	var ext []byte
	ext = append(ext, 0x00, 0x15, byte(pad>>8), byte(pad)) // padding (RFC 7685)
	ext = append(ext, make([]byte, pad)...)
	entry := append([]byte{0x00, byte(len(host) >> 8), byte(len(host))}, host...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	ext = append(ext, 0x00, 0x00, byte(len(list)>>8), byte(len(list))) // server_name
	ext = append(ext, list...)
	alpn := []byte{0x00, 0x0c, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	ext = append(ext, 0x00, 0x10, byte(len(alpn)>>8), byte(len(alpn)))
	ext = append(ext, alpn...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00)             // null compression
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	msg := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

// records re-frames a single-record hello as handshake records of at most
// size payload bytes each.
func records(hello []byte, size int) []byte {
	msg := hello[5:]
	var out []byte
	for len(msg) > 0 {
		n := min(size, len(msg))
		out = append(out, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

// cutTail drops the last bytes of a hello, inside its final (ALPN) extension.
func cutTail(hello []byte) []byte { return hello[:len(hello)-5] }

// helloRec is a NET_HELLO or NET_HELLO_MORE record of socket 1 to
// 10.0.0.53:443 sent at ts, with more set when the kernel follows the hello.
func helloRec(typ uint8, ts uint64, more bool, payload []byte) netRecord {
	r := netRec(typ, 1, 443, sockStream, payload)
	r.hdr.TsNs = ts
	if more {
		r.hdr.Flags = netFlagHelloMore
	}
	return r
}

func TestHandleNetRecord_HelloAcrossSends(t *testing.T) {
	const host = "api.example.com"
	hello := bigHello(host, 1500)
	if i := bytes.Index(hello, []byte(host)); i <= 1024 || len(hello) < 1500 {
		t.Fatalf("hello is %d bytes with SNI at %d, want SNI past 1024", len(hello), i)
	}
	frag := records(hello, 1000)
	connect := netRec(netConnect, 1, 443, sockStream, nil)
	closeAt := func(ts uint64) netRecord { r := netRec(netClose, 1, 443, sockStream, nil); r.hdr.TsNs = ts; return r }
	byName := string(models.NetConnect) + " " + host
	byAddr := string(models.NetConnect) + " 10.0.0.53:443"

	tests := []struct {
		name     string
		recs     []netRecord
		want     string
		at       uint64 // the event's timestamp, in boot nanoseconds
		followed int
	}{
		{"whole in one send", []netRecord{connect, helloRec(netHello, 10, false, hello), closeAt(99)}, byName, 10, 0},
		{"record header sent alone", []netRecord{connect,
			helloRec(netHello, 10, true, hello[:5]),
			helloRec(netHelloMore, 11, false, hello[5:]),
			closeAt(99)}, byName, 10, 1},
		{"three sends", []netRecord{connect,
			helloRec(netHello, 10, true, hello[:700]),
			helloRec(netHelloMore, 11, true, hello[700:1200]),
			helloRec(netHelloMore, 12, false, hello[1200:]),
			closeAt(99)}, byName, 10, 1},
		// A hello over two records: the kernel cannot tell where the second
		// ends and keeps following; userspace stops at the end of the
		// message and ignores what follows.
		{"two records, the kernel follows past the end", []netRecord{connect,
			helloRec(netHello, 10, true, frag[:1005]),
			helloRec(netHelloMore, 11, true, frag[1005:]),
			helloRec(netHelloMore, 12, true, []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}),
			closeAt(99)}, byName, 10, 1},
		// The rest never came: the name is parsed from what did at the
		// close, and the event keeps the hello's time.
		{"rest never sent, name in the first part", []netRecord{connect,
			helloRec(netHello, 10, true, cutTail(bigHello(host, 10))),
			closeAt(99)}, byName, 10, 1},
		{"rest never sent, name in the missing part", []netRecord{connect,
			helloRec(netHello, 10, true, hello[:1000]),
			closeAt(99)}, byAddr, 99, 1},
		// Records from before N-31 carry no flag: a capture cut at 1 KiB
		// parses at once, as before.
		{"cut at 1 KiB without the flag", []netRecord{connect,
			helloRec(netHello, 10, false, hello[:1024]),
			closeAt(99)}, byAddr, 99, 0},
		{"a continuation after the hello is ignored", []netRecord{connect,
			helloRec(netHello, 10, false, hello),
			helloRec(netHelloMore, 11, false, []byte("stray")),
			closeAt(99)}, byName, 10, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Observer{events: make(chan models.GroundTruthEvent, 8), conns: map[uint64]*connection{}}
			for _, r := range tt.recs {
				o.handleNetRecord(r)
			}
			o.flushOpenConnections()
			close(o.events)
			var got []models.GroundTruthEvent
			for e := range o.events {
				got = append(got, e)
			}
			if len(got) != 1 {
				t.Fatalf("got %d events %+v, want one", len(got), got)
			}
			if s := string(got[0].ActionType) + " " + got[0].Target; s != tt.want {
				t.Errorf("event %q, want %q", s, tt.want)
			}
			if want := time.Unix(0, int64(tt.at)); !got[0].Timestamp.Equal(want) {
				t.Errorf("stamped %v, want %v", got[0].Timestamp, want)
			}
			if o.coverage.HellosFollowed != tt.followed {
				t.Errorf("HellosFollowed = %d, want %d", o.coverage.HellosFollowed, tt.followed)
			}
			if wantHost := tt.want == byName; (o.coverage.WithHostname == 1) != wantHost {
				t.Errorf("WithHostname = %d, want a hostname: %v", o.coverage.WithHostname, wantHost)
			}
		})
	}
}

// A hello still being followed at the end of the capture is parsed then.
func TestHandleNetRecord_HelloPendingAtStop(t *testing.T) {
	const host = "pending.example.com"
	o := &Observer{events: make(chan models.GroundTruthEvent, 4), conns: map[uint64]*connection{}}
	o.handleNetRecord(netRec(netConnect, 1, 443, sockStream, nil))
	o.handleNetRecord(helloRec(netHello, 10, true, cutTail(bigHello(host, 10))))
	o.flushOpenConnections()
	close(o.events)
	e := <-o.events
	if e.ActionType != models.NetConnect || e.Target != host || o.coverage.OpenAtStop != 1 {
		t.Errorf("event %s %s, OpenAtStop %d; want net_connect %s, 1", e.ActionType, e.Target, o.coverage.OpenAtStop, host)
	}
}

// TestObserver_LargeAndSplitHellosYieldSNI: a tracked process sends 2 KiB
// ClientHellos whose SNI sits past byte 1024, whole in one send, in pieces
// over several sends, over two records, and across iovecs. Each connection
// is named. A connection that sends an HTTP request is the control: it is
// named by address and not followed.
func TestObserver_LargeAndSplitHellosYieldSNI(t *testing.T) {
	skipUnprivileged(t)

	hosts := []string{"whole.agenttrace-test.internal", "pieces.agenttrace-test.internal",
		"records.agenttrace-test.internal", "iovecs.agenttrace-test.internal"}
	var hellos []string
	for _, h := range hosts {
		hello := bigHello(h, 1800)
		if i := bytes.Index(hello, []byte(h)); i <= 1024 {
			t.Fatalf("SNI of %s at byte %d, want past 1024", h, i)
		}
		hellos = append(hellos, hex.EncodeToString(hello))
	}
	ports := sinks(t, 5)
	obs := startObserver(t)

	pyPID := runPython(t, fmt.Sprintf(`
import os, socket, time
def conn(port):
    s = socket.socket()
    s.connect(("127.0.0.1", port))
    return s
h = [bytes.fromhex(x) for x in %q.split()]
s = conn(%d); s.send(h[0]); s.close()
s = conn(%d)
for a, b in ((0, 5), (5, 900), (900, 1600), (1600, len(h[1]))):
    s.send(h[1][a:b]); time.sleep(0.02)
s.close()
m = h[2][5:]
r1 = b"\x16\x03\x01" + (1000).to_bytes(2, "big") + m[:1000]
r2 = b"\x16\x03\x01" + (len(m) - 1000).to_bytes(2, "big") + m[1000:]
s = conn(%d); s.send(r1); time.sleep(0.02); s.send(r2); s.close()
s = conn(%d); os.writev(s.fileno(), [h[3][:5], h[3][5:1500], h[3][1500:]]); s.close()
s = conn(%d); s.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); s.send(b"more"); s.close()
`, fmt.Sprint(hellos[0], " ", hellos[1], " ", hellos[2], " ", hellos[3]), ports[0], ports[1], ports[2], ports[3], ports[4]))
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs)
	for _, host := range hosts {
		at, pid := typeOf(t, events, host)
		if at != models.NetConnect || pid != pyPID {
			t.Errorf("event for %s is %q from PID %d, want net_connect from %d; events %+v", host, at, pid, pyPID, events)
		}
	}
	control := fmt.Sprintf("127.0.0.1:%d", ports[4])
	if at, _ := typeOf(t, events, control); at != models.NetConnect {
		t.Errorf("control %s is %q, want net_connect by address", control, at)
	}
	if cov := obs.Coverage(); cov.HellosFollowed != 2 {
		t.Errorf("HellosFollowed = %d, want 2 (pieces, records)", cov.HellosFollowed)
	}
}
