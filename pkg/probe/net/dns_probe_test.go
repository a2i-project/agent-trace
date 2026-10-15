package net

import (
	"context"
	"fmt"
	stdnet "net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Privileged tests for DNS questions on net_dns (N-27) and addressed
// datagrams (N-28). They send to 127.0.0.1, where nothing need listen on
// port 53: the probe records a send at syscall entry, and an unanswered
// datagram is still sent.

// pyDNS is a Python helper that builds a DNS query for a name and type.
const pyDNS = `
import socket, struct
def q(name, qtype, ident=0x1234):
    b = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        b += bytes([len(label)]) + label.encode()
    return b + b"\0" + struct.pack(">HH", qtype, 1)
def tx(f, *a):
    # A refusal from an earlier datagram (ICMP port unreachable) surfaces on
    # the next send of a connected socket; the send was still entered.
    try:
        f(*a)
    except OSError:
        pass
`

// targetsOf returns the targets of the events of type at from pid.
func targetsOf(events []models.GroundTruthEvent, at models.ActionType, pid uint32) []string {
	var out []string
	for _, e := range events {
		if e.ActionType == at && e.PID == pid {
			out = append(out, e.Target)
		}
	}
	return out
}

// TestObserver_DNSQuestionsAreRecorded: a process that sends DNS queries
// through each send path the measured resolvers use (send on a connected
// socket, as c-ares and gethostbyname do with sendto and no address;
// sendmsg, as dig and host do; sendmmsg, as glibc's getaddrinfo does;
// write, as Go and busybox do; an addressed sendto, as musl does; TCP with
// its length prefix) yields one net_dns event per query that names it, and
// a datagram socket connected to port 53 that sends nothing, as Go's address
// selection does, is a net_dial.
func TestObserver_DNSQuestionsAreRecorded(t *testing.T) {
	skipUnprivileged(t)

	// A TCP listener on 127.0.0.1:53 lets the TCP query connect. Port 53 may
	// be taken (a local resolver on the loopback); the TCP case is then
	// skipped, not failed.
	tcpOK := true
	ln, err := stdnet.Listen("tcp4", "127.0.0.1:53")
	if err != nil {
		t.Logf("no TCP listener on 127.0.0.1:53 (%v): the TCP query is not checked", err)
		tcpOK = false
	} else {
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	// A UDP sink on the same address keeps the kernel from refusing the
	// datagrams; when the port is taken, the refusals are tolerated (tx).
	if pc, err := stdnet.ListenPacket("udp4", "127.0.0.1:53"); err == nil {
		t.Cleanup(func() { _ = pc.Close() })
	}

	obs := startObserver(t)
	pyPID := runPython(t, pyDNS+fmt.Sprintf(`
import os
R = ("127.0.0.1", 53)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(R)
tx(s.send, q("send.dns.test", 1))
tx(s.sendmsg, [q("sendmsg.dns.test", 28)])
tx(os.write, s.fileno(), q("write.dns.test", 16))
s.close()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tx(s.sendto, q("unconnected-1.dns.test", 1), R)
tx(s.sendto, q("unconnected-2.dns.test", 1), R)
tx(s.sendmsg, [q("sendmsg-addressed.dns.test", 1)], [], 0, R)
s.close()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(R)  # Go's address selection: connected, nothing sent
s.close()
if %t:
    t = socket.create_connection(R)
    m = q("tcp.dns.test", 1)
    t.sendall(struct.pack(">H", len(m)) + m)
    t.close()
`, tcpOK))

	// sendmmsg has no Python binding: a C-like call through ctypes would
	// work, but glibc's getaddrinfo is the real user, checked in
	// TestObserver_GetaddrinfoQuestionIsRecorded.
	time.Sleep(300 * time.Millisecond)
	events := drainEvents(t, obs)

	got := targetsOf(events, models.NetDNS, pyPID)
	want := []string{
		"send.dns.test/A@127.0.0.1:53",
		"sendmsg.dns.test/AAAA@127.0.0.1:53",
		"write.dns.test/TXT@127.0.0.1:53",
		"unconnected-1.dns.test/A@127.0.0.1:53",
		"unconnected-2.dns.test/A@127.0.0.1:53",
		"sendmsg-addressed.dns.test/A@127.0.0.1:53",
	}
	if tcpOK {
		want = append(want, "tcp.dns.test/A@127.0.0.1:53")
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("no net_dns %s; net_dns events of the sender: %v", w, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d net_dns events, want %d: %v", len(got), len(want), got)
	}
	if dials := targetsOf(events, models.NetDial, pyPID); !contains(dials, "127.0.0.1:53") {
		t.Errorf("the connected port-53 socket that sent nothing is not a net_dial: dials %v", dials)
	}
	cov := obs.Coverage()
	if cov.DNSNamed < len(want) || cov.DNSUnparsed != 0 {
		t.Errorf("coverage DNSNamed=%d DNSUnparsed=%d, want at least %d and 0", cov.DNSNamed, cov.DNSUnparsed, len(want))
	}
}

// TestObserver_GetaddrinfoQuestionIsRecorded: a lookup through glibc's
// getaddrinfo, which sends its A and AAAA queries in one sendmmsg on a
// connected socket, yields a net_dns event naming the A query. It skips when
// the system resolver is not reached over port 53 (nss-resolve, or no
// nameserver in /etc/resolv.conf).
func TestObserver_GetaddrinfoQuestionIsRecorded(t *testing.T) {
	skipUnprivileged(t)
	if !resolverOnPort53(t) {
		t.Skip("the system resolver is not reached over port 53 here")
	}
	name := fmt.Sprintf("agent-trace-probe-%d.example.com", os.Getpid())

	obs := startObserver(t)
	pyPID := runPython(t, fmt.Sprintf(`
import socket
try:
    socket.getaddrinfo(%q, 443)
except OSError:
    pass
`, name))
	time.Sleep(300 * time.Millisecond)
	events := drainEvents(t, obs)

	got := targetsOf(events, models.NetDNS, pyPID)
	found := false
	for _, g := range got {
		if strings.HasPrefix(g, name+"/A@") || strings.HasPrefix(g, name+"/AAAA@") {
			found = true
		}
	}
	if !found {
		t.Errorf("no net_dns event names %s; net_dns events of the sender: %v", name, got)
	}
}

// TestObserver_DigAndHostQuestionsAreRecorded runs dig and host, when
// installed, against 127.0.0.1, where nothing need answer, and expects the
// name each asked for.
func TestObserver_DigAndHostQuestionsAreRecorded(t *testing.T) {
	skipUnprivileged(t)
	tools := map[string][]string{
		"dig":  {"+tries=1", "+time=1", "@127.0.0.1", "dig.dns.test", "A"},
		"host": {"-W", "1", "-t", "A", "host.dns.test", "127.0.0.1"},
	}
	for tool, args := range tools {
		t.Run(tool, func(t *testing.T) {
			path, err := exec.LookPath(tool)
			if err != nil {
				t.Skipf("%s not installed", tool)
			}
			obs := startObserver(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, path, args...)
			_ = cmd.Start()
			pid := uint32(0)
			if cmd.Process != nil {
				pid = uint32(cmd.Process.Pid)
			}
			_ = cmd.Wait() // no answer is expected; only the query matters
			time.Sleep(300 * time.Millisecond)
			events := drainEvents(t, obs)
			name := tool + ".dns.test/A@127.0.0.1:53"
			var all []string
			for _, e := range events {
				if e.ActionType == models.NetDNS {
					all = append(all, e.Target)
				}
			}
			if !contains(all, name) {
				t.Errorf("no net_dns %s from %s (pid %d); net_dns events: %v", name, tool, pid, all)
			}
		})
	}
}

// TestObserver_AddressedDatagramsAreConnections: datagrams sent with an
// address on an unconnected socket are net_connect events by address, one
// per socket and destination however many datagrams go there (N-28). A
// datagram socket connected to a port and closed without a send is the
// control and stays a net_dial (N-22).
func TestObserver_AddressedDatagramsAreConnections(t *testing.T) {
	skipUnprivileged(t)
	ports := []int{freeUDPPort(t), freeUDPPort(t), freeUDPPort(t)}

	obs := startObserver(t)
	pyPID := runPython(t, fmt.Sprintf(`
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(5):
    s.sendto(b"chunk %%d" %% i, ("127.0.0.1", %d))
s.sendmsg([b"by sendmsg"], [], 0, ("127.0.0.1", %d))
s.close()
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.connect(("127.0.0.1", %d))
c.close()
`, ports[0], ports[1], ports[2]))
	time.Sleep(300 * time.Millisecond)
	events := drainEvents(t, obs)

	expectTypes(t, events, pyPID,
		map[int]models.ActionType{ports[0]: models.NetConnect, ports[1]: models.NetConnect, ports[2]: models.NetDial},
		map[int]string{ports[0]: "five sendto to one address", ports[1]: "sendmsg with an address", ports[2]: "connected, nothing sent"})
	if n := obs.Coverage().Datagrams; n != 2 {
		t.Errorf("Datagrams = %d, want 2 (one per destination)", n)
	}
}

// freeUDPPort returns a UDP port that was free a moment ago on 127.0.0.1.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().(*stdnet.UDPAddr).Port
}

// resolverOnPort53 reports whether glibc's lookups go to a nameserver over
// port 53: /etc/nsswitch.conf names dns for hosts before any resolve
// module, and /etc/resolv.conf names a nameserver.
func resolverOnPort53(t *testing.T) bool {
	t.Helper()
	ns, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return false
	}
	hostsDNS := false
	for _, line := range strings.Split(string(ns), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "hosts:" {
			continue
		}
		for _, m := range f[1:] {
			if m == "resolve" {
				return false
			}
			if m == "dns" {
				hostsDNS = true
				break
			}
		}
	}
	rc, err := os.ReadFile("/etc/resolv.conf")
	return hostsDNS && err == nil && strings.Contains(string(rc), "nameserver")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
