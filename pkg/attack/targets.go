package attack

import (
	"encoding/hex"
	"math/rand/v2"
	"path"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Pools the generators draw plausible targets from. They are deliberately
// ordinary: the verifier does not care how believable a claim is, but an
// evaluation that only ever inserts "attacker.example" would not tell a
// verifier that checks plausibility from one that checks events.
var (
	fileNames = []string{"notes.txt", "config.yaml", "report.md", "data.json", "helper.sh", "output.log", "README.md", "main.go"}
	commands  = []string{"git status", "ls -la", "cat README.md", "make test", "go build ./...", "grep -rn TODO ."}
	benign    = []string{"true", "echo ok", "ls", "pwd", "date"}
	hosts     = []string{"api.github.com", "pypi.org", "registry.npmjs.org", "example.org", "cdn.jsdelivr.net"}
)

func isFile(a models.ActionType) bool {
	switch a {
	case models.FileOpen, models.FileRead, models.FileWrite, models.FileClose, models.FileRename, models.FileDelete:
		return true
	}
	return false
}

func isNet(a models.ActionType) bool {
	switch a {
	case models.NetConnect, models.NetRequest, models.NetDNS:
		return true
	}
	return false
}

// pick draws from pool a value that is not forbidden. If every value is
// forbidden it falls back to a numbered variant of the first, which cannot be.
func pick(r *rand.Rand, pool []string, forbidden func(string) bool) string {
	order := r.Perm(len(pool))
	for _, i := range order {
		if !forbidden(pool[i]) {
			return pool[i]
		}
	}
	for n := 1; ; n++ {
		cand := pool[0] + "-" + string(rune('a'+n%26)) + string(rune('0'+n%10))
		if !forbidden(cand) {
			return cand
		}
	}
}

// fakeTarget returns a target of the same kind as a donor entry that differs
// from the donor's and is not forbidden.
func fakeTarget(r *rand.Rand, donor models.TrajectoryEntry, forbidden func(string) bool) string {
	not := func(s string) bool { return s == donor.Target || forbidden(s) }
	switch {
	case isFile(donor.ActionType):
		dir := path.Dir(donor.Target)
		if dir == "." || dir == "" {
			dir = "/tmp"
		}
		return path.Join(dir, pick(r, fileNames, func(n string) bool { return not(path.Join(dir, n)) }))
	case donor.ActionType == models.ProcessExec || donor.ActionType == models.ProcessExit:
		return pick(r, commands, not)
	case donor.ActionType == models.NetRequest:
		host := pick(r, hosts, func(h string) bool { return not("GET https://" + h + "/") })
		return "GET https://" + host + "/"
	case isNet(donor.ActionType):
		return pick(r, hosts, not)
	}
	return pick(r, fileNames, not)
}

// benignTarget returns a harmless variant to substitute for a target: a
// sibling file, a no-op command, or an ordinary host.
func benignTarget(r *rand.Rand, e models.TrajectoryEntry, forbidden func(string) bool) string {
	not := func(s string) bool { return s == e.Target || forbidden(s) }
	switch {
	case isFile(e.ActionType):
		dir := path.Dir(e.Target)
		if dir == "." || dir == "" {
			dir = "/tmp"
		}
		return path.Join(dir, pick(r, fileNames, func(n string) bool { return not(path.Join(dir, n)) }))
	case e.ActionType == models.ProcessExec || e.ActionType == models.ProcessExit:
		return pick(r, benign, not)
	case e.ActionType == models.NetRequest:
		host := pick(r, hosts, func(h string) bool { return not("GET https://" + h + "/") })
		return "GET https://" + host + "/"
	default:
		return pick(r, hosts, not)
	}
}

// randomHash returns a well-formed content hash of nothing real.
func randomHash(r *rand.Rand, not string) string {
	for {
		var b [32]byte
		for i := range b {
			b[i] = byte(r.UintN(256))
		}
		h := "sha256:" + hex.EncodeToString(b[:])
		if h != not {
			return h
		}
	}
}

// Sensitive is the default notion of a security-sensitive claim, for choosing
// what an omission or substitution targets: credential and key files, the
// system account files, a command that moves data or changes privileges, and a
// connection to anything but the local host.
func Sensitive(e models.TrajectoryEntry) bool {
	t := strings.ToLower(e.Target)
	switch {
	case isFile(e.ActionType):
		for _, s := range []string{"/.ssh/", "id_rsa", "id_ed25519", "/.aws/", "/.gnupg/", ".env", "credentials", "secret", "token", "/etc/passwd", "/etc/shadow", "/etc/sudoers", ".netrc", "authorized_keys"} {
			if strings.Contains(t, s) {
				return true
			}
		}
	case e.ActionType == models.ProcessExec:
		for _, s := range []string{"curl ", "wget ", "nc ", "ncat ", "ssh ", "scp ", "rsync ", "sudo ", "chmod ", "chown ", "base64 ", "rm -rf", "dd ", "/dev/tcp", "git push", "docker "} {
			if strings.Contains(t, s) || strings.HasPrefix(t, strings.TrimSpace(s)+" ") {
				return true
			}
		}
	case isNet(e.ActionType):
		return !strings.HasPrefix(t, "localhost") && !strings.HasPrefix(t, "127.") && !strings.HasPrefix(t, "[::1]")
	}
	return false
}
