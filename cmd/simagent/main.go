package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// httpClient is used for the optional --fetch-url HTTPS request. A 10-second
// timeout is generous enough for example.com but short enough to not stall
// tests indefinitely if the network is unavailable.
//
// Go's dialer races IPv6 and IPv4 attempts against a dual-stack host (RFC 6555
// fast fallback). The losing dial is cancelled before any ClientHello, so it
// carries no SNI and surfaces as IP-only net_connect ground truth that no
// trajectory entry claims. Pin every dial to one IPv4 address, as the curl
// path does with --resolve, so exactly one connection is opened.
var httpClient = func() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = dialSingleIPv4
	return &http.Client{Timeout: 10 * time.Second, Transport: tr}
}()

// dialSingleIPv4 dials one resolved IPv4 address for addr's host. TLS
// ServerName still comes from the request URL, so the SNI is unchanged.
func dialSingleIPv4(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := resolveSingleIPv4(host)
	if err != nil {
		log.Printf("resolve %s: %v (continuing unpinned; expect extra net_connect ground truth)", host, err)
		return d.DialContext(ctx, network, addr)
	}
	return d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, port))
}

// resolveSingleIPv4 returns one IPv4 address for host, so the caller can pin
// curl to a single connection target (see the --resolve use below). Mirrors
// tests/e2e/tier5_test.go's helper of the same name.
func resolveSingleIPv4(host string) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for %s", host)
}


func main() {
	var workspace string
	var trajectoryOut string
	var dropEntry int
	var fileOnly bool
	var attack string
	var fetchURL string

	flag.StringVar(&workspace, "workspace", "", "Path to the workspace directory")
	flag.StringVar(&trajectoryOut, "trajectory-out", "", "Path to write the trajectory JSON")
	flag.IntVar(&dropEntry, "drop-entry", -1, "Zero-based index of a trajectory entry to omit before writing (simulates an omission attack for manual testing; -1 disables)")
	flag.BoolVar(&fileOnly, "file-only", false, "Skip the subprocess step, producing a trajectory with only filesystem actions (for Tier 1, where no process probe runs)")
	flag.StringVar(&attack, "attack", "", "Simulate an attack scenario: 'omission', 'fabrication', 'substitution-exit', 'substitution-hash', 'substitution-cmd', 'net-omission', 'net-fabrication'")
	flag.StringVar(&fetchURL, "fetch-url", "", "If set, run `curl -s -o /dev/null -m 10 <url>` and record a NetConnect trajectory entry for the host")
	var shellCmd string
	flag.StringVar(&shellCmd, "shell-cmd", "", "Run this script through a child /bin/sh -c and claim only the shell invocation, not what the script spawns. {ws} in the script expands to the workspace path. Gives the process tree a level 1 (the shell) and level 2 (its children), see docs/architecture/40_tools.md")
	var fetchMethod, fetchBody string
	var emitNetRequest bool
	var fetchViaCurl bool
	flag.StringVar(&fetchMethod, "fetch-method", "GET", "HTTP method to use for fetch (simulates net request)")
	flag.StringVar(&fetchBody, "fetch-body", "", "HTTP body to send (for POST/PUT)")
	flag.BoolVar(&emitNetRequest, "emit-net-request", false, "Also emit a NetRequest entry with RequestHash after the NetConnect (in-process fetch only; a curl subprocess's requests are never claimed)")
	flag.BoolVar(&fetchViaCurl, "fetch-via-curl", false, "Use curl subprocess instead of net/http for network request")

	flag.Parse()

	if workspace == "" || trajectoryOut == "" {
		log.Fatal("--workspace and --trajectory-out are required")
	}
	if emitNetRequest && fetchViaCurl {
		log.Fatal("--emit-net-request cannot be combined with --fetch-via-curl: the request is made by curl's subtree, which no claim can corroborate (D3)")
	}

	var trajectory models.Trajectory

	addEntry := func(action models.ActionType, target string) {
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: action,
			Target:     target,
		})
	}
	addEntryWithOutputHash := func(action models.ActionType, target, outputHash string) {
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: action,
			Target:     target,
			OutputHash: &outputHash,
		})
	}
	addEntryWithInputHash := func(action models.ActionType, target, inputHash string) {
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: action,
			Target:     target,
			InputHash:  &inputHash,
		})
	}
	addEntryWithRequestHash := func(action models.ActionType, target, requestHash string) {
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: action,
			Target:     target,
			RequestHash: &requestHash,
		})
	}

	// Wait slightly between operations so timestamps are strictly ordered and matched properly
	delay := func() {
		time.Sleep(50 * time.Millisecond)
	}

	f1 := filepath.Join(workspace, "file1.txt")

	// 1. WriteFile
	// os.WriteFile triggers, in this order:
	// - FAN_CREATE (FileWrite, resolved to the directory: the create event is
	//   a DFID-only record, so it covers the file by the directory fallback)
	// - FAN_OPEN (FileOpen)
	// - FAN_MODIFY (FileWrite), merged with the close
	// - FAN_CLOSE_WRITE (FileClose)
	// The verifier aligns claims against the observed sequence by position, so
	// the claims are in the order the kernel reports, not in the order the
	// operations read.
	emptyHash := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	addEntry(models.FileWrite, f1) // create
	addEntryWithInputHash(models.FileOpen, f1, emptyHash)
	addEntry(models.FileWrite, f1) // modify
	fileContents := []byte("hello")
	err := os.WriteFile(f1, fileContents, 0644)
	if err != nil {
		log.Fatalf("failed to write file: %v", err)
	}
	fileHash := content.SHA256Bytes(fileContents)
	addEntryWithOutputHash(models.FileClose, f1, fileHash)

	delay()

	// 2. Rename
	// os.Rename triggers FAN_MOVED_FROM and FAN_MOVED_TO on the directory; the
	// probe emits them as one FileRename whether or not the kernel merged
	// them (P-18).
	f2 := filepath.Join(workspace, "file2.txt")
	addEntry(models.FileRename, f1)
	err = os.Rename(f1, f2)
	if err != nil {
		log.Fatalf("failed to rename file: %v", err)
	}

	delay()

	// 3. Exec (Tier 2): the agent double-checks its edit by running "wc -l"
	// against the renamed file, like a real coding agent verifying a change.
	// We report the exact argv the kernel will see: os/exec passes argv[0] as
	// given ("wc"), not the PATH-resolved absolute path, so the process
	// probe's reconstructed command line matches this string byte-for-byte.
	// Skipped under --file-only: Tier 1 runs no process probe, so these
	// entries would have no ground truth to corroborate them.
	if !fileOnly {
		// Tier 2.5 Semantic Gap test: agent executes a shell command (top-level)
		// which spawns a subprocess (forensic).
		// We resolve the absolute path because the verifier now uses strict
		// absolute-path matching for process execution to prevent substitution attacks.
		wcPath, err := exec.LookPath("wc")
		if err != nil {
			log.Fatalf("failed to find wc in PATH: %v", err)
		}
		wcArgs := []string{wcPath, "-l", f2}
		wcCmdLine := strings.Join(wcArgs, " ")
		addEntry(models.ProcessExec, wcCmdLine)
		// wc opens f2 for reading, but that open is wc's own action, inside the
		// subtree of the command claimed above. The verifier attributes it to
		// the command by ancestry and never aligns it against a claim, so the
		// agent claims the command and not what the command does (D3).
		wcCmd := exec.Command(wcArgs[0], wcArgs[1:]...)
		runErr := wcCmd.Run()
		if _, ok := runErr.(*exec.ExitError); runErr != nil && !ok {
			log.Fatalf("failed to run wc: %v", runErr)
		}
		var wcExitCode int32
		if wcCmd.ProcessState != nil {
			wcExitCode = int32(wcCmd.ProcessState.ExitCode())
		}
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: models.ProcessExit,
			Target:     wcCmdLine,
			ExitCode:   &wcExitCode,
		})

		delay()
	}

	// 3b. Compound command (Tier 6 step 4): the way a real coding agent runs a
	// shell tool. The agent claims one command, the shell invocation. It never
	// claims what the script then spawns or touches: that is the shell's
	// subtree, observed as level 2 and below, and attributed to this claim by
	// ancestry (V1, D3). The claim interval comes from the format, so it
	// carries the end the real run produced (D12).
	if shellCmd != "" {
		script := strings.ReplaceAll(shellCmd, "{ws}", workspace)
		shArgs := []string{"-c", script}
		// The proc probe reports the execve filename then argv[1:].
		shCmdLine := strings.Join(append([]string{"/bin/sh"}, shArgs...), " ")
		start := time.Now()
		cmd := exec.Command("/bin/sh", shArgs...)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		runErr := cmd.Run()
		if _, ok := runErr.(*exec.ExitError); runErr != nil && !ok {
			log.Fatalf("failed to run shell command: %v", runErr)
		}
		end := time.Now()
		var shExit int32
		if cmd.ProcessState != nil {
			shExit = int32(cmd.ProcessState.ExitCode())
		}
		trajectory = append(trajectory,
			models.TrajectoryEntry{Timestamp: start, End: &end, ActionType: models.ProcessExec, Target: shCmdLine},
			models.TrajectoryEntry{Timestamp: end, ActionType: models.ProcessExit, Target: shCmdLine, ExitCode: &shExit},
		)
		delay()
	}

	// 4. Delete
	// os.Remove triggers:
	// - FAN_DELETE (FileDelete)
	// Note: on tmpfs, this might report the parent dir in DFID, but we use TempDir
	// and if the kernel provides DFID_NAME, it gives the full path. We'll report the full path.
	addEntry(models.FileDelete, f2)
	err = os.Remove(f2)
	if err != nil {
		log.Fatalf("failed to remove file: %v", err)
	}

	// 5. Optional HTTPS fetch (Tier 3), in one of two modes.
	//
	// By default the request is made from within this process using net/http,
	// so the TCP connection originates from simagent's own PID. That PID is
	// what the caller wires into the net probe's tracked_pids BPF map, so the
	// tcp_connect tracepoint fires and the netHello path captures the TLS
	// ClientHello SNI. Go's crypto/tls is statically linked, though, so the
	// libssl SSL_write uprobe cannot see the plaintext: this mode exercises
	// identity-only (NetConnect) verification.
	//
	// --fetch-via-curl instead shells out to curl, whose dynamically-linked
	// libssl the uprobe can attach to, so content-level NetRequest
	// verification is exercised too. The child is visible to the net probe
	// because tracked_pids is inherited across fork, and to the proc probe
	// through ancestry scoping, so its execve/exit must be reported here like
	// any other action this agent takes.
	var fetchHost string
	if fetchURL != "" {
		u, err := url.Parse(fetchURL)
		if err != nil {
			log.Fatalf("invalid --fetch-url %q: %v", fetchURL, err)
		}
		fetchHost = u.Hostname()

		if fetchViaCurl {
			curlPath, err := exec.LookPath("curl")
			if err != nil {
				log.Fatalf("failed to find curl in PATH: %v", err)
			}

			var args []string

			// Content capture reads SSL_write plaintext and parses it as
			// HTTP/1.x (pkg/tlsparse). Left to itself curl negotiates h2 with
			// most hosts, whose plaintext is HTTP/2 framing: the probe can
			// neither validate its uprobe offset against it nor recover a
			// request from it, so the NetRequest entry recorded below would
			// have no ground truth to corroborate it. Pin the protocol.
			args = append(args, "--http1.1")

			// A hostname with several A/AAAA records (example.com is served
			// from several CDN edges) makes curl open Happy-Eyeballs-style
			// parallel connections. The losing ones never complete a
			// handshake, so they carry no SNI and surface as IP-only
			// net_connect ground truth that no trajectory entry claims. Pin
			// one address so exactly one connection is opened.
			if ip, rerr := resolveSingleIPv4(fetchHost); rerr != nil {
				log.Printf("resolve %s: %v (continuing unpinned; expect extra net_connect ground truth)", fetchHost, rerr)
			} else {
				port := u.Port()
				if port == "" {
					port = "443"
				}
				args = append(args, "--resolve", fetchHost+":"+port+":"+ip)
			}

			args = append(args, "-s", "-o", "/dev/null", "-X", fetchMethod)
			if fetchBody != "" {
				args = append(args, "-d", fetchBody)
			}
			args = append(args, fetchURL)

			// The proc probe reports the execve filename followed by
			// argv[1:], never argv[0], so record the resolved absolute path
			// the same way the wc step above does.
			curlCmdLine := strings.Join(append([]string{curlPath}, args...), " ")

			// We must use a short delay so any caller tracking this PID can prepare
			delay()
			addEntry(models.ProcessExec, curlCmdLine)
			cmd := exec.Command(curlPath, args...)
			runErr := cmd.Run()
			if runErr != nil {
				log.Printf("curl failed: %v", runErr)
			}
			var curlExitCode int32
			if cmd.ProcessState != nil {
				curlExitCode = int32(cmd.ProcessState.ExitCode())
			}
			trajectory = append(trajectory, models.TrajectoryEntry{
				Timestamp:  time.Now(),
				ActionType: models.ProcessExit,
				Target:     curlCmdLine,
				ExitCode:   &curlExitCode,
			})
		} else {
			var bodyReader io.Reader
			if fetchBody != "" {
				bodyReader = strings.NewReader(fetchBody)
			}
			req, err := http.NewRequest(fetchMethod, fetchURL, bodyReader)
			if err != nil {
				log.Fatalf("new request: %v", err)
			}

			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("fetch %s: %v (ignoring for trajectory purposes)", fetchURL, err)
			} else {
				_ = resp.Body.Close()
			}
		}

		// Record what we did: a network connection to the host. Under
		// --fetch-via-curl the connection belongs to curl's subtree, so the
		// agent claims the curl command above and not the connection, which
		// the verifier attributes to that command by ancestry (D3).
		if !fetchViaCurl {
			addEntry(models.NetConnect, fetchHost)
		}

		if emitNetRequest {
			port := 0
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			} else if u.Scheme == "https" {
				port = 443
			}
			target := models.CanonicalNetTarget(fetchMethod, fetchHost, port, u.Path, u.RawQuery)
			if fetchBody != "" {
				h := sha256.Sum256([]byte(fetchBody))
				hashStr := "sha256:" + hex.EncodeToString(h[:])
				addEntryWithRequestHash(models.NetRequest, target, hashStr)
			} else {
				addEntry(models.NetRequest, target)
			}
		}

		delay()
	}

	if dropEntry >= 0 && dropEntry < len(trajectory) {
		trajectory = append(trajectory[:dropEntry], trajectory[dropEntry+1:]...)
	}

	switch attack {
	case "omission":
		// Drop the first entry if drop-entry wasn't already used
		if dropEntry == -1 && len(trajectory) > 0 {
			trajectory = trajectory[1:]
		}
	case "fabrication":
		// Claim to have run curl, but didn't
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: models.ProcessExec,
			Target:     "/usr/bin/curl https://example.com",
		})
	case "substitution-exit":
		// Find a process_exit and change its exit code
		for i := range trajectory {
			if trajectory[i].ActionType == models.ProcessExit && trajectory[i].ExitCode != nil {
				fakeExitCode := *trajectory[i].ExitCode + 1
				trajectory[i].ExitCode = &fakeExitCode
				break
			}
		}
	case "substitution-hash":
		// Find a file_close with an output hash and change it
		for i := range trajectory {
			if trajectory[i].ActionType == models.FileClose && trajectory[i].OutputHash != nil {
				fakeHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
				trajectory[i].OutputHash = &fakeHash
				break
			}
		}
	case "substitution-cmd":
		// Find a process_exec and change its arguments
		for i := range trajectory {
			if trajectory[i].ActionType == models.ProcessExec {
				trajectory[i].Target = trajectory[i].Target + " --fake-flag"
				break
			}
		}
	case "net-omission":
		// Drop the NetConnect entry — the net probe still saw it, so it
		// surfaces as Unrecorded in the verifier.
		filtered := trajectory[:0:0]
		for _, e := range trajectory {
			if e.ActionType != models.NetConnect {
				filtered = append(filtered, e)
			}
		}
		trajectory = filtered
	case "net-fabrication":
		// Claim to have connected to a host that was never contacted.
		trajectory = append(trajectory, models.TrajectoryEntry{
			Timestamp:  time.Now(),
			ActionType: models.NetConnect,
			Target:     "ghost.example.invalid",
		})
	}

	b, err := json.MarshalIndent(trajectory, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal trajectory: %v", err)
	}
	if err := os.WriteFile(trajectoryOut, b, 0644); err != nil {
		log.Fatalf("failed to write trajectory: %v", err)
	}
}
