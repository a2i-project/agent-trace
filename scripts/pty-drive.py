#!/usr/bin/env python3
"""Drive an interactive agent session on a pseudo-terminal (I-162).

    pty-drive.py --log FILE [--dialog MARKER KEYS]... --ready MARKER...
                 --prompt TEXT... (--exit-keys KEYS | --exit-command TEXT)
                 --trace-method jsonl-session --trace-dir DIR --session ID
                 [timeouts] -- COMMAND...

COMMAND runs as the child on a new pseudo-terminal (40 rows by 120 columns
unless --rows and --cols say otherwise), as its session leader with the
terminal as its controlling terminal and its stdin, stdout and stderr. The
driver reads everything the child writes and types into it, in order:

  1. It waits for the ready screen, answering each dialog whose MARKER
     appears by writing its KEYS (names separated by spaces, KEYS below),
     at most once per dialog, at any time in the session.
  2. For each --prompt: it writes the text, waits until the output has been
     quiet for --settle seconds (the terminal interface echoes it), writes a
     carriage return, and waits until the agent's transcript shows that many
     turns ended.
  3. It ends the session and waits for the child to exit: --exit-keys
     writes the named keys one by one, --exit-key-delay seconds apart
     (Claude Code 2.1.306 under --disable-slash-commands answers /exit with
     "Unknown command" and exits on two Ctrl-D close together), or
     --exit-command types a command the same way as a prompt.

Screen matching: the output is cleaned of ANSI and OSC escape sequences and
carriage returns, and a marker matches when it is in the text written since
the driver last typed, both with all white space removed (an interface that
places text by cursor moves leaves no spaces in the stream). Every --ready
marker must match, and the output must then be quiet for --settle seconds.

Turns: --trace-method jsonl-session counts, in <trace-dir>/<project>/<session>.jsonl
(the file appears at the first prompt), the distinct main-thread assistant
messages (isSidechain not true) whose message.stop_reason is end_turn, by
message id: Claude Code may write one message as several records.

The cleaned screen goes to --log; the driver's own lines (what it is waiting
for, a timeout) go to stderr. Exit status: the child's, after the
exit; 124 when a wait timed out (the driver then ends the session,
gives the child --kill-grace seconds, sends it SIGTERM, then SIGKILL after
as long again); the child's status, or 125 when that is 0, when the child
exited before the script was done; 130 when the driver was interrupted (it
sends the child SIGTERM and waits for it); 2 for a usage error.

Standard library only. It knows no agent: every string comes from its flags.
"""
import argparse
import codecs
import errno
import fcntl
import glob
import json
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import time

# The key names a profile may use, as the bytes a terminal sends.
KEYS = {
    "enter": b"\r",
    "tab": b"\t",
    "space": b" ",
    "escape": b"\x1b",
    "backspace": b"\x7f",
    "up": b"\x1b[A",
    "down": b"\x1b[B",
    "right": b"\x1b[C",
    "left": b"\x1b[D",
    "ctrl-c": b"\x03",
    "ctrl-d": b"\x04",
}

# Complete escape sequences: CSI, OSC (ended by BEL or ST), the other
# two-byte escapes and character set designations.
ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()*+][0-9A-Za-z]|\x1b[@-Z\\^_`a-z{|}~=>78]")
# What a marker is compared on: no white space.
SPACE = re.compile(r"\s+")
# The compacted text kept for matching, at most this many characters.
KEEP = 200000


class Timeout(Exception):
    pass


class Ended(Exception):
    """The child exited while the driver waited for something else."""


class Driver:
    def __init__(self, a):
        self.a = a
        self.log = open(a.log, "w", encoding="utf-8")
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending = ""
        self.seen = ""  # compacted text since the driver last typed
        self.last_output = time.monotonic()
        self.answered = set()
        self.status = None
        self.pid = None
        self.fd = None

    def note(self, msg):
        line = "pty-drive: %s" % msg
        print(line, file=sys.stderr, flush=True)
        self.log.write("\n[%s]\n" % line)
        self.log.flush()

    def start(self, argv):
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.execvp(argv[0], argv)
            except OSError as e:
                os.write(2, ("pty-drive: cannot run %s: %s\n" % (argv[0], e)).encode())
            os._exit(127)
        self.pid, self.fd = pid, fd
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", self.a.rows, self.a.cols, 0, 0))

    def feed(self, data):
        text = self.pending + self.decoder.decode(data)
        text = ESCAPE.sub("", text).replace("\r", "")
        # An escape sequence cut by the read waits for the rest.
        cut = text.rfind("\x1b")
        if cut >= 0 and len(text) - cut < 256:
            text, self.pending = text[:cut], text[cut:]
        else:
            self.pending = ""
        text = text.replace("\x1b", "")
        self.log.write(text)
        self.log.flush()
        self.seen = (self.seen + SPACE.sub("", text))[-KEEP:]

    def reap(self):
        if self.status is None:
            pid, st = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(st)
        return self.status

    def pump(self, timeout):
        """Read what the child writes for up to timeout seconds."""
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if self.fd is None:
                if self.reap() is not None or left <= 0:
                    return
                time.sleep(min(left, 0.05))
                continue
            r, _, _ = select.select([self.fd], [], [], max(left, 0))
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError as e:
                    if e.errno != errno.EIO:
                        raise
                    data = b""
                if not data:
                    # The terminal closed: every process holding it exited.
                    os.close(self.fd)
                    self.fd = None
                    continue
                self.last_output = time.monotonic()
                self.feed(data)
            elif left <= 0:
                return

    def quiet(self):
        return time.monotonic() - self.last_output >= self.a.settle

    def write(self, data):
        self.seen = ""
        os.write(self.fd, data)

    def dialogs(self):
        """Answer each dialog whose marker is on the screen, once."""
        for i, (marker, keys) in enumerate(self.a.dialog):
            if i in self.answered or SPACE.sub("", marker) not in self.seen:
                continue
            self.answered.add(i)
            self.note("dialog %r: sending %s" % (marker, keys))
            for k in keys.split():
                self.write(KEYS[k])
                self.pump(self.a.key_delay)

    def wait(self, what, cond, timeout):
        end = time.monotonic() + timeout
        while True:
            self.pump(0.1)
            if self.fd is not None:
                self.dialogs()
            if cond():
                return
            if self.reap() is not None:
                raise Ended("the session ended while waiting for %s" % what)
            if time.monotonic() > end:
                raise Timeout("no %s within %g s" % (what, timeout))

    def type(self, text):
        self.write(text.encode())
        # The interface echoes the text; the carriage return goes alone once
        # it has, or after --type-timeout at most.
        end = time.monotonic() + self.a.type_timeout
        while not self.quiet() and time.monotonic() < end and self.reap() is None:
            self.pump(0.1)
        self.pump(self.a.settle)
        self.write(b"\r")

    def turns(self):
        files = glob.glob(os.path.join(glob.escape(self.a.trace_dir), "*", glob.escape(self.a.session) + ".jsonl"))
        if not files:
            return 0
        ids = set()
        try:
            with open(files[0], encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f):
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(r, dict) or r.get("type") != "assistant" or r.get("isSidechain") is True:
                        continue
                    m = r.get("message")
                    if isinstance(m, dict) and m.get("stop_reason") == "end_turn":
                        ids.add(m.get("id") or r.get("uuid") or n)
        except OSError:
            return 0
        return len(ids)

    def run(self):
        a = self.a
        ready = [SPACE.sub("", m) for m in a.ready]
        self.wait("ready screen", lambda: all(m in self.seen for m in ready) and self.quiet(), a.ready_timeout)
        self.note("ready")
        for i, prompt in enumerate(a.prompt, 1):
            self.note("prompt %d of %d" % (i, len(a.prompt)))
            self.type(prompt)
            self.wait("end of turn %d" % i, lambda: self.turns() >= i, a.turn_timeout)
            self.wait("quiet screen after turn %d" % i, self.quiet, a.turn_timeout)
            self.note("turn %d ended" % i)
        self.note("ending the session")
        self.end()
        self.wait("exit of the session", lambda: self.reap() is not None, a.exit_timeout)
        self.pump(0.2)
        return self.status

    def end(self):
        """The profile's exit: its keys, or its typed command."""
        if self.a.exit_keys:
            for k in self.a.exit_keys.split():
                self.write(KEYS[k])
                self.pump(self.a.exit_key_delay)
        else:
            self.type(self.a.exit_command)

    def stop(self):
        """End a session the script could not finish: the exit, then
        SIGTERM, then SIGKILL, each after --kill-grace seconds."""
        if self.reap() is None and self.fd is not None:
            try:
                self.end()
            except OSError:
                pass
        for sig in (None, signal.SIGTERM, signal.SIGKILL):
            if sig is not None and self.reap() is None:
                self.note("sending %s to the session" % signal.Signals(sig).name)
                try:
                    os.kill(self.pid, sig)
                except ProcessLookupError:
                    pass
            end = time.monotonic() + self.a.kill_grace
            while self.reap() is None and time.monotonic() < end:
                self.pump(0.1)
            if self.reap() is not None:
                break
        self.pump(0.2)
        return self.reap()


def parse(argv):
    if "--" not in argv:
        print("pty-drive: no command: give it after --", file=sys.stderr)
        sys.exit(2)
    i = argv.index("--")
    ap = argparse.ArgumentParser(prog="pty-drive.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--log", required=True, help="where the cleaned screen text goes")
    ap.add_argument("--dialog", nargs=2, action="append", default=[], metavar=("MARKER", "KEYS"), help="a dialog's screen marker and the key names to send when it appears, once")
    ap.add_argument("--ready", action="append", required=True, help="a marker of the ready screen; all must appear")
    ap.add_argument("--prompt", action="append", required=True, help="a prompt to type, in order")
    ap.add_argument("--exit-keys", help="the key names that end the session, sent one by one")
    ap.add_argument("--exit-key-delay", type=float, default=0.2, help="seconds between the exit keys")
    ap.add_argument("--exit-command", help="a command typed to end the session, in place of --exit-keys")
    ap.add_argument("--trace-method", required=True, choices=["jsonl-session"], help="how turns are counted")
    ap.add_argument("--trace-dir", required=True, help="the transcripts' directory")
    ap.add_argument("--session", required=True, help="the session id, the transcript's name")
    ap.add_argument("--rows", type=int, default=40)
    ap.add_argument("--cols", type=int, default=120)
    ap.add_argument("--settle", type=float, default=0.5, help="seconds of quiet output that end an echo or a screen update")
    ap.add_argument("--key-delay", type=float, default=0.3, help="seconds between the keys of a dialog")
    ap.add_argument("--type-timeout", type=float, default=10, help="longest wait for a typed text's echo")
    ap.add_argument("--ready-timeout", type=float, default=120)
    ap.add_argument("--turn-timeout", type=float, default=600)
    ap.add_argument("--exit-timeout", type=float, default=60)
    ap.add_argument("--kill-grace", type=float, default=30)
    a = ap.parse_args(argv[:i])
    a.command = argv[i + 1:]
    if not a.command:
        ap.error("no command after --")
    if bool(a.exit_keys) == bool(a.exit_command):
        ap.error("give exactly one of --exit-keys and --exit-command")
    if a.exit_keys:
        bad = [k for k in a.exit_keys.split() if k not in KEYS]
        if bad:
            ap.error("--exit-keys: unknown key name(s) %s (known: %s)" % (" ".join(bad), ", ".join(sorted(KEYS))))
    for marker, keys in a.dialog:
        bad = [k for k in keys.split() if k not in KEYS]
        if bad or not keys.split():
            ap.error("dialog %r: unknown key name(s) %s (known: %s)" % (marker, " ".join(bad) or "none given", ", ".join(sorted(KEYS))))
    return a


def main(argv):
    a = parse(argv)
    if not os.environ.get("TERM") or os.environ["TERM"] == "dumb":
        os.environ["TERM"] = "xterm-256color"
    d = Driver(a)
    interrupted = []

    def on_signal(sig, _frame):
        interrupted.append(sig)
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    d.start(a.command)
    try:
        status = d.run()
        d.note("the session exited with status %d" % status)
        return status
    except Timeout as e:
        d.note("timeout: %s; ending the session" % e)
        d.stop()
        return 124
    except Ended as e:
        st = d.status
        d.note("%s, with status %d" % (e, st))
        d.pump(0.2)
        return st if st else 125
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        d.note("interrupted; stopping the session")
        if d.reap() is None:
            try:
                os.kill(d.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            while d.reap() is None:
                d.pump(0.1)
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
