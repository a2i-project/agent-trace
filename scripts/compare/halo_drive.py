"""Feed PostToolUse events to halo-record's hook, one call per event, in one
process. Runs under TOOLS_DIR/venv-halo with the halo-record checkout on
PYTHONPATH (chains.py starts it); HALO_LOG and HALO_SUBJECT come from the
environment, as for `halo hook`.

    python halo_drive.py EVENTS.jsonl

It calls halo_record.hook.main, the function behind `halo hook`, with each
event as its standard input, which is what a hook process per event does,
without the interpreter start-up per event. The hook never fails the agent
and reports a lost record on standard error instead, so anything it writes
there fails this driver.
"""
import io
import sys

from halo_record import hook


def main(path):
    with open(path, "rb") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    real_in, real_err = sys.stdin, sys.stderr
    for n, line in enumerate(lines, 1):
        err = io.StringIO()
        sys.stdin, sys.stderr = io.TextIOWrapper(io.BytesIO(line + b"\n"), encoding="utf-8"), err
        try:
            rc = hook.main([])
        finally:
            sys.stdin, sys.stderr = real_in, real_err
        if rc != 0 or err.getvalue().strip():
            sys.stderr.write("event %d: exit %s: %s\n" % (n, rc, err.getvalue().strip()))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
