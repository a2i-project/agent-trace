package proc

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Temporary diagnostic for the kernel 7.0 runner; not for main.
func TestDiagKernel7Proc(t *testing.T) {
	skipUnprivileged(t)
	var u unix.Utsname
	_ = unix.Uname(&u)
	t.Logf("kernel %s", unix.ByteSliceToString(u.Release[:]))
	for _, f := range []string{
		"/sys/kernel/tracing/events/syscalls/sys_enter_execve/format",
		"/sys/kernel/tracing/events/syscalls/sys_enter_execveat/format",
		"/sys/kernel/tracing/events/syscalls/sys_enter_exit_group/format",
		"/sys/kernel/tracing/events/sched/sched_process_exec/format",
		"/sys/kernel/tracing/events/sched/sched_process_exit/format",
		"/sys/kernel/tracing/events/task/task_newtask/format",
	} {
		b, err := os.ReadFile(f)
		t.Logf("== %s err=%v\n%s", f, err, b)
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Logf("EnableStats: %v", err)
	} else {
		defer stats.Close()
	}
	obs, err := New(Config{EventBufSize: 4096})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 3; i++ {
		_ = exec.Command("/bin/sh", "-c", "/bin/true diag-a; /bin/true diag-b").Run()
	}
	time.Sleep(300 * time.Millisecond)
	progs := map[string]*ebpf.Program{
		"execve": obs.objs.HandleExecve, "execveat": obs.objs.HandleExecveat,
		"exec_ok": obs.objs.HandleExecOk, "fork": obs.objs.HandleFork,
		"exit": obs.objs.HandleExit, "exit_group": obs.objs.HandleExitGroup,
	}
	for n, p := range progs {
		st, err := p.Stats()
		if err != nil {
			t.Logf("%s: stats err %v", n, err)
			continue
		}
		t.Logf("prog %s run_count=%d", n, st.RunCount)
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var n int
	for e := range obs.Events() {
		if n < 40 {
			t.Logf("event %s pid=%d %q", e.ActionType, e.PID, e.Target)
		}
		n++
	}
	t.Logf("events total %d", n)
}
