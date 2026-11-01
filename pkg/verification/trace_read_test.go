package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// A trace kept in a SQLite database in write-ahead-log mode, as agy keeps
// its conversations: the database is covered with its -wal and -journal,
// both transient, and not its -shm (V-75, V-76).
const (
	sqlDB      = "/home/u/.gemini/antigravity-cli/conversations/c1.db"
	sqlWAL     = sqlDB + "-wal"
	sqlSHM     = sqlDB + "-shm"
	sqlJournal = sqlDB + "-journal"
	emptyIn    = emptyContentHash
	reader     = "/bin/sh -c python3 read.py"
)

func sqliteDecl() *TraceDecl {
	return &TraceDecl{
		Covers:    func(p string) bool { return p == sqlDB || p == sqlWAL || p == sqlJournal },
		Main:      func(p string) bool { return p == sqlDB },
		Transient: func(p string) bool { return p == sqlWAL || p == sqlJournal },
	}
}

// sqliteRun verifies the events of one command, pid 200, after the
// harness's own writing of the database, and returns the tampering.
func sqliteRun(t *testing.T, events ...models.GroundTruthEvent) []TraceTamper {
	t.Helper()
	g := models.GroundTruth{
		agentEv(0, models.FileOpen, sqlDB), agentEv(1, models.FileWrite, sqlWAL), agentEv(2, models.FileClose, sqlWAL),
		fork(10, 200, agentPID), execEv(11, 200, agentPID, reader),
	}
	g = append(g, events...)
	g = append(g, exitEv(90, 200, agentPID, reader))
	v := Verify(Input{
		Claims: claimsFor(reader), Ground: g, RootPID: agentPID, Coverage: completeCov(),
		Trace:    TraceInput{Decl: sqliteDecl()},
		Baseline: func(e models.GroundTruthEvent) bool { return e.PID == agentPID },
	})
	return v.TraceTampering
}

func cmdEv(ms int, typ models.ActionType, path string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: path, PID: 200}
}

func emptyOpen(ms int, path string) models.GroundTruthEvent {
	return withHash(cmdEv(ms, models.FileOpen, path), sp(emptyIn), nil)
}

func tamperTargets(tt []TraceTamper) string {
	var s []string
	for _, x := range tt {
		s = append(s, string(x.Event.ActionType)+" "+x.Event.Target[strings.LastIndex(x.Event.Target, "/")+1:])
	}
	return strings.Join(s, ", ")
}

// A stock SQLite client that only reads leaves closes of the files it
// opened for writing, and, for a database no other process holds open,
// creates the -wal empty and deletes it at the close. None of it changed
// the trace, so none of it is tampering (V-75, V-76).
func TestTrace_AReadOnlySQLiteOpenAndCloseIsNotTampering(t *testing.T) {
	for name, events := range map[string][]models.GroundTruthEvent{
		"a database the harness holds open": {
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileOpen, sqlWAL), cmdEv(22, models.FileOpen, sqlSHM),
			cmdEv(23, models.FileWrite, sqlSHM), cmdEv(24, models.FileClose, sqlSHM),
			cmdEv(25, models.FileClose, sqlWAL), withHash(cmdEv(26, models.FileClose, sqlDB), nil, sp("sha256:db")),
		},
		"a -wal created at the open, as its empty-content hash shows": {
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileWrite, sqlWAL), emptyOpen(21, sqlWAL),
			cmdEv(22, models.FileWrite, sqlSHM), cmdEv(22, models.FileOpen, sqlSHM), cmdEv(23, models.FileDelete, sqlSHM),
			cmdEv(24, models.FileClose, sqlWAL), cmdEv(24, models.FileDelete, sqlWAL), cmdEv(25, models.FileClose, sqlDB),
		},
		"a -wal created after its last delete": {
			agentEv(15, models.FileDelete, sqlWAL),
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileWrite, sqlWAL), cmdEv(21, models.FileOpen, sqlWAL),
			cmdEv(24, models.FileClose, sqlWAL), cmdEv(24, models.FileDelete, sqlWAL), cmdEv(25, models.FileClose, sqlDB),
		},
		"a -journal created and deleted empty": {
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileWrite, sqlJournal), emptyOpen(21, sqlJournal),
			cmdEv(22, models.FileClose, sqlJournal), cmdEv(23, models.FileDelete, sqlJournal), cmdEv(24, models.FileClose, sqlDB),
		},
		"two reads in one process": {
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileClose, sqlDB),
			cmdEv(30, models.FileOpen, sqlDB), cmdEv(31, models.FileClose, sqlDB),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if tt := sqliteRun(t, events...); len(tt) != 0 {
				t.Errorf("tampering: %s, want none", tamperTargets(tt))
			}
		})
	}
}

// A real write, a rename, a delete or a truncation of a covered file stays
// tampering, and so does every create or delete of a transient file that
// the capture does not show changed nothing.
func TestTrace_ASQLiteWriteOrDeleteIsTampering(t *testing.T) {
	for name, c := range map[string]struct {
		events []models.GroundTruthEvent
		want   string
	}{
		"a write of the database": {[]models.GroundTruthEvent{
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileWrite, sqlDB), cmdEv(22, models.FileClose, sqlDB),
		}, "file_write c1.db, file_close c1.db"},
		"a truncating open": {[]models.GroundTruthEvent{
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(20, models.FileWrite, sqlDB), cmdEv(21, models.FileClose, sqlDB),
		}, "file_write c1.db, file_close c1.db"},
		"a delete of the database": {[]models.GroundTruthEvent{
			cmdEv(20, models.FileDelete, sqlDB),
		}, "file_delete c1.db"},
		"a rename over the database": {[]models.GroundTruthEvent{
			cmdEv(20, models.FileRename, sqlDB),
		}, "file_rename c1.db"},
		"a write through the -wal": {[]models.GroundTruthEvent{
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileOpen, sqlWAL), cmdEv(22, models.FileWrite, sqlWAL),
			cmdEv(23, models.FileClose, sqlWAL), cmdEv(24, models.FileClose, sqlDB),
		}, "file_write c1.db-wal, file_close c1.db-wal"},
		"a close with no open in the capture": {[]models.GroundTruthEvent{
			cmdEv(20, models.FileClose, sqlDB),
		}, "file_close c1.db"},
		"a pre-existing -wal deleted": {[]models.GroundTruthEvent{
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileOpen, sqlWAL),
			cmdEv(24, models.FileClose, sqlWAL), cmdEv(24, models.FileDelete, sqlWAL), cmdEv(25, models.FileClose, sqlDB),
		}, "file_delete c1.db-wal"},
		// The harness wrote the -wal at 1: a write before the open may be
		// a truncation, not a create.
		"a -wal written without evidence it was created": {[]models.GroundTruthEvent{
			cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileWrite, sqlWAL), cmdEv(21, models.FileOpen, sqlWAL),
			cmdEv(24, models.FileClose, sqlWAL), cmdEv(24, models.FileDelete, sqlWAL), cmdEv(25, models.FileClose, sqlDB),
		}, "file_write c1.db-wal, file_delete c1.db-wal"},
		"a created -wal written before its delete": {[]models.GroundTruthEvent{
			cmdEv(21, models.FileWrite, sqlWAL), emptyOpen(21, sqlWAL), cmdEv(22, models.FileWrite, sqlWAL),
			cmdEv(24, models.FileClose, sqlWAL), cmdEv(24, models.FileDelete, sqlWAL),
		}, "file_write c1.db-wal, file_write c1.db-wal, file_close c1.db-wal, file_delete c1.db-wal"},
		"a created -wal the harness wrote before the command deleted it": {[]models.GroundTruthEvent{
			cmdEv(21, models.FileWrite, sqlWAL), emptyOpen(21, sqlWAL), agentEv(22, models.FileWrite, sqlWAL),
			cmdEv(24, models.FileClose, sqlWAL), cmdEv(24, models.FileDelete, sqlWAL),
		}, "file_write c1.db-wal, file_delete c1.db-wal"},
		"a created -wal of another process deleted": {[]models.GroundTruthEvent{
			fork(15, 201, agentPID), execEv(16, 201, agentPID, reader),
			{Timestamp: at(21), ActionType: models.FileWrite, Target: sqlWAL, PID: 201},
			withHash(models.GroundTruthEvent{Timestamp: at(21), ActionType: models.FileOpen, Target: sqlWAL, PID: 201}, sp(emptyIn), nil),
			cmdEv(24, models.FileDelete, sqlWAL),
		}, "file_write c1.db-wal, file_delete c1.db-wal"},
		// A process that created the file in an earlier incarnation of its
		// pid is not the one that deletes it.
		"a delete by a later process with the same pid": {[]models.GroundTruthEvent{
			cmdEv(21, models.FileWrite, sqlWAL), emptyOpen(21, sqlWAL), cmdEv(22, models.FileClose, sqlWAL),
			exitEv(23, 200, agentPID, reader), fork(24, 200, agentPID), execEv(25, 200, agentPID, reader),
			cmdEv(26, models.FileDelete, sqlWAL),
		}, "file_write c1.db-wal, file_delete c1.db-wal"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tamperTargets(sqliteRun(t, c.events...)); got != c.want {
				t.Errorf("tampering: %s, want %s", got, c.want)
			}
		})
	}
}

// Without a Transient declaration a create and delete of a covered file
// stay tampering; the read rule still holds.
func TestTrace_NoTransientDeclarationKeepsCreateAndDelete(t *testing.T) {
	decl := sqliteDecl()
	decl.Transient = nil
	g := models.GroundTruth{
		fork(10, 200, agentPID), execEv(11, 200, agentPID, reader),
		cmdEv(20, models.FileOpen, sqlDB), cmdEv(21, models.FileWrite, sqlWAL), emptyOpen(21, sqlWAL),
		cmdEv(24, models.FileClose, sqlWAL), cmdEv(24, models.FileDelete, sqlWAL), cmdEv(25, models.FileClose, sqlDB),
		exitEv(90, 200, agentPID, reader),
	}
	got := tamperTargets(traceTampering(decl, g, nil, BuildForest(g, agentPID)))
	if want := "file_write c1.db-wal, file_delete c1.db-wal"; got != want {
		t.Errorf("tampering: %s, want %s", got, want)
	}
}
