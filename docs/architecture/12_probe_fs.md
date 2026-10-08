# Filesystem probe

Checked against commit c612b89 on 2026-10-08, with the changes in the commit that introduced P-17.

## Objective

The filesystem probe (`pkg/probe/fs`) records file opens, writes, closes, creations, deletions and renames on the filesystem that holds the workspace, or on every real filesystem mounted on the host, with the PID that caused each one and a content hash for files that were written and closed. The common contract, clocks and coverage format are in [10_probes_common.md](10_probes_common.md).

## Structure

| File | Contents |
|---|---|
| `fanotify.go` | `initFanotify`, `markFilesystem`, `markAll`, `parseMountInfo`, `openMountFD`, `newKernelResolver`, and the pure parser `parseEvents`, `resolveEventPath`, `parseDfidName`, `extractFID`, `recordFSID` |
| `observer.go` | `Config`, `Observer`, `New`, `markOne`, `Scope`, `Start`, `Stop`, `readLoop`, `drainNonBlocking`, `processRawEvent`, `registerClose`, `resolveSettled`, `hashSettledFD`, `lookupShadowHash`, `maskToActionTypes` |
| `pkg/content/hash.go` | `SHA256File`, `SHA256FD`, `SHA256Bytes`; digests are written as `sha256:<hex>` |

`Config` fields: `Path` (required; selects the filesystem, and the directory hashed at `Start`), `AllFilesystems` (mark every real filesystem on the host, P-17), `PathFilter` (string prefix on the resolved path), `PIDFilter` (exact pid, test use), `EventBufSize` (default 4096). `cmd/watch` sets `Path` to `--workspace` and `AllFilesystems`, with no `PathFilter`: the agent's file claims may name any path, so the probe filters nothing and `watch` applies the scope rule once the process tree is known ([40_tools.md](40_tools.md)).

## Technologies

fanotify through `golang.org/x/sys/unix`, in notification class (`FAN_CLASS_NOTIF`) with `FAN_REPORT_FID | FAN_REPORT_DFID_NAME`, so the kernel reports file handles instead of open file descriptors. The mark is `FAN_MARK_ADD | FAN_MARK_FILESYSTEM` on `Config.Path`, which covers every mount of the filesystem containing that path. With `AllFilesystems`, `markAll` reads `/proc/self/mountinfo`, skips pseudo filesystems, read-only images and fuse mounts (`pseudoFSTypes`), and marks each remaining filesystem once, by its `statfs` id, keeping one mount fd per id; a filesystem it cannot mark or open is recorded and skipped, and `Scope` returns both lists. The mask is `FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO`. Every fanotify info record carries the filesystem id of its handle (`recordFSID`), and handles are resolved with `open_by_handle_at` on the mount fd of that filesystem, then `readlink` of `/proc/self/fd/N`; a handle from an unmarked filesystem resolves to no path. Requires `CAP_SYS_ADMIN` in the initial user namespace.

## Workflow

### Reading and resolving

1. `Start` walks `PathFilter`, or `Path` when there is no filter, and hashes every regular file into `shadowHashes` (by path) and `shadowHashesByInode` (by device and inode), then starts `readLoop`. Files elsewhere are not hashed, so their first open carries the empty-content hash.
2. `readLoop` polls the fanotify fd and a stop pipe with a 5 ms timeout (`settlePollMs`), so it wakes to judge pending closes even when nothing arrives. Each wakeup drains every available record (`drainNonBlocking`) and stamps the whole batch with one `time.Now()`.
3. `parseEvents` walks the metadata records. `resolveEventPath` prefers a DFID_NAME record (parent directory handle plus name), then a FID record (the object's own handle), then a DFID record (directory only). Only the last case sets `PathIsAmbiguous`, which happens when the kernel merged events and dropped the name. The FID handle is kept for later inode lookups.
4. `processRawEvent` sets `overflow` on `FAN_Q_OVERFLOW`, applies `PIDFilter` and `PathFilter`, strips the probe's own hash-read `FAN_OPEN` (tracked in `pendingHashOpens`), and bumps the path's `pathGeneration` and `lastWriteAt` for any create, modify, close-write or open.
5. `maskToActionTypes` expands one mask into events in a fixed causal order: `FAN_OPEN` to `file_open`, `FAN_CREATE` or `FAN_MODIFY` to one `file_write`, `FAN_CLOSE_WRITE` to `file_close`, then `FAN_DELETE` to `file_delete` and `FAN_MOVED_FROM` or `FAN_MOVED_TO` to `file_rename`. The kernel merges consecutive events on one object into a single mask that has no order; emitting open, write, close in that order makes a merged notification and the same operations delivered separately produce the same sequence (commit 81b3c4d). The verifier aligns by position, so a fixed order matters.
6. Every event carries `PID` from the fanotify metadata (0 when the kernel caused it). There is no tracked-set filter: `PIDFilter` matches one exact pid and does not follow children. A fanotify event is read some time after the access, a short-lived child has often left any tracked set by then, and a filter consulting the set would drop that child's events with nothing counting the loss. Attribution is the verifier's job (`pkg/verification.Forest.Attribute`).

### Hashes

A `file_open` gets an `InputHash` from `lookupShadowHash`: the last settled hash for the path, else the hash for the file's device and inode (which survives a rename), else the SHA-256 of empty content.

A `file_close` goes through a settle protocol so its `OutputHash` is the content the close described and not a state a later write left behind:

1. `registerClose` makes the close the pending one for its path, records the path's write generation (`pendingClose.gen`, taken after the close's own event bumped it) and opens an `O_PATH` fd from its handle. If a close was already pending for that path, the older one is emitted at once with no `OutputHash`, because a newer close proves it was not final.
2. `resolveSettled` runs after every wakeup. It hashes a pending close only if it is still the current entry for its path, the path has had no write-class event for `settleQuietWindow` (20 ms), and the path's generation is still the one recorded at registration. A write-class event after the close, an open included, means the content the close described may be gone, so the close is published with no `OutputHash` and no read is made (P-16).
3. `hashSettledFD` snapshots the path's generation, reads the content through the `O_PATH` fd, drains the fanotify queue without blocking, and compares the generation again. A write that completed during the read has its notification already queued, so a changed generation means the read is not trusted and no `OutputHash` is attached (time-of-check to time-of-use protection). A trusted digest updates both shadow maps.
4. On `Stop`, `flushPendingCloses` resolves every remaining close without the quiet check, since no further write can be observed.

`FileClose` events therefore leave the probe later than the events around them; `cmd/watch` sorts all events by timestamp before writing.

## Guarantees and loss accounting

Paths are resolved by the kernel from file handles, not read from user memory. The probe sees every writer on the marked filesystem, whichever process tree it belongs to, and records the causing PID. A published `OutputHash` is computed only after the path has been quiet for the settle window and survived the generation check; when the probe cannot vouch for it, the hash is absent rather than stale.

The probe never drops on its own channel: `processRawEvent` and the settle code send with a blocking send. A slow consumer backs up into the kernel queue, and a full kernel queue produces `FAN_Q_OVERFLOW`. `CaptureCoverage` reports `Ran: true` and `QueueOverflow`, which `verification.Assess` treats as event loss (INCONCLUSIVE). All other `ProbeCoverage` counters are zero for this probe.

## Known limits

- The `OutputHash` is computed in userspace after the close, so a write that lands between the close and the read, outside the generation check's window, can still make the hash describe later content. The probe errs towards publishing no hash: any open of the path after the close drops it, including a plain read, so a file read within the settle window of being written is published without a hash.
- Writes through a shared `mmap` do not raise `FAN_MODIFY`.
- `FAN_ACCESS` and `FAN_CLOSE_NOWRITE` are not in the mask, so reads are invisible beyond the open and the probe never emits `file_read`.
- Attribute and permission changes are not watched.
- Without `AllFilesystems`, only the filesystem containing `Config.Path` is marked, so activity on tmpfs `/tmp` or any other mount is invisible. With it, fuse mounts, read-only images and any filesystem that refused the mark are still invisible; the capture's `fs_scope` lists them.
- `PathFilter` is a plain string prefix, so `/work` also admits `/workspace2`. `cmd/watch` no longer uses it; its own workspace test is directory-bounded.
- A rename produces two `file_rename` events, one per name, with nothing linking them.
- The kernel can merge several modifies into one notification, so the number of `file_write` events for a burst is not stable.
- Timestamps are taken at userspace read time and are not comparable in order with proc or net timestamps.
- The startup walk opens every file under the walked directory while the mark is active, and those opens are reported as `file_open` events with watch's own PID.
- `pathGeneration`, `lastWriteAt` and the shadow hash maps grow for the observer's whole life.
- PID reuse among short-lived processes is resolved by time in the verifier, which is a heuristic.
