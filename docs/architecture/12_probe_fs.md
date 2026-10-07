# Filesystem probe

Checked against commit d1276ff on 2026-10-07.

## Objective

The filesystem probe (`pkg/probe/fs`) records file opens, writes, closes, creations, deletions and renames on the filesystem that holds the workspace, with the PID that caused each one and a content hash for files that were written and closed. The common contract, clocks and coverage format are in [10_probes_common.md](10_probes_common.md).

## Structure

| File | Contents |
|---|---|
| `fanotify.go` | `initFanotify`, `markFilesystem`, `openMountFD`, `newKernelResolver`, and the pure parser `parseEvents`, `resolveEventPath`, `parseDfidName`, `extractFID` |
| `observer.go` | `Config`, `Observer`, `New`, `Start`, `Stop`, `readLoop`, `drainNonBlocking`, `processRawEvent`, `registerClose`, `resolveSettled`, `hashSettledFD`, `lookupShadowHash`, `maskToActionTypes` |
| `pkg/content/hash.go` | `SHA256File`, `SHA256FD`, `SHA256Bytes`; digests are written as `sha256:<hex>` |

`Config` fields: `Path` (required; selects the filesystem), `PathFilter` (string prefix on the resolved path), `PIDFilter` (exact pid, test use), `EventBufSize` (default 4096). `cmd/watch` sets both `Path` and `PathFilter` to `--workspace`.

## Technologies

fanotify through `golang.org/x/sys/unix`, in notification class (`FAN_CLASS_NOTIF`) with `FAN_REPORT_FID | FAN_REPORT_DFID_NAME`, so the kernel reports file handles instead of open file descriptors. The mark is `FAN_MARK_ADD | FAN_MARK_FILESYSTEM` on `Config.Path`, which covers every mount of the filesystem containing that path. The mask is `FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO`. Handles are resolved with `open_by_handle_at` on a directory fd for `Config.Path`, then `readlink` of `/proc/self/fd/N`. Requires `CAP_SYS_ADMIN` in the initial user namespace.

## Workflow

### Reading and resolving

1. `Start` walks `PathFilter` and hashes every regular file into `shadowHashes` (by path) and `shadowHashesByInode` (by device and inode), then starts `readLoop`.
2. `readLoop` polls the fanotify fd and a stop pipe with a 5 ms timeout (`settlePollMs`), so it wakes to judge pending closes even when nothing arrives. Each wakeup drains every available record (`drainNonBlocking`) and stamps the whole batch with one `time.Now()`.
3. `parseEvents` walks the metadata records. `resolveEventPath` prefers a DFID_NAME record (parent directory handle plus name), then a FID record (the object's own handle), then a DFID record (directory only). Only the last case sets `PathIsAmbiguous`, which happens when the kernel merged events and dropped the name. The FID handle is kept for later inode lookups.
4. `processRawEvent` sets `overflow` on `FAN_Q_OVERFLOW`, applies `PIDFilter` and `PathFilter`, strips the probe's own hash-read `FAN_OPEN` (tracked in `pendingHashOpens`), and bumps the path's `pathGeneration` and `lastWriteAt` for any create, modify, close-write or open.
5. `maskToActionTypes` expands one mask into events in a fixed causal order: `FAN_OPEN` to `file_open`, `FAN_CREATE` or `FAN_MODIFY` to one `file_write`, `FAN_CLOSE_WRITE` to `file_close`, then `FAN_DELETE` to `file_delete` and `FAN_MOVED_FROM` or `FAN_MOVED_TO` to `file_rename`. The kernel merges consecutive events on one object into a single mask that has no order; emitting open, write, close in that order makes a merged notification and the same operations delivered separately produce the same sequence (commit 81b3c4d). The verifier aligns by position, so a fixed order matters.
6. Every event carries `PID` from the fanotify metadata (0 when the kernel caused it). There is no tracked-set filter: `PIDFilter` matches one exact pid and does not follow children. A fanotify event is read some time after the access, a short-lived child has often left any tracked set by then, and a filter consulting the set would drop that child's events with nothing counting the loss. Attribution is the verifier's job (`pkg/verification.Forest.Attribute`).

### Hashes

A `file_open` gets an `InputHash` from `lookupShadowHash`: the last settled hash for the path, else the hash for the file's device and inode (which survives a rename), else the SHA-256 of empty content.

A `file_close` goes through a settle protocol so its `OutputHash` reflects the file's content after the write burst ends:

1. `registerClose` makes the close the pending one for its path and opens an `O_PATH` fd from its handle. If a close was already pending for that path, the older one is emitted at once with no `OutputHash`, because a newer close proves it was not final.
2. `resolveSettled` runs after every wakeup. It hashes a pending close only if it is still the current entry for its path and the path has had no write-class event for `settleQuietWindow` (20 ms).
3. `hashSettledFD` snapshots the path's generation, reads the content through the `O_PATH` fd, drains the fanotify queue without blocking, and compares the generation again. A write that completed during the read has its notification already queued, so a changed generation means the read is not trusted and no `OutputHash` is attached (time-of-check to time-of-use protection). A trusted digest updates both shadow maps.
4. On `Stop`, `flushPendingCloses` resolves every remaining close without the quiet check, since no further write can be observed.

`FileClose` events therefore leave the probe later than the events around them; `cmd/watch` sorts all events by timestamp before writing.

## Guarantees and loss accounting

Paths are resolved by the kernel from file handles, not read from user memory. The probe sees every writer on the marked filesystem, whichever process tree it belongs to, and records the causing PID. A published `OutputHash` is computed only after the path has been quiet for the settle window and survived the generation check; when the probe cannot vouch for it, the hash is absent rather than stale.

The probe never drops on its own channel: `processRawEvent` and the settle code send with a blocking send. A slow consumer backs up into the kernel queue, and a full kernel queue produces `FAN_Q_OVERFLOW`. `CaptureCoverage` reports `Ran: true` and `QueueOverflow`, which `verification.Assess` treats as event loss (INCONCLUSIVE). All other `ProbeCoverage` counters are zero for this probe.

## Known limits

- The `OutputHash` is computed in userspace after the close, so a write that lands between the close and the read, outside the generation check's window, can still make the hash describe later content.
- Writes through a shared `mmap` do not raise `FAN_MODIFY`.
- `FAN_ACCESS` and `FAN_CLOSE_NOWRITE` are not in the mask, so reads are invisible beyond the open and the probe never emits `file_read`.
- Attribute and permission changes are not watched.
- Only the filesystem containing `Config.Path` is marked, so activity on tmpfs `/tmp` or any other mount is invisible.
- `PathFilter` is a plain string prefix, so `/work` also admits `/workspace2`.
- A rename produces two `file_rename` events, one per name, with nothing linking them.
- The kernel can merge several modifies into one notification, so the number of `file_write` events for a burst is not stable.
- Timestamps are taken at userspace read time and are not comparable in order with proc or net timestamps.
- The startup walk opens every file under `PathFilter` while the mark is active, and those opens are reported as `file_open` events with watch's own PID.
- `pathGeneration`, `lastWriteAt` and the shadow hash maps grow for the observer's whole life.
- PID reuse among short-lived processes is resolved by time in the verifier, which is a heuristic.
