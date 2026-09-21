# Kalshi public reporting archive format

The input `discovery/s3-reporting-manifest.json` is the frozen S3 object inventory.
It lists 3,935 keys: one zero-byte `reporting/` directory marker and 3,934 source
files totaling **462,291,303,835 bytes**. The directory marker is represented by
the inventory; it is not a data file.

The archive preserves the original downloaded bytes. JSON files are compressed
with gzip in this snapshot. Objects already named `.gz` retain their original gzip bytes.
Restoring an original `.json.gz` produces that original compressed file, not a
substituted JSON document.

## Download and package

```powershell
python scripts/archive_reporting.py download --package --compression gzip --level 6 --jobs 8 --volume-mib 512 --flush-seconds 120
```

Downloads use a bounded thread pool and 1 MiB buffers. Each request sends the
inventory ETag in `If-Match`, rejects changed objects, checks exact source size,
and computes source SHA256 and MD5. A single-part S3 ETag must match source MD5.
Multipart ETags are recorded as not comparable to a whole-object MD5.
Original gzip files also pass streaming gzip CRC/length validation. Files up to
8 MiB are parsed as JSON; larger files explicitly say they were not JSON-parsed.
No claim of full JSON syntax validation is made for large files.

`archive/data/records/*.json` records successful and failed source retrievals.
`archive/data/progress/*.json` contains live transfer progress.
`archive/data/status.json` summarizes verified and packaged coverage.
`archive/data/archive-manifest.json` contains the consolidated source metadata.
These local statuses do not establish cloud persistence; the uploader records
cloud asset digests separately.

`packages/volume-000001.zip` and succeeding ZIPs use ZIP_STORED entries. Each
volume is at most the configured size. Large compressed objects may span ZIPs;
their parts have explicit offsets, lengths and SHA256 digests. Volumes are
finalized during acquisition, so cloud upload can proceed concurrently.

Every volume contains `VOLUME-MANIFEST.json` with complete metadata for its source
objects. ZIP entries are named `objects/<object-id>/part-<byte-offset>.bin`.
The object ID is the SHA256 of the original S3 key. Each object's compressed blob
also has its own SHA256. Concatenating its parts in offset order reconstructs the
blob. Decoding the recorded outer compression reconstructs the original bytes.

A matching `packages/volume-000001.json` sidecar is the commit marker. It includes
the final ZIP SHA256, size, entry inventory and embedded object metadata. Uploaders
must wait for both the ZIP and sidecar. ZIP CRCs are checked before commitment.

## Resume after interruption

Run the same download command. Completed source records and committed volume
offsets are reused. An unfinished HTTP download restarts that source object;
an unfinished ZIP resumes from the last committed volume's byte offset.
Incomplete `.partial` files are not treated as preserved data. No existing user
source files are deleted or changed.

A process lock prevents two download/packaging processes using the same data
directory. If the process is terminated abruptly, first verify that the PID in
`archive/data/pipeline.lock` is no longer running, then remove that generated lock
and run the command again. The cloud uploader and read-only verifier may run
alongside the downloader.

The optional `--remove-packed-blobs` flag removes only generated local staging
blobs after all their bytes exist in committed ZIP volumes. It is off by default.
This flag makes no claim that the ZIPs have reached the cloud.

## Verify every original byte without restoring 462 GB

```powershell
python scripts/restore_reporting.py --packages packages --verify-only --inventory discovery/s3-reporting-manifest.json --report archive/data/restore-verification.json
```

This checks the exact original inventory key set and source sizes/ETags; each ZIP
hash when its sidecar is available; every part hash; reconstructed blob hashes;
and decompressed original source size, SHA256 and MD5. It streams the original
bytes and does not write the 462 GB dataset to disk. Missing parts, duplicate
offsets, mismatched hashes, and incomplete inventory coverage cause failure.
The helper uses only the Python standard library.

For continuous verification while downloads continue, `verify_streaming.py`
provides a separate watcher built on the same exact-byte restoration checks.

## Restore

Download the complete set of `volume-*.zip` assets and, preferably, their `.json`
sidecars. Then:

```powershell
python scripts/restore_reporting.py --packages packages --destination D:/Kalshi-restored --inventory discovery/s3-reporting-manifest.json --report restore-verification.json
```

Full restoration requires at least 462,291,303,835 free bytes, plus filesystem
overhead. Files are restored under `reporting/`, preserving the original keys.
Existing output files are never overwritten. Use a new destination for a full
restore. To restore or verify only a subset, add a repeatable glob:

```powershell
python scripts/restore_reporting.py --packages packages --destination D:/Kalshi-one-day --include 'reporting/*2026-09-19*'
```

The ZIPs are self-describing: their embedded manifests are sufficient for restore,
even without sidecars. Sidecars provide a separate ZIP-level SHA256 check. The
original inventory is required when requesting exact full-corpus coverage proof.

## Bounded implementation QA

`python scripts/test_archive_reporting.py` downloads generated fixtures from a
local HTTP server and checks source MD5, JSON parsing, original gzip CRC, splitting
across multiple size-capped volumes, resumption after an uncommitted final volume,
byte-exact restoration, rejection of incorrect source hashes, and deduplication
when restarting an already completed package set. Fixtures remain confined to
`archive/data/qa/` and `packages/qa/` and are not part of the real source archive.
