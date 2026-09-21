#!/usr/bin/env python3
"""Lossless, restartable preservation of Kalshi's public reporting objects.

Only the supplied inventory is fetched. No credentials or account access required.
Use ``download --package`` to finalize uploadable volumes as downloads finish.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import fnmatch
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

CHUNK = 1024 * 1024
MIB = 1024 * 1024
LOCK = threading.Lock()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, indent=2, ensure_ascii=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def sha_file(path):
    sha = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(CHUNK), b""):
            sha.update(chunk)
    return sha.hexdigest()


def object_id(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def emit(event, **fields):
    with LOCK:
        print(json.dumps({"time": now(), "event": event, **fields}), flush=True)


def inventory(args):
    records = read_json(args.inventory)
    keys = [item["key"] for item in records]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate source keys in inventory")
    return [item for item in records if not item["key"].endswith("/")]


def record_path(args, item):
    return args.data / "records" / (object_id(item["key"]) + ".json")


def all_records(args):
    return [read_json(path) for path in sorted((args.data / "records").glob("*.json"))]


def matching_record(args, item):
    path = record_path(args, item)
    if not path.exists():
        return None
    record = read_json(path)
    if record.get("status") != "verified":
        return None
    if record["source_size"] != item["size"] or record["inventory_etag"] != item["etag"]:
        raise ValueError("Inventory changed for an already archived object: " + item["key"])
    return record


def validate_source_gzip(path):
    length = 0
    small_json = bytearray()
    with gzip.open(path, "rb") as source:
        for chunk in iter(lambda: source.read(CHUNK), b""):
            length += len(chunk)
            if length <= 8 * MIB:
                small_json.extend(chunk)
            else:
                small_json.clear()
    result = {"gzip_integrity": "passed_crc32_and_size", "uncompressed_bytes": length}
    if length <= 8 * MIB:
        json.loads(small_json)
        result["json_validation"] = "parsed_valid_json"
    else:
        result["json_validation"] = "not_parsed_large_file"
    return result


def fetch_one(args, item):
    key = item["key"]
    identity = object_id(key)
    compression = "identity" if key.endswith(".gz") else args.compression
    extension = {"gzip": ".gz", "xz": ".xz", "identity": ".original"}[compression]
    blob = args.data / "blobs" / (identity + extension)
    partial = args.data / "work" / (identity + ".partial")
    progress = args.data / "progress" / (identity + ".json")
    url = args.base_url.rstrip("/") + "/" + urllib.parse.quote(key, safe="/")
    last_error = None
    for attempt in range(1, args.retries + 1):
        received = 0
        started = time.monotonic()
        try:
            free = shutil.disk_usage(args.data).free
            if free < args.min_free_gib * 1024**3:
                raise RuntimeError(f"Only {free} disk bytes free; stop before filling disk")
            request = urllib.request.Request(url, headers={
                "Accept-Encoding": "identity", "If-Match": item["etag"],
                "User-Agent": "Kalshi-Public-Reporting-Preservation/1.0",
            })
            source_sha = hashlib.sha256()
            source_md5 = hashlib.md5()
            small_json = bytearray() if item["size"] <= 8 * MIB and compression != "identity" else None
            with urllib.request.urlopen(request, timeout=args.timeout) as response, partial.open("wb") as raw:
                if response.status != 200:
                    raise ValueError(f"Unexpected HTTP status {response.status}")
                response_headers = dict(response.headers.items())
                received_etag = response.headers.get("ETag")
                if received_etag and received_etag.strip('"') != item["etag"].strip('"'):
                    raise ValueError("ETag changed since inventory")
                declared = response.headers.get("Content-Length")
                if declared and int(declared) != item["size"]:
                    raise ValueError("Content-Length differs from inventory")
                # urllib does not automatically decode Content-Encoding. Preserve
                # exactly the returned object bytes even if S3 metadata says gzip.
                if compression == "gzip":
                    encoder = gzip.GzipFile(filename="", fileobj=raw, mode="wb", compresslevel=args.level, mtime=0)
                elif compression == "xz":
                    encoder = lzma.LZMAFile(raw, "wb", preset=args.level, check=lzma.CHECK_SHA256)
                else:
                    encoder = raw
                next_progress = 0
                try:
                    while True:
                        chunk = response.read(CHUNK)
                        if not chunk:
                            break
                        source_sha.update(chunk)
                        source_md5.update(chunk)
                        received += len(chunk)
                        if received > item["size"]:
                            raise ValueError("Response exceeds inventoried size")
                        if small_json is not None:
                            small_json.extend(chunk)
                        encoder.write(chunk)
                        if time.monotonic() >= next_progress:
                            atomic_json(progress, {"key": key, "attempt": attempt, "source_bytes_received": received,
                                "expected_source_bytes": item["size"], "elapsed_seconds": round(time.monotonic()-started, 1),
                                "updated_at": now()})
                            next_progress = time.monotonic() + 15
                finally:
                    if encoder is not raw:
                        encoder.close()
                raw.flush()
                os.fsync(raw.fileno())
            if received != item["size"]:
                raise ValueError(f"Truncated response: {received} != {item['size']}")
            etag = item["etag"].strip('"')
            md5_status = "not_comparable_multipart_etag"
            if re.fullmatch(r"[a-fA-F0-9]{32}", etag):
                if source_md5.hexdigest().lower() != etag.lower():
                    raise ValueError("Source MD5 does not match single-part S3 ETag")
                md5_status = "matched_single_part_s3_etag"
            validation = {"json_validation": "not_parsed_large_file"}
            if small_json is not None:
                json.loads(small_json)
                validation["json_validation"] = "parsed_valid_json"
            if key.endswith(".gz"):
                validation = validate_source_gzip(partial)
            blob_sha = sha_file(partial)
            blob_size = partial.stat().st_size
            os.replace(partial, blob)
            record = {"format_version": 1, "status": "verified", "key": key, "object_id": identity,
                "source_url": url, "source_size": received, "source_sha256": source_sha.hexdigest(),
                "source_md5": source_md5.hexdigest(), "inventory_etag": item["etag"],
                "inventory_last_modified": item["last_modified"], "etag_verification": md5_status,
                "response_headers": response_headers, "compression": compression,
                "blob_filename": blob.name, "blob_size": blob_size, "blob_sha256": blob_sha,
                "retrieved_at": now(), "elapsed_seconds": round(time.monotonic()-started, 2), **validation}
            atomic_json(record_path(args, item), record)
            progress.unlink(missing_ok=True)
            emit("object_verified", key=key, source_bytes=received, stored_bytes=blob_size)
            return record
        except Exception as error:
            last_error = error
            emit("download_attempt_failed", key=key, attempt=attempt, error=str(error))
            if isinstance(error, urllib.error.HTTPError) and error.code in (400, 401, 403, 404, 412):
                break
            if isinstance(error, RuntimeError) and "disk bytes" in str(error):
                break
            if attempt < args.retries:
                time.sleep(min(30, 2**attempt))
    atomic_json(record_path(args, item), {"status": "failed", "key": key, "source_url": url,
        "expected_source_bytes": item["size"], "received_last_attempt": received,
        "error": str(last_error), "failed_at": now()})
    return None


class Packager:
    """A completed .json sidecar is the commit marker for one immutable ZIP.

    Partial ZIPs are never considered committed. On restart, covered blob offsets
    are reconstructed from committed sidecars, so an interrupted object resumes
    at its last completed volume without redownloading or duplicating bytes.
    """
    def __init__(self, args):
        self.args = args
        self.maximum = int(args.volume_mib * MIB)
        self.covered = {}
        self.records = {}
        self.volumes = []
        self.current = None
        self.entries = []
        self.metadata = {}
        self.estimated = 0
        self.sequence = getattr(args, "sequence_start", 1)
        self.opened_at = None
        self.active_reader = None
        for path in sorted(args.packages.glob("volume-*.json")):
            journal = read_json(path)
            volume = args.packages / journal["filename"]
            if not volume.exists() or volume.stat().st_size != journal["bytes"]:
                raise ValueError("Missing or size-changed committed volume: " + str(volume))
            self.volumes.append(journal)
            self.sequence = max(self.sequence, journal["sequence"] + 1)
            for part in journal["entries"]:
                identity = part["object_id"]
                if part["offset"] != self.covered.get(identity, 0):
                    raise ValueError("Noncontiguous committed object parts: " + identity)
                self.covered[identity] = part["offset"] + part["length"]

    def _open(self):
        name = f"volume-{self.sequence:06d}.zip"
        self.partial = self.args.packages / (name + ".partial")
        self.final = self.args.packages / name
        self.current = zipfile.ZipFile(self.partial, "w", compression=zipfile.ZIP_STORED, allowZip64=True)
        self.entries = []
        self.metadata = {}
        self.estimated = 0
        self.opened_at = time.monotonic()

    def offer(self, record):
        identity = record["object_id"]
        self.records[identity] = record
        offset = self.covered.get(identity, 0)
        if offset > record["blob_size"]:
            raise ValueError("Packaged bytes exceed recorded blob size")
        if offset == record["blob_size"]:
            self._prune(record)
            return
        blob = self.args.data / "blobs" / record["blob_filename"]
        if not blob.exists() or blob.stat().st_size != record["blob_size"]:
            raise ValueError("Missing unpackaged blob: " + str(blob))
        self.active_reader = identity
        with blob.open("rb") as source:
            source.seek(offset)
            while offset < record["blob_size"]:
                if self.current is None:
                    self._open()
                # Reserve generous manifest/ZIP overhead; also cap entry count.
                available = self.maximum - self.estimated - 256 * 1024
                if available <= 1024 or len(self.entries) >= 100:
                    self.finish()
                    continue
                length = min(available, record["blob_size"] - offset)
                part_name = f"objects/{identity}/part-{offset:016d}.bin"
                part_sha = hashlib.sha256()
                written = 0
                with self.current.open(part_name, "w") as target:
                    while written < length:
                        chunk = source.read(min(CHUNK, length-written))
                        if not chunk:
                            raise ValueError("Blob truncated while packaging")
                        part_sha.update(chunk)
                        target.write(chunk)
                        written += len(chunk)
                self.metadata[identity] = record
                self.entries.append({"object_id": identity, "name": part_name, "offset": offset,
                    "length": length, "sha256": part_sha.hexdigest()})
                self.estimated += length + len(part_name)*2 + 256 + 4096
                offset += length
                # In-memory coverage includes pending bytes; sidecars only include
                # committed coverage, so a process interruption loses no data.
                self.covered[identity] = offset
                if self.maximum - self.estimated - 256*1024 <= 1024:
                    self.finish()
        self.active_reader = None
        self._prune(record)
        if self.current is not None and time.monotonic()-self.opened_at >= self.args.flush_seconds:
            self.finish()

    def finish(self):
        if self.current is None:
            return
        manifest = {"format_version": 1, "sequence": self.sequence,
            "description": "Lossless source-object blobs, split by byte offset where needed.",
            "entries": self.entries, "objects": list(self.metadata.values())}
        self.current.writestr("VOLUME-MANIFEST.json", json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"))
        self.current.close()
        self.current = None
        size = self.partial.stat().st_size
        if size > self.maximum:
            raise ValueError(f"Volume too large: {size} > {self.maximum}")
        with zipfile.ZipFile(self.partial) as check:
            bad = check.testzip()
            if bad is not None:
                raise ValueError("ZIP CRC verification failed: " + bad)
        digest = sha_file(self.partial)
        os.replace(self.partial, self.final)
        journal = {**manifest, "filename": self.final.name, "bytes": size, "sha256": digest,
            "finalized_at": now(), "zip_crc_check": "passed"}
        atomic_json(self.final.with_suffix(".json"), journal)
        self.volumes.append(journal)
        emit("volume_ready", filename=self.final.name, bytes=size, sha256=digest, entries=len(self.entries))
        completed = list(self.metadata.values())
        self.sequence += 1
        self.entries = []
        self.metadata = {}
        for record in completed:
            self._prune(record)

    def _prune(self, record):
        if not self.args.remove_packed_blobs:
            return
        identity = record["object_id"]
        if identity == self.active_reader:
            return
        # Do not prune if the object's final bytes are still in an open volume.
        if any(part["object_id"] == identity for part in self.entries):
            return
        if self.covered.get(identity, 0) != record["blob_size"]:
            return
        blob = self.args.data / "blobs" / record["blob_filename"]
        if blob.exists():
            # This path is derived only from our SHA256-based generated filename.
            if blob.resolve().parent != (self.args.data / "blobs").resolve():
                raise ValueError("Unsafe generated blob path")
            blob.unlink()


def write_status(args, source_inventory, packager=None):
    records = all_records(args)
    verified = {record["key"]: record for record in records if record["status"] == "verified"}
    packages = packager.volumes if packager else [read_json(path) for path in sorted(args.packages.glob("volume-*.json"))]
    coverage = {}
    for volume in packages:
        for part in volume["entries"]:
            coverage[part["object_id"]] = coverage.get(part["object_id"], 0) + part["length"]
    summary = {"updated_at": now(), "inventory_path": str(args.inventory),
        "inventory_sha256": sha_file(args.inventory), "source_object_count": len(source_inventory),
        "source_bytes_expected": sum(item["size"] for item in source_inventory),
        "source_objects_verified": len(verified), "source_bytes_verified": sum(r["source_size"] for r in verified.values()),
        "compressed_bytes_verified": sum(r["blob_size"] for r in verified.values()),
        "objects_fully_packaged": sum(coverage.get(r["object_id"]) == r["blob_size"] for r in verified.values()),
        "volumes_ready": len(packages), "volume_bytes": sum(v["bytes"] for v in packages),
        "objects_missing": [item["key"] for item in source_inventory if item["key"] not in verified],
        "failed": [record for record in records if record["status"] == "failed"],
        "cloud_upload_status": "Tracked separately by cloud uploader; local verification does not prove cloud persistence."}
    atomic_json(args.data / "status.json", summary)
    atomic_json(args.data / "archive-manifest.json", {"format_version": 1, "summary": summary,
        "objects": list(verified.values()),
        "volumes": [{key: value for key, value in volume.items() if key not in ("entries", "objects")} for volume in packages]})
    return summary


def ordered_items(args, items):
    if args.include:
        items = [item for item in items if any(fnmatch.fnmatch(item["key"], pattern) for pattern in args.include)]
    if args.order == "smallest":
        items.sort(key=lambda item: (item["size"], item["key"]))
    elif args.order == "newest":
        # Tiny historical files first; the rest by date descending. Market/trade
        # families share each date, so both make progress instead of one backlog.
        tiny = sorted((item for item in items if item["size"] <= MIB), key=lambda item: item["size"])
        others = [item for item in items if item["size"] > MIB]
        others.sort(key=lambda item: (re.search(r"\d{4}-\d{2}-\d{2}", item["key"]).group(0)
            if re.search(r"\d{4}-\d{2}-\d{2}", item["key"]) else item["last_modified"], item["key"]), reverse=True)
        items = tiny + others
    if args.limit:
        items = items[:args.limit]
    return items


def download(args):
    source_inventory = inventory(args)
    packager = Packager(args) if args.package else None
    pending = []
    for item in ordered_items(args, source_inventory.copy()):
        record = matching_record(args, item)
        if record:
            blob = args.data / "blobs" / record["blob_filename"]
            covered = packager.covered.get(record["object_id"], 0) if packager else 0
            if blob.exists() or covered == record["blob_size"]:
                if packager:
                    packager.offer(record)
                continue
        pending.append(item)
    emit("download_start", pending_objects=len(pending), jobs=args.jobs, compression=args.compression, level=args.level)
    write_status(args, source_inventory, packager)
    last_status = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        iterator = iter(pending)
        futures = {}
        for item in iterator:
            futures[pool.submit(fetch_one, args, item)] = item
            if len(futures) >= args.jobs:
                break
        while futures:
            done, _ = concurrent.futures.wait(futures, timeout=10, return_when=concurrent.futures.FIRST_COMPLETED)
            if not done:
                if packager and packager.current and time.monotonic()-packager.opened_at >= args.flush_seconds:
                    packager.finish()
                    write_status(args, source_inventory, packager)
                    last_status = time.monotonic()
                continue
            for future in done:
                item = futures.pop(future)
                record = future.result()
                if record and packager:
                    packager.offer(record)
                next_item = next(iterator, None)
                if next_item is not None:
                    futures[pool.submit(fetch_one, args, next_item)] = next_item
            if time.monotonic() - last_status >= 10:
                write_status(args, source_inventory, packager)
                last_status = time.monotonic()
    if packager:
        packager.finish()
    summary = write_status(args, source_inventory, packager)
    emit("download_finished", **{key: value for key, value in summary.items() if key not in ("objects_missing", "failed")})
    return 1 if summary["failed"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("download", "package", "status"))
    parser.add_argument("--inventory", type=Path, default=Path("discovery/s3-reporting-manifest.json"))
    parser.add_argument("--data", type=Path, default=Path("archive/data"))
    parser.add_argument("--packages", type=Path, default=Path("packages"))
    parser.add_argument("--base-url", default="https://kalshi-public-docs.s3.amazonaws.com")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--compression", choices=("gzip", "xz", "identity"), default="xz")
    parser.add_argument("--level", type=int, default=3)
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--min-free-gib", type=float, default=5)
    parser.add_argument("--volume-mib", type=float, default=512)
    parser.add_argument("--sequence-start", type=int, default=1, help="First immutable volume sequence for a disjoint shard")
    parser.add_argument("--flush-seconds", type=float, default=60)
    parser.add_argument("--package", action="store_true", help="Continuously finalize ZIP volumes while downloading")
    parser.add_argument("--remove-packed-blobs", action="store_true", help="Remove generated staging blobs only after their volumes are committed")
    parser.add_argument("--order", choices=("newest", "smallest", "manifest"), default="newest")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--include", action="append", help="Only source keys matching a shell glob; repeatable")
    args = parser.parse_args()
    if not 0 <= args.level <= 9 or not 1 <= args.jobs <= 32 or args.volume_mib < 1 or args.sequence_start < 1:
        parser.error("level must be 0..9, jobs 1..32, volume size >= 1 MiB, and sequence start >= 1")
    for path in (args.data / "blobs", args.data / "records", args.data / "work", args.data / "progress", args.packages):
        path.mkdir(parents=True, exist_ok=True)
    if args.command == "status":
        summary = write_status(args, inventory(args))
        print(json.dumps({key: value for key, value in summary.items() if key not in ("objects_missing", "failed")}, indent=2))
        return 0
    # Exclusive workspace lock. An interrupted process leaves the small lock
    # intentionally; an operator may remove it only after confirming it exited.
    lock_path = args.data / "pipeline.lock"
    try:
        handle = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except FileExistsError:
        raise SystemExit(f"Pipeline lock exists: {lock_path}. Check PID and remove only if process has exited.")
    try:
        with os.fdopen(handle, "w") as lock:
            json.dump({"pid": os.getpid(), "started_at": now(), "command": sys.argv}, lock)
        if args.command == "download":
            return download(args)
        packager = Packager(args)
        for record in all_records(args):
            if record["status"] == "verified":
                packager.offer(record)
        packager.finish()
        write_status(args, inventory(args), packager)
        return 0
    finally:
        lock_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
