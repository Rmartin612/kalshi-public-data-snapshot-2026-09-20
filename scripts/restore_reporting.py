#!/usr/bin/env python3
"""Verify or restore exact original source objects from archive ZIP volumes.

Python 3.10+ standard library only. Supply all volume ZIPs in --packages.
--verify-only streams through every restored byte without writing source files.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fnmatch
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import zipfile

CHUNK = 1024 * 1024


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


class PartsReader(io.RawIOBase):
    def __init__(self, parts, record):
        super().__init__()
        self.parts = iter(parts)
        self.record = record
        self.part = None
        self.volume = None
        self.source = None
        self.sha = hashlib.sha256()
        self.size = 0
        self.done = False

    def readable(self):
        return True

    def _close_part(self):
        if self.source is None:
            return
        self.source.close()
        self.volume.close()
        self.source = self.volume = None
        if self.part_size != self.part["length"] or self.part_sha.hexdigest() != self.part["sha256"]:
            raise ValueError("Part checksum/size mismatch: " + self.part["name"])

    def readinto(self, target):
        if self.done:
            return 0
        while True:
            if self.source is None:
                entry = next(self.parts, None)
                if entry is None:
                    self.done = True
                    if self.size != self.record["blob_size"] or self.sha.hexdigest() != self.record["blob_sha256"]:
                        raise ValueError("Reassembled blob checksum/size mismatch: " + self.record["key"])
                    return 0
                volume_path, self.part = entry
                self.volume = zipfile.ZipFile(volume_path)
                self.source = self.volume.open(self.part["name"])
                self.part_sha = hashlib.sha256()
                self.part_size = 0
            chunk = self.source.read(len(target))
            if not chunk:
                self._close_part()
                continue
            self.part_sha.update(chunk)
            self.part_size += len(chunk)
            self.sha.update(chunk)
            self.size += len(chunk)
            target[:len(chunk)] = chunk
            return len(chunk)

    def close(self):
        if self.source is not None:
            self.source.close()
            self.volume.close()
            self.source = self.volume = None
        super().close()


def load_archive(folder, verify_volume_hashes):
    records = {}
    parts = {}
    volumes = []
    for path in sorted(folder.glob("volume-*.zip")):
        sidecar = path.with_suffix(".json")
        if verify_volume_hashes and sidecar.exists():
            journal = json.loads(sidecar.read_text(encoding="utf-8-sig"))
            if path.stat().st_size != journal["bytes"] or sha_file(path) != journal["sha256"]:
                raise ValueError("Volume SHA256/size mismatch: " + str(path))
        with zipfile.ZipFile(path) as archive:
            manifest = json.loads(archive.read("VOLUME-MANIFEST.json"))
            for record in manifest["objects"]:
                identity = record["object_id"]
                if identity in records and records[identity] != record:
                    raise ValueError("Inconsistent object metadata across volumes: " + record["key"])
                records[identity] = record
            for part in manifest["entries"]:
                if part["name"] not in archive.namelist():
                    raise ValueError("Missing ZIP entry: " + part["name"])
                if archive.getinfo(part["name"]).file_size != part["length"]:
                    raise ValueError("ZIP entry size disagrees with manifest: " + part["name"])
                parts.setdefault(part["object_id"], []).append((path, part))
        volumes.append(path.name)
    if not volumes:
        raise ValueError("No volume-*.zip files found")
    return records, parts, volumes


def restore_one(record, parts, output_path):
    expected_offset = 0
    for _, part in parts:
        if part["offset"] != expected_offset:
            raise ValueError("Missing, overlapping, or duplicate parts: " + record["key"])
        expected_offset += part["length"]
    if expected_offset != record["blob_size"]:
        raise ValueError("Incomplete object (one or more ZIP volumes are missing): " + record["key"])
    digest = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with contextlib.ExitStack() as stack:
        raw = stack.enter_context(PartsReader(parts, record))
        buffered = stack.enter_context(io.BufferedReader(raw, buffer_size=CHUNK))
        if record["compression"] == "xz":
            source = stack.enter_context(lzma.LZMAFile(buffered, "rb"))
        elif record["compression"] == "gzip":
            source = stack.enter_context(gzip.GzipFile(fileobj=buffered, mode="rb"))
        elif record["compression"] == "identity":
            source = buffered
        else:
            raise ValueError("Unknown blob compression: " + record["compression"])
        output = stack.enter_context(output_path.open("xb")) if output_path else None
        for chunk in iter(lambda: source.read(CHUNK), b""):
            size += len(chunk)
            digest.update(chunk)
            md5.update(chunk)
            if output:
                output.write(chunk)
        # Force EOF through the underlying concatenation to verify its final
        # part and whole-blob hash, including compressed-stream trailing bytes.
        trailing = buffered.read(1)
        if trailing:
            raise ValueError("Unexpected bytes after compressed object: " + record["key"])
        if output:
            output.flush()
            os.fsync(output.fileno())
    if size != record["source_size"] or digest.hexdigest() != record["source_sha256"] or md5.hexdigest() != record["source_md5"]:
        raise ValueError("Restored original checksum/size mismatch: " + record["key"])
    return {"key": record["key"], "source_size": size, "source_sha256": digest.hexdigest(), "verified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, default=Path("packages"))
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--inventory", type=Path, help="Require exact key/size coverage of the original S3 inventory")
    parser.add_argument("--report", type=Path, help="Write machine-readable verification results")
    parser.add_argument("--include", action="append", help="Only keys matching a shell glob; repeatable")
    parser.add_argument("--skip-volume-hashes", action="store_true", help="Skip sidecar ZIP hashes (part/blob/source hashes remain mandatory)")
    args = parser.parse_args()
    if not args.verify_only and args.destination is None:
        parser.error("Supply --destination or --verify-only")
    records, parts, volumes = load_archive(args.packages, not args.skip_volume_hashes)
    selected = [record for record in records.values() if not args.include or any(fnmatch.fnmatch(record["key"], pattern) for pattern in args.include)]
    if args.inventory:
        expected = {item["key"]: item for item in json.loads(args.inventory.read_text(encoding="utf-8-sig"))
            if not item["key"].endswith("/") and (not args.include or any(fnmatch.fnmatch(item["key"], p) for p in args.include))}
        observed = {record["key"]: record for record in selected}
        if set(expected) != set(observed):
            missing = sorted(set(expected)-set(observed))
            extra = sorted(set(observed)-set(expected))
            raise ValueError(f"Inventory key coverage mismatch: missing={len(missing)}, extra={len(extra)}; first missing={missing[:5]}")
        for key, record in observed.items():
            if expected[key]["size"] != record["source_size"] or expected[key]["etag"] != record["inventory_etag"]:
                raise ValueError("Inventory size/ETag mismatch: " + key)
    if not args.verify_only:
        args.destination.mkdir(parents=True, exist_ok=True)
        required = sum(record["source_size"] for record in selected)
        if shutil.disk_usage(args.destination).free < required:
            raise ValueError(f"Insufficient restore space: {required} source bytes required")
    verified = []
    for record in sorted(selected, key=lambda record: record["key"]):
        key_path = PurePosixPath(record["key"])
        if key_path.is_absolute() or any(part in ("", ".", "..") or ":" in part or "\\" in part for part in key_path.parts):
            raise ValueError("Unsafe source key path: " + record["key"])
        output = None
        if not args.verify_only:
            output = args.destination.joinpath(*key_path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists():
                raise FileExistsError("Will not replace an existing restored file: " + str(output))
            partial = output.with_name(output.name + ".restore-partial")
        else:
            partial = None
        result = restore_one(record, sorted(parts[record["object_id"]], key=lambda item: item[1]["offset"]), partial)
        if output:
            os.replace(partial, output)
        verified.append(result)
        print(json.dumps(result), flush=True)
    report = {"status": "verified", "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": "verify_only" if args.verify_only else "restore", "volumes": volumes,
        "object_count": len(verified), "source_bytes": sum(item["source_size"] for item in verified),
        "exact_inventory_coverage_checked": bool(args.inventory), "objects": verified}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key not in ("objects", "volumes")}), flush=True)


if __name__ == "__main__":
    main()
