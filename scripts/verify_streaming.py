#!/usr/bin/env python3
"""Continuously prove exact source recovery as immutable archive volumes arrive.

Writes only small audit receipts. Every source byte is reconstructed in memory,
hashed, then discarded. No source-object restore tree is created.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import time
import zipfile

from restore_reporting import restore_one, sha_file


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Audit:
    def __init__(self, args):
        self.args = args
        inventory = read_json(args.inventory)
        inventory = [item for item in inventory if not item["key"].endswith("/")]
        self.expected = {item["key"]: item for item in inventory}
        if len(inventory) != len(self.expected):
            raise ValueError("Duplicate inventory keys")
        self.inventory_sha = sha_file(args.inventory)
        self.source_bytes = sum(item["size"] for item in inventory)
        self.records, self.parts, self.volumes, self.verified = {}, {}, {}, {}
        self.audit_dir = args.audit_dir

    def discover(self):
        changed = False
        for sidecar in sorted(self.args.packages.glob("volume-*.json")):
            if sidecar.name in self.volumes:
                continue
            journal = read_json(sidecar)
            name = journal["filename"]
            if Path(name).name != name or name != sidecar.with_suffix(".zip").name:
                raise ValueError("Unsafe or inconsistent volume filename: " + name)
            volume = self.args.packages / name
            if not volume.is_file() or volume.stat().st_size != journal["bytes"]:
                raise ValueError("Committed volume is missing or size differs: " + name)
            digest = sha_file(volume)
            if digest != journal["sha256"]:
                raise ValueError("Volume SHA256 mismatch: " + name)
            with zipfile.ZipFile(volume) as archive:
                names = archive.namelist()
                if len(names) != len(set(names)):
                    raise ValueError("Duplicate ZIP entry names: " + name)
                manifest = json.loads(archive.read("VOLUME-MANIFEST.json"))
                for field in ("format_version", "sequence", "description", "entries", "objects"):
                    if manifest[field] != journal[field]:
                        raise ValueError("ZIP manifest and commit sidecar disagree: " + name)
                expected_names = {"VOLUME-MANIFEST.json"} | {part["name"] for part in manifest["entries"]}
                if set(names) != expected_names or len(manifest["entries"]) + 1 != len(names):
                    raise ValueError("Unlisted or duplicate ZIP entries: " + name)
                local_ids = set()
                for record in manifest["objects"]:
                    identity, key = record["object_id"], record["key"]
                    if identity in local_ids:
                        raise ValueError("Duplicate object metadata within volume: " + key)
                    local_ids.add(identity)
                    if key not in self.expected:
                        raise ValueError("Object absent from source inventory: " + key)
                    if identity != hashlib.sha256(key.encode()).hexdigest():
                        raise ValueError("Object identifier does not match key: " + key)
                    expected = self.expected[key]
                    if record["source_size"] != expected["size"] or record["inventory_etag"] != expected["etag"]:
                        raise ValueError("Object metadata differs from source inventory: " + key)
                    if record.get("status") != "verified":
                        raise ValueError("Unverified source object metadata: " + key)
                    if identity in self.records and self.records[identity] != record:
                        raise ValueError("Inconsistent object metadata across volumes: " + key)
                    self.records[identity] = record
                for part in manifest["entries"]:
                    identity = part["object_id"]
                    if identity not in local_ids:
                        raise ValueError("Part has no volume-local object metadata: " + part["name"])
                    if part["length"] <= 0 or part["offset"] < 0:
                        raise ValueError("Invalid part length/offset: " + part["name"])
                    if archive.getinfo(part["name"]).file_size != part["length"]:
                        raise ValueError("ZIP entry length mismatch: " + part["name"])
                    if identity in self.verified:
                        raise ValueError("An extra part appeared for an already verified object: " + identity)
                    self.parts.setdefault(identity, []).append((volume, part))
            item = {"name": name, "bytes": journal["bytes"], "sha256": digest,
                    "sidecar_sha256": sha_file(sidecar), "verified_at": now()}
            self.volumes[sidecar.name] = item
            atomic_json(self.audit_dir / "volumes" / sidecar.name, item)
            print(json.dumps({"event": "volume_hash_verified", "name": name, "bytes": journal["bytes"]}), flush=True)
            changed = True
        return changed

    def completed(self):
        pending = []
        for identity, record in self.records.items():
            if identity in self.verified:
                continue
            parts = sorted(self.parts.get(identity, []), key=lambda entry: entry[1]["offset"])
            offset = 0
            for _, part in parts:
                if part["offset"] != offset:
                    raise ValueError("Noncontiguous, overlapping, or duplicate parts: " + record["key"])
                offset += part["length"]
            if offset > record["blob_size"]:
                raise ValueError("Parts exceed recorded compressed blob size: " + record["key"])
            if offset == record["blob_size"]:
                dependencies = [{"volume": path.name, "volume_sha256": self.volumes[path.with_suffix('.json').name]["sha256"],
                                 "entry": part} for path, part in parts]
                fingerprint = canonical_hash({"inventory_sha256": self.inventory_sha,
                                              "record": record, "parts": dependencies})
                receipt_path = self.audit_dir / "objects" / (identity + ".json")
                if receipt_path.exists():
                    receipt = read_json(receipt_path)
                    if (receipt.get("input_fingerprint") != fingerprint or receipt.get("verified") is not True
                            or receipt.get("key") != record["key"] or receipt.get("source_size") != record["source_size"]
                            or receipt.get("source_sha256") != record["source_sha256"]):
                        raise ValueError("Existing verification receipt does not match immutable inputs: " + record["key"])
                    self.verified[identity] = receipt
                    continue
                pending.append((identity, record, parts, fingerprint, dependencies, receipt_path))
        return pending

    def verify(self, job):
        identity, record, parts, fingerprint, dependencies, path = job
        result = restore_one(record, parts, None)
        receipt = {**result, "verified_at": now(), "input_fingerprint": fingerprint,
                   "blob_sha256": record["blob_sha256"], "blob_size": record["blob_size"],
                   "source_md5": record["source_md5"], "inventory_sha256": self.inventory_sha,
                   "method": "volume_sha256_then_part_sha256_then_blob_sha256_then_lossless_decode_source_sha256_and_md5",
                   "dependencies": dependencies}
        atomic_json(path, receipt)
        return identity, receipt

    def status(self, complete=False):
        observed_keys = {record["key"] for record in self.records.values()}
        verified_keys = {record["key"] for record in self.verified.values()}
        if complete and (observed_keys != set(self.expected) or verified_keys != set(self.expected)
                         or len(self.verified) != len(self.expected)):
            raise ValueError("Final exact inventory coverage failed")
        source_bytes = sum(record["source_size"] for record in self.verified.values())
        if complete and source_bytes != self.source_bytes:
            raise ValueError("Final source byte total failed")
        report = {"status": "COMPLETE" if complete else "in_progress", "updated_at": now(),
                  "mode": "incremental_verify_only", "inventory_path": str(self.args.inventory),
                  "inventory_sha256": self.inventory_sha,
                  "expected_object_count": len(self.expected), "object_count": len(self.verified),
                  "expected_source_bytes": self.source_bytes, "source_bytes": source_bytes,
                  "exact_inventory_coverage_checked": complete, "all_restored_bytes_hashed": complete,
                  "volume_count": len(self.volumes), "volumes": list(self.volumes.values()),
                  "missing_objects": sorted(set(self.expected)-verified_keys),
                  "cloud_verification": "Separate verification required; this proves local immutable-volume recovery only."}
        atomic_json(self.audit_dir / "status.json", report)
        if complete:
            report["objects"] = sorted(self.verified.values(), key=lambda item: item["key"])
            atomic_json(self.args.report, report)
        print(json.dumps({key: value for key, value in report.items()
                          if key not in ("missing_objects", "volumes", "objects", "cloud_verification")}), flush=True)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=Path("discovery/s3-reporting-manifest.json"))
    parser.add_argument("--packages", type=Path, default=Path("packages"))
    parser.add_argument("--audit-dir", type=Path, default=Path("archive/verification"))
    parser.add_argument("--report", type=Path, default=Path("archive/RESTORE_VERIFICATION.json"))
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--poll-seconds", type=float, default=10)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16 or args.poll_seconds <= 0:
        parser.error("jobs must be 1..16 and poll-seconds must be positive")
    args.audit_dir.mkdir(parents=True, exist_ok=True)
    lock = args.audit_dir / "verification.lock"
    try:
        handle = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise SystemExit("Verification lock exists; confirm the prior process exited before removing it")
    try:
        with os.fdopen(handle, "w") as stream:
            json.dump({"pid": os.getpid(), "started_at": now()}, stream)
        audit = Audit(args)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            while True:
                audit.discover()
                pending = audit.completed()
                if pending:
                    futures = [pool.submit(audit.verify, job) for job in pending]
                    for future in concurrent.futures.as_completed(futures):
                        identity, receipt = future.result()
                        audit.verified[identity] = receipt
                        if len(audit.verified) % 50 == 0:
                            audit.status()
                complete = len(audit.verified) == len(audit.expected)
                audit.status(complete)
                if complete:
                    return 0
                if not args.watch:
                    return 2
                time.sleep(args.poll_seconds)
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
