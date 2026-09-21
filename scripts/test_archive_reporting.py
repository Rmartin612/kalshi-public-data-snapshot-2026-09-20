"""Bounded integrity/restart QA; fixtures remain under archive/data/qa and packages/qa."""
import argparse
import functools
import gzip
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import archive_reporting as pipeline
import restore_reporting as restore


def main():
    stamp = str(time.time_ns())
    data = Path("archive/data/qa") / stamp
    packages = Path("packages/qa") / stamp
    fixtures = data / "fixtures"
    fixtures.mkdir(parents=True)
    # Random hexadecimal text is valid JSON and large enough after compression
    # to require several 1 MiB volumes.
    values = {"reporting/large.json": json.dumps({"payload": os.urandom(2200000).hex()}).encode(),
              "reporting/small.json": b'[{"ok":true}]'}
    values["reporting/already.json.gz"] = gzip.compress(values["reporting/large.json"], mtime=0)
    items = []
    for key, content in values.items():
        path = fixtures / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        items.append({"key": key, "size": len(content), "etag": '"'+hashlib.md5(content).hexdigest()+'"', "last_modified": "2026-09-21T00:00:00Z"})
    inventory = data / "inventory.json"
    inventory.write_text(json.dumps(items), encoding="utf-8")

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(fixtures)))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        command = [sys.executable, "scripts/archive_reporting.py", "download", "--inventory", str(inventory),
            "--data", str(data), "--packages", str(packages), "--base-url", f"http://127.0.0.1:{server.server_port}",
            "--jobs", "2", "--compression", "xz", "--level", "3", "--min-free-gib", "0"]
        subprocess.run(command, check=True)
    finally:
        server.shutdown()
    args = argparse.Namespace(data=data, packages=packages, volume_mib=1, flush_seconds=999999, remove_packed_blobs=False)
    packager = pipeline.Packager(args)
    records = pipeline.all_records(args)
    large = next(record for record in records if record["key"] == "reporting/large.json")
    packager.offer(large)
    assert len(packager.volumes) >= 2, "Fixture must span several volumes"
    assert packager.current is not None, "Fixture must have a final partial volume"
    # Simulate a process ending with an uncommitted final ZIP. Restart must trust
    # only .json commit markers and resume exactly at the last committed offset.
    packager.current.close()
    resumed = pipeline.Packager(args)
    assert 0 < resumed.covered[large["object_id"]] < large["blob_size"]
    for record in records:
        resumed.offer(record)
    resumed.finish()
    subprocess.run([sys.executable, "scripts/restore_reporting.py", "--packages", str(packages),
        "--inventory", str(inventory), "--destination", str(data/"restored"), "--report", str(data/"verification.json")], check=True)
    for key, original in values.items():
        assert (data/"restored"/key).read_bytes() == original, key
    assert all(path.stat().st_size <= 1024*1024 for path in packages.glob("*.zip"))
    before = len(list(packages.glob("*.zip")))
    restarted = pipeline.Packager(args)
    for record in records:
        restarted.offer(record)
    restarted.finish()
    assert len(list(packages.glob("*.zip"))) == before, "Completed restart must create no duplicate volumes"
    # A modified part must be rejected, even if a ZIP's CRC is self-consistent.
    loaded, parts, _ = restore.load_archive(packages, True)
    target = dict(loaded[large["object_id"]])
    target["source_sha256"] = "0"*64
    try:
        restore.restore_one(target, sorted(parts[target["object_id"]], key=lambda item: item[1]["offset"]), None)
        raise AssertionError("Incorrect source hash was accepted")
    except ValueError as error:
        assert "checksum" in str(error), error
    print(json.dumps({"qa": "passed", "fixture_directory": str(data), "volume_count": before,
        "checks": ["HTTP source MD5", "valid JSON", "original gzip CRC", "multi-volume split", "partial-volume restart",
                   "byte-exact restore", "source hash rejection", "complete restart deduplication", "volume size cap"]}))


if __name__ == "__main__":
    main()
