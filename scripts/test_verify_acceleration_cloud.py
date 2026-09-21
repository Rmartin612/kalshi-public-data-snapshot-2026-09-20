"""Offline proof-binding and extraction tests. No API calls or cloud writes."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import zipfile

import archive_reporting as packaging
import verify_acceleration_cloud as check
import verify_streaming as recovery


def expect_failure(action, text):
    try:
        action()
    except (ValueError, KeyError) as error:
        assert text.lower() in str(error).lower(), str(error)
    else:
        raise AssertionError("Invalid evidence was accepted")


def main():
    work = check.ROOT / "acceleration-runtime" / ("verifier-qa-" + str(time.time_ns()))
    data, packages = work / "data", work / "packages"
    (data / "blobs").mkdir(parents=True)
    packages.mkdir()
    values = {"reporting/fixture-large.json": json.dumps({"payload": os.urandom(1300000).hex()}).encode(),
              "reporting/fixture-small.json": b'[{"fixture":true}]',
              "reporting/fixture-gzip.json.gz": gzip.compress(b'[{"original_gzip":true}]', mtime=0)}
    inventory, records = [], []
    for key, raw in values.items():
        identity = hashlib.sha256(key.encode()).hexdigest()
        blob = raw if key.endswith(".gz") else gzip.compress(raw, compresslevel=6, mtime=0)
        etag = '"' + hashlib.md5(raw).hexdigest() + '"'
        inventory.append({"key": key, "size": len(raw), "etag": etag, "last_modified": "2026-09-21T00:00:00Z"})
        record = {"status": "verified", "object_id": identity, "key": key,
                  "source_size": len(raw), "source_sha256": hashlib.sha256(raw).hexdigest(), "source_md5": hashlib.md5(raw).hexdigest(),
                  "source_url": "https://kalshi-public-docs.s3.amazonaws.com/" + key,
                  "inventory_etag": etag, "inventory_last_modified": "2026-09-21T00:00:00Z",
                  "compression": "identity" if key.endswith(".gz") else "gzip",
                  "blob_filename": identity + ".blob", "blob_size": len(blob), "blob_sha256": hashlib.sha256(blob).hexdigest()}
        (data / "blobs" / record["blob_filename"]).write_bytes(blob)
        records.append(record)
        check.save(data / "records" / (identity + ".json"), record)
    inventory_path = work / "inventory-00.json"
    check.save(inventory_path, inventory)
    pack = packaging.Packager(argparse.Namespace(data=data, packages=packages, volume_mib=1,
                                                sequence_start=100000, flush_seconds=99999, remove_packed_blobs=False))
    for record in records:
        pack.offer(record)
    pack.finish()
    proof_path = work / "RESTORE_VERIFICATION.json"
    audit = recovery.Audit(argparse.Namespace(inventory=inventory_path, packages=packages,
                                             audit_dir=work / "audit", report=proof_path))
    audit.discover()
    for job in audit.completed():
        identity, receipt = audit.verify(job)
        audit.verified[identity] = receipt
    audit.status(True)
    assert len(audit.volumes) > 1, "Fixture must exercise split objects"
    plan = {"full_inventory_sha256": check.sha(inventory_path)}
    plan_path = work / "PLAN.json"
    check.save(plan_path, plan)
    shard = {"filename": inventory_path.name, "inventory_sha256": check.sha(inventory_path),
             "objects": len(records), "source_bytes": sum(item["source_size"] for item in records), "sequence_start": 100000}
    cloud, live = [], {}
    for index, path in enumerate(sorted(packages.glob("*.zip"))):
        name, digest, size = path.name, check.sha(path), path.stat().st_size
        receipt = {"name": name, "sha256": digest, "bytes": size, "asset_id": index + 1,
                   "cloud_digest": "sha256:" + digest, "url": "https://example.test/" + name}
        cloud.append(receipt)
        live[name] = {"name": name, "id": index + 1, "size": size, "state": "uploaded", "digest": "sha256:" + digest,
                      "browser_download_url": receipt["url"]}
    original_approved = check.APPROVED_PLAN
    check.APPROVED_PLAN = check.sha(plan_path)
    marker = {"status": "COMPLETE", "shard": 0, "repository": check.REPO, "release_id": 123,
              "release_tag": check.TAG, "plan_sha256": check.APPROVED_PLAN, "full_inventory_sha256": plan["full_inventory_sha256"],
              "shard_inventory_sha256": shard["inventory_sha256"], "source_object_count": shard["objects"],
              "source_bytes": shard["source_bytes"], "volume_count": len(cloud), "volumes": cloud,
              "workflow_run_id": "100", "workflow_run_attempt": "1", "restore_proof_sha256": check.sha(proof_path)}
    check.save(work / "SHARD_PROOF.json", marker)
    check.save(work / "CLOUD_UPLOADS.json", cloud)
    control = work / "shard-00-control.zip"
    with zipfile.ZipFile(control, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in (plan_path, inventory_path, proof_path, work / "SHARD_PROOF.json", work / "CLOUD_UPLOADS.json"):
            archive.write(path, path.name)
        for folder, prefix in ((data / "records", "records"), (work / "audit/objects", "recovery-receipts"), (packages, "volumes")):
            for path in folder.glob("*.json"):
                archive.write(path, prefix + "/" + path.name)
    marker["control_asset"] = {"name": control.name}
    extracted = check.safe_extract(control, work / "extracted", 0)
    expected = {item["key"]: item for item in inventory}
    result = check.verify_shard(0, marker, extracted, plan, shard, expected, live, 123)
    assert result["source_object_count"] == 3 and result["source_bytes"] == shard["source_bytes"]
    first_name = cloud[0]["name"]
    old_digest = live[first_name]["digest"]
    live[first_name]["digest"] = "sha256:" + "0" * 64
    expect_failure(lambda: check.verify_shard(0, marker, extracted, plan, shard, expected, live, 123), "Live cloud metadata differs")
    live[first_name]["digest"] = old_digest
    receipt_path = next(path for name, path in extracted.items() if name.startswith("recovery-receipts/"))
    prior = receipt_path.read_bytes()
    receipt = check.read(receipt_path)
    receipt["input_fingerprint"] = "0" * 64
    check.save(receipt_path, receipt)
    expect_failure(lambda: check.verify_shard(0, marker, extracted, plan, shard, expected, live, 123), "Unbound source recovery")
    receipt_path.write_bytes(prior)
    bad = work / "unsafe.zip"
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("../escape.json", "{}")
    expect_failure(lambda: check.safe_extract(bad, work / "unsafe-output", 0), "Unexpected control ZIP path")
    check.APPROVED_PLAN = original_approved
    actual_plan = check.ROOT / "acceleration/frozen/PLAN.json"
    actual_inventory = check.ROOT / "discovery/s3-reporting-manifest.json"
    plan_result = check.load_plan(actual_plan, actual_inventory)
    assert len(plan_result[1]) == 3934
    # A private destination must fail before any asset inventory is trusted.
    expect_failure(lambda: check.require_public_destination({"private": True, "visibility": "private", "full_name": check.REPO}, {"tag_name": check.TAG}, check.REPO, check.TAG), "expected public")
    expect_failure(lambda: check.require_public_destination({"private": False, "visibility": "public", "full_name": "wrong/repository"}, {"tag_name": check.TAG}, check.REPO, check.TAG), "expected public")
    # Exercise missing-marker reporting without network access.
    original_api, original_list, original_argv = check.api, check.list_assets, sys.argv
    check.api = lambda endpoint, pages=False: {"private": False, "visibility": "public", "full_name": check.REPO} if endpoint == "repos/" + check.REPO else {"tag_name": check.TAG}
    check.list_assets = lambda release_id: {}
    sys.argv = ["verify_acceleration_cloud.py", "--release-id", "123", "--output-dir", str(work / "missing-markers")]
    try:
        assert check.main() == 2
        incomplete = check.read(work / "missing-markers/release-123/CLOUD_SNAPSHOT_VERIFICATION.json")
        assert incomplete["status"] == "INCOMPLETE" and "completion markers" in incomplete["error"]
    finally:
        check.api, check.list_assets, sys.argv = original_api, original_list, original_argv
    print(json.dumps({"status": "PASS", "tests": ["split-gzip-and-original-gzip-proof", "live-cloud-hash-mismatch-rejected",
          "recovery-receipt-tamper-rejected", "zip-path-traversal-rejected", "actual-approved-plan-3934-coverage",
          "missing-markers-remain-INCOMPLETE", "private-and-wrong-repositories-rejected"], "fixture_directory": str(work)}, indent=2))


if __name__ == "__main__":
    main()
