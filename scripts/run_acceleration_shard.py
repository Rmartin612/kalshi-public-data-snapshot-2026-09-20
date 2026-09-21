#!/usr/bin/env python3
"""Preserve one approved cloud shard; upload committed ZIPs while acquisition runs.

Only a short-lived GH_TOKEN is used through gh CLI. No Actions artifacts/cache.
A completion marker is uploaded only after exact recovery and cloud verification.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile

from public_destination import REPOSITORY, RELEASE_TAG, require_public_destination


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024*1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")


def gh(*args, timeout=600):
    result = subprocess.run(["gh", *map(str, args)], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def assets(repo, release_id):
    pages = json.loads(gh("api", "--paginate", "--slurp", f"repos/{repo}/releases/{release_id}/assets?per_page=100"))
    return {asset["name"]: asset for page in pages for asset in page}


def upload(path, repo, tag, release_id):
    size, digest = path.stat().st_size, sha(path)
    if size >= 2*1024**3:
        raise ValueError("Release asset exceeds per-file limit")
    current = assets(repo, release_id).get(path.name)
    if current and (current.get("digest") != "sha256:"+digest or current.get("size") != size):
        raise ValueError("Existing cloud asset differs; refusing overwrite: "+path.name)
    for attempt in range(3):
        if current:
            break
        try:
            gh("release", "upload", tag, path, "--repo", repo)
        except Exception:
            current = assets(repo, release_id).get(path.name)
            if current is None and attempt == 2:
                raise
            if current is None:
                time.sleep(5*(attempt+1))
                continue
        current = assets(repo, release_id).get(path.name)
    if not current or current.get("state") != "uploaded" or current.get("size") != size or current.get("digest") != "sha256:"+digest:
        raise ValueError("Cloud upload size/digest verification failed: "+path.name)
    receipt = {"name": path.name, "bytes": size, "sha256": digest, "asset_id": current["id"],
        "cloud_digest": current["digest"], "url": current["browser_download_url"], "verified_at": now()}
    print(json.dumps({"event": "cloud_asset_verified", **receipt}), flush=True)
    return receipt


def run(*args):
    subprocess.run([sys.executable, *map(str, args)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, required=True, choices=range(8))
    parser.add_argument("--release-id", type=int, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--plan", type=Path, default=Path("acceleration/frozen/PLAN.json"))
    parser.add_argument("--repo", default=REPOSITORY)
    parser.add_argument("--release-tag", default=RELEASE_TAG)
    args = parser.parse_args()
    if not args.plan.exists() or sha(args.plan) != args.plan_sha256:
        raise ValueError("Missing or changed approved frozen plan")
    plan = read(args.plan)
    if (plan["repository"] != args.repo or plan["release_tag"] != args.release_tag
            or plan.get("expected_repository_visibility") != "public"):
        raise ValueError("Unexpected cloud destination")
    if (plan["jobs"] != 8 or plan["timeout_minutes_each"] != 45 or len(plan["shards"]) != 8
            or plan["compression"] != "gzip" or plan["compression_level"] != 6):
        raise ValueError("Unexpected approved job envelope")
    if sha(Path("discovery/s3-reporting-manifest.json")) != plan["full_inventory_sha256"]:
        raise ValueError("Full source inventory changed")
    full = {item["key"]: item for item in read(Path("discovery/s3-reporting-manifest.json")) if not item["key"].endswith("/")}
    seen = set()
    for shard in plan["shards"]:
        path = args.plan.parent/shard["filename"]
        if sha(path) != shard["inventory_sha256"]:
            raise ValueError("Shard inventory changed")
        contents = read(path)
        if len(contents) != shard["objects"] or sum(item["size"] for item in contents) != shard["source_bytes"]:
            raise ValueError("Shard totals differ from approved plan")
        for item in contents:
            if item["key"] in seen or full.get(item["key"]) != item:
                raise ValueError("Shard inventories overlap or differ from full inventory")
            seen.add(item["key"])
    if seen != set(full):
        raise ValueError("Shards do not cover every source key exactly once")
    shard = plan["shards"][args.shard]
    inventory = args.plan.parent/shard["filename"]
    repo, tag = plan["repository"], plan["release_tag"]
    if os.environ.get("GITHUB_REPOSITORY") != repo:
        raise ValueError("Workflow repository differs from the reviewed public destination")
    if not shutil.which("gh") or not os.environ.get("GH_TOKEN"):
        raise ValueError("GitHub CLI and short-lived workflow GH_TOKEN are required")
    release = json.loads(gh("api", f"repos/{repo}/releases/{args.release_id}"))
    repository = json.loads(gh("api", f"repos/{repo}"))
    require_public_destination(repository, release, repo, tag, draft=True)
    suffix = f"{args.shard:02d}"
    if f"SHARD-{suffix}-COMPLETE.json" in assets(repo, args.release_id):
        raise ValueError("Shard completion already exists; do not rerun a completed job")
    work = Path("acceleration-runtime")/f"shard-{suffix}"
    data, packages, audit = work/"data", work/"packages", work/"verification"
    work.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(work).free < 8*1024**3:
        raise ValueError("Cloud runner has less than 8 GiB free staging space")
    command = [sys.executable, "scripts/archive_reporting.py", "download", "--inventory", str(inventory),
        "--data", str(data), "--packages", str(packages), "--package", "--compression", "gzip", "--level", "6",
        "--jobs", "2", "--sequence-start", str(shard["sequence_start"]), "--volume-mib", "512",
        "--flush-seconds", "120", "--min-free-gib", "2", "--remove-packed-blobs"]
    volume_receipts = {}

    def upload_ready():
        for sidecar in sorted(packages.glob("volume-*.json")):
            journal = read(sidecar)
            if journal["filename"] in volume_receipts:
                continue
            path = packages/journal["filename"]
            receipt = upload(path, repo, tag, args.release_id)
            if receipt["sha256"] != journal["sha256"] or receipt["bytes"] != journal["bytes"]:
                raise ValueError("Cloud volume differs from committed immutable volume")
            volume_receipts[path.name] = receipt
            save(work/"CLOUD_UPLOADS.json", list(volume_receipts.values()))

    process = subprocess.Popen(command)
    try:
        while process.poll() is None:
            upload_ready()
            time.sleep(3)
        if process.returncode:
            raise RuntimeError(f"Downloader exited {process.returncode}; already uploaded volumes remain partial")
        upload_ready()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    status = read(data/"status.json")
    if (status["source_objects_verified"] != shard["objects"] or status["objects_fully_packaged"] != shard["objects"]
            or status["objects_missing"] or status["failed"]):
        raise ValueError("Not every shard source was downloaded and packaged")
    proof_path = work/"RESTORE_VERIFICATION.json"
    run("scripts/verify_streaming.py", "--inventory", inventory, "--packages", packages,
        "--audit-dir", audit, "--report", proof_path, "--jobs", "2")
    proof = read(proof_path)
    if proof["status"] != "COMPLETE" or proof["object_count"] != shard["objects"] or proof["source_bytes"] != shard["source_bytes"]:
        raise ValueError("Shard exact-byte recovery proof is incomplete")
    # Fresh server-side digest read-back after complete local recovery verification.
    remote = assets(repo, args.release_id)
    for receipt in volume_receipts.values():
        asset = remote.get(receipt["name"])
        if not asset or asset.get("id") != receipt["asset_id"] or asset.get("size") != receipt["bytes"] or asset.get("digest") != "sha256:"+receipt["sha256"] or asset.get("state") != "uploaded":
            raise ValueError("Cloud volume changed before shard completion")
    completion = {"status": "COMPLETE", "shard": args.shard, "completed_at": now(),
        "repository": repo, "release_id": args.release_id, "release_tag": tag,
        "plan_sha256": args.plan_sha256, "full_inventory_sha256": plan["full_inventory_sha256"],
        "shard_inventory_sha256": shard["inventory_sha256"], "source_object_count": shard["objects"],
        "source_bytes": shard["source_bytes"], "volume_count": len(volume_receipts), "volumes": list(volume_receipts.values()),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"), "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "restore_proof_sha256": sha(proof_path)}
    save(work/"SHARD_PROOF.json", completion)
    control = work/f"shard-{suffix}-control.zip"
    with zipfile.ZipFile(control, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as target:
        for path in (args.plan, inventory, proof_path, work/"CLOUD_UPLOADS.json", work/"SHARD_PROOF.json"):
            target.write(path, path.name)
        for folder, prefix in ((data/"records", "records"), (audit/"objects", "recovery-receipts"), (packages, "volumes")):
            for path in sorted(folder.glob("*.json")):
                target.write(path, prefix+"/"+path.name)
    completion["control_asset"] = upload(control, repo, tag, args.release_id)
    marker = work/f"SHARD-{suffix}-COMPLETE.json"
    save(marker, completion)
    marker_receipt = upload(marker, repo, tag, args.release_id)
    print(json.dumps({"event": "shard_complete", "shard": args.shard,
        "source_objects": shard["objects"], "source_bytes": shard["source_bytes"],
        "completion_asset": marker_receipt}), flush=True)


if __name__ == "__main__":
    main()
