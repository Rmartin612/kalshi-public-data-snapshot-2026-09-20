#!/usr/bin/env python3
"""Independently verify all eight cloud shards without downloading bulk volumes.

Read-only GitHub API calls and authenticated metadata downloads only. Recovery
was performed on the runners; live cloud SHA256 equality binds those exact ZIP
bytes to their restoration proofs. A separate bulk download can test delivery.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.parse
import zipfile

from public_destination import REPOSITORY, RELEASE_TAG, require_public_destination

ROOT = Path(__file__).resolve().parents[1]
REPO = REPOSITORY
TAG = RELEASE_TAG
APPROVED_PLAN = "96108987421a1b433b431248084e06cd5298ac3a1dcd9decb4f1833845062da2"
EXPECTED_COUNT, EXPECTED_BYTES = 3934, 462291303835
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CANONICAL_VOLUME = re.compile(r"volume-[0-9]+\.zip\Z")
METHOD = "volume_sha256_then_part_sha256_then_blob_sha256_then_lossless_decode_source_sha256_and_md5"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def unique(items, field, label):
    values = {item[field]: item for item in items}
    require(len(values) == len(items), "Duplicate " + label)
    return values


def api(endpoint, pages=False):
    command = ["gh", "api", endpoint]
    if pages:
        command += ["--paginate", "--slurp"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "GitHub read failed")
    return json.loads(result.stdout)


def list_assets(release_id):
    pages = api(f"repos/{REPO}/releases/{release_id}/assets?per_page=100", True)
    return unique([asset for page in pages for asset in page], "name", "cloud asset names")


def asset_identity(asset):
    return {key: asset[key] for key in ("id", "name", "size", "digest", "state")}


def check_receipt(receipt, live):
    name = receipt["name"]
    require(name in live, "Missing cloud asset: " + name)
    asset = live[name]
    require(HEX64.fullmatch(receipt["sha256"]) is not None, "Invalid asset hash: " + name)
    require(asset["state"] == "uploaded" and asset["id"] == receipt["asset_id"]
            and asset["size"] == receipt["bytes"] and asset["digest"] == "sha256:" + receipt["sha256"],
            "Live cloud metadata differs from receipt: " + name)
    # Publication changes GitHub's draft 'untagged-*' browser URL. The immutable
    # asset ID and content digest bind bytes; a captured URL is provenance only.
    require(receipt["cloud_digest"] == asset["digest"], "Receipt digest differs from cloud asset: " + name)
    return asset


def download_metadata(asset, destination, max_bytes):
    require(Path(asset["name"]).name == asset["name"], "Unsafe cloud asset filename")
    require(asset["state"] == "uploaded" and 0 < asset["size"] <= max_bytes, "Invalid metadata asset size/state")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest", "")) is not None, "Cloud SHA256 unavailable")
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / asset["name"]
    if not target.exists() or target.stat().st_size != asset["size"] or "sha256:" + sha(target) != asset["digest"]:
        partial = target.with_name(target.name + ".partial")
        with partial.open("wb") as output:
            result = subprocess.run(["gh", "api", f"repos/{REPO}/releases/assets/{asset['id']}",
                                     "-H", "Accept: application/octet-stream"], stdout=output,
                                    stderr=subprocess.PIPE, timeout=300)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace").strip() or "Metadata download failed")
        require(partial.stat().st_size == asset["size"] and "sha256:" + sha(partial) == asset["digest"],
                "Downloaded metadata checksum mismatch: " + asset["name"])
        os.replace(partial, target)
    return target


def safe_extract(control, destination, index):
    top = {"PLAN.json", f"inventory-{index:02d}.json", "RESTORE_VERIFICATION.json", "CLOUD_UPLOADS.json", "SHARD_PROOF.json"}
    pattern = re.compile(r"(?:records|recovery-receipts)/[0-9a-f]{64}\.json\Z|volumes/volume-[0-9]{6}\.json\Z")
    paths = {}
    destination.mkdir(parents=True, exist_ok=True)
    base = destination.resolve()
    with zipfile.ZipFile(control) as archive:
        infos = archive.infolist()
        require(len(infos) == len({item.filename for item in infos}), "Duplicate control ZIP paths")
        require(len(infos) <= 10000 and sum(item.file_size for item in infos) <= 512 * 1024**2,
                "Control ZIP metadata exceeds safe limits")
        for item in infos:
            name = item.filename
            require(name in top or pattern.fullmatch(name) is not None, "Unexpected control ZIP path: " + name)
            require(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16)
                    and not (item.flag_bits & 1) and item.file_size <= 64 * 1024**2,
                    "Unsupported control ZIP entry: " + name)
            target = destination.joinpath(*name.split("/"))
            require(target.resolve().is_relative_to(base), "Control ZIP path leaves verification directory")
            target.parent.mkdir(parents=True, exist_ok=True)
            content = archive.read(item)  # Reads through ZIP CRC checking.
            target.write_bytes(content)
            paths[name] = target
    require(top <= set(paths), "Missing required control metadata")
    return paths


def load_plan(plan_path, inventory_path):
    require(sha(plan_path) == APPROVED_PLAN, "Plan does not match the specifically approved SHA256")
    plan = read(plan_path)
    require(plan["repository"] == REPO and plan["release_tag"] == TAG and plan["jobs"] == 8
            and plan.get("expected_repository_visibility") == "public",
            "Unexpected approved destination/job plan")
    require(sha(inventory_path) == plan["full_inventory_sha256"], "Full source inventory hash differs")
    source = [item for item in read(inventory_path) if not item["key"].endswith("/")]
    full = unique(source, "key", "full source keys")
    require(len(full) == EXPECTED_COUNT == plan["source_object_count"]
            and sum(item["size"] for item in full.values()) == EXPECTED_BYTES == plan["source_bytes"],
            "Full source count/byte total differs from approved corpus")
    shards = unique(plan["shards"], "index", "shard indexes")
    require(set(shards) == set(range(8)), "Expected exactly eight shard indexes")
    seen = set()
    inventories = {}
    for index, shard in shards.items():
        require(shard["filename"] == f"inventory-{index:02d}.json"
                and shard["sequence_start"] == (index + 1) * 100000, "Unexpected shard filenames/sequences")
        path = plan_path.parent / shard["filename"]
        require(sha(path) == shard["inventory_sha256"], "Frozen shard SHA256 differs")
        rows = unique(read(path), "key", "shard source keys")
        require(len(rows) == shard["objects"] and sum(item["size"] for item in rows.values()) == shard["source_bytes"],
                "Frozen shard totals differ")
        require(not (seen & set(rows)) and all(full.get(key) == row for key, row in rows.items()),
                "Frozen shards overlap or differ from full source inventory")
        seen.update(rows)
        inventories[index] = rows
    require(seen == set(full), "Frozen shards do not cover exact full inventory")
    return plan, full, shards, inventories


def verify_shard(index, marker, paths, plan, shard, expected, live, release_id):
    bindings = {"status": "COMPLETE", "shard": index, "repository": REPO, "release_id": release_id,
                "release_tag": TAG, "plan_sha256": APPROVED_PLAN, "full_inventory_sha256": plan["full_inventory_sha256"],
                "shard_inventory_sha256": shard["inventory_sha256"], "source_object_count": shard["objects"],
                "source_bytes": shard["source_bytes"]}
    require(all(marker.get(key) == value for key, value in bindings.items()), "Shard completion bindings differ")
    require(str(marker.get("workflow_run_id", "")).isdigit() and str(marker.get("workflow_run_attempt", "")).isdigit(),
            "Missing workflow run provenance")
    require(sha(paths["PLAN.json"]) == APPROVED_PLAN and sha(paths[shard["filename"]]) == shard["inventory_sha256"],
            "Cloud control plan/shard inventory differs from approved bytes")
    require(read(paths["SHARD_PROOF.json"]) == {key: value for key, value in marker.items() if key != "control_asset"},
            "Internal shard proof differs from cloud completion marker")
    require(sha(paths["RESTORE_VERIFICATION.json"]) == marker["restore_proof_sha256"], "Restore proof SHA256 differs")
    proof = read(paths["RESTORE_VERIFICATION.json"])
    require(proof.get("status") == "COMPLETE" and proof.get("exact_inventory_coverage_checked") is True
            and proof.get("all_restored_bytes_hashed") is True and proof.get("missing_objects") == []
            and proof.get("inventory_sha256") == shard["inventory_sha256"], "Incomplete/unbound runner restoration proof")
    for field in ("object_count", "expected_object_count"):
        require(proof[field] == shard["objects"], "Restoration object count differs")
    for field in ("source_bytes", "expected_source_bytes"):
        require(proof[field] == shard["source_bytes"], "Restoration source bytes differ")
    records = {Path(name).stem: read(path) for name, path in paths.items() if name.startswith("records/")}
    receipts = {Path(name).stem: read(path) for name, path in paths.items() if name.startswith("recovery-receipts/")}
    by_key = unique(list(records.values()), "key", "acquisition record source keys")
    require(set(by_key) == set(expected) and set(receipts) == set(records), "Source records/recovery receipt coverage differs")
    proof_objects = unique(proof["objects"], "key", "restoration proof source keys")
    require(set(proof_objects) == set(expected), "Restoration proof key coverage differs")
    cloud = unique(marker["volumes"], "name", "completion volume names")
    require(unique(read(paths["CLOUD_UPLOADS.json"]), "name", "cloud receipt names") == cloud, "Cloud receipt lists differ")
    recovered_volumes = unique(proof["volumes"], "name", "restoration volume names")
    journals = {read(path)["filename"]: (read(path), path) for name, path in paths.items() if name.startswith("volumes/")}
    require(len(journals) == len([name for name in paths if name.startswith("volumes/")]), "Duplicate volume sidecar names")
    require(set(cloud) == set(journals) == set(recovered_volumes)
            and len(cloud) == marker["volume_count"] == proof["volume_count"], "Volume coverage differs across proofs")
    ordered_names = [f"volume-{shard['sequence_start'] + offset:06d}.zip" for offset in range(len(cloud))]
    require(set(cloud) == set(ordered_names), "Unexpected or noncontiguous shard volume sequences")
    parts = {identity: [] for identity in records}
    for name, (journal, path) in journals.items():
        receipt, restored = cloud[name], recovered_volumes[name]
        check_receipt(receipt, live)
        require(path.name == Path(name).with_suffix(".json").name and journal["sequence"] == int(name[7:-4]), "Sidecar name/sequence differs")
        require(journal["zip_crc_check"] == "passed" and journal["bytes"] == receipt["bytes"] == restored["bytes"]
                and journal["sha256"] == receipt["sha256"] == restored["sha256"]
                and sha(path) == restored["sidecar_sha256"], "Volume bytes/hash differs across proofs")
        local = unique(journal["objects"], "object_id", "volume object identifiers")
        require(all(identity in records and records[identity] == record for identity, record in local.items()), "Volume source metadata differs")
        entries = journal["entries"]
        require(len({part["name"] for part in entries}) == len(entries)
                and {part["object_id"] for part in entries} == set(local), "Unbound or duplicate volume entries")
        for part in entries:
            identity, offset, length = part["object_id"], part["offset"], part["length"]
            require(isinstance(offset, int) and isinstance(length, int) and offset >= 0 and length > 0
                    and HEX64.fullmatch(part["sha256"]) is not None
                    and part["name"] == f"objects/{identity}/part-{offset:016d}.bin", "Invalid volume part metadata")
            parts[identity].append({"volume": name, "volume_sha256": journal["sha256"], "entry": part})
    summary_objects = []
    for identity, record in records.items():
        key = record["key"]
        original, receipt = expected[key], receipts[identity]
        require(identity == hashlib.sha256(key.encode()).hexdigest() == record["object_id"] and record["status"] == "verified",
                "Source object identity/status differs")
        require(record["source_size"] == original["size"] and record["inventory_etag"] == original["etag"]
                and record["inventory_last_modified"] == original["last_modified"], "Source record differs from frozen inventory")
        require(record["source_url"] == "https://kalshi-public-docs.s3.amazonaws.com/" + urllib.parse.quote(key, safe="/"), "Unexpected source URL")
        require(HEX64.fullmatch(record["source_sha256"]) is not None and HEX64.fullmatch(record["blob_sha256"]) is not None
                and re.fullmatch(r"[0-9a-f]{32}", record["source_md5"]) is not None, "Invalid source/blob hash")
        require(record["compression"] == ("identity" if key.endswith(".gz") else "gzip"), "Unexpected preservation encoding")
        if record["compression"] == "identity":
            require(record["blob_size"] == record["source_size"] and record["blob_sha256"] == record["source_sha256"], "Identity encoding changed source bytes")
        dependencies = sorted(parts[identity], key=lambda item: item["entry"]["offset"])
        offset = 0
        for dependency in dependencies:
            require(dependency["entry"]["offset"] == offset, "Missing/overlapping/duplicate source-object parts: " + key)
            offset += dependency["entry"]["length"]
        require(offset == record["blob_size"] and offset > 0, "Incomplete source-object part coverage: " + key)
        fingerprint = canonical_hash({"inventory_sha256": shard["inventory_sha256"], "record": record, "parts": dependencies})
        require(receipt == proof_objects[key] and receipt["verified"] is True and receipt["key"] == key
                and receipt["inventory_sha256"] == shard["inventory_sha256"] and receipt["input_fingerprint"] == fingerprint
                and receipt["dependencies"] == dependencies and receipt["method"] == METHOD, "Unbound source recovery receipt: " + key)
        for field in ("source_size", "source_sha256", "source_md5", "blob_size", "blob_sha256"):
            require(receipt[field] == record[field], "Recovered source/blob value differs: " + key)
        summary_objects.append({"key": key, "source_size": record["source_size"], "source_sha256": record["source_sha256"],
                                "source_md5": record["source_md5"], "blob_sha256": record["blob_sha256"],
                                "shard": index, "recovery_input_fingerprint": fingerprint,
                                "volumes": sorted({item["volume"] for item in dependencies})})
    return {"index": index, "source_object_count": len(records), "source_bytes": sum(item["source_size"] for item in records.values()),
            "volume_count": len(cloud), "restore_proof_sha256": marker["restore_proof_sha256"],
            "workflow_run_id": str(marker["workflow_run_id"]), "workflow_run_attempt": str(marker["workflow_run_attempt"]),
            "objects": summary_objects, "volumes": list(cloud.values())}


def main():
    global REPO, TAG, APPROVED_PLAN
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-id", type=int, required=True)
    parser.add_argument("--plan", type=Path, default=ROOT / "acceleration/frozen/PLAN.json")
    parser.add_argument("--inventory", type=Path, default=ROOT / "discovery/s3-reporting-manifest.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "acceleration-runtime/cloud-verification")
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--release-tag", default=TAG)
    parser.add_argument("--plan-sha256", default=APPROVED_PLAN)
    args = parser.parse_args()
    REPO, TAG, APPROVED_PLAN = args.repo, args.release_tag, args.plan_sha256
    folder = args.output_dir / f"release-{args.release_id}"
    report_path = folder / "CLOUD_SNAPSHOT_VERIFICATION.json"
    report = {"status": "INCOMPLETE", "attempted_at": now(), "repository": REPO,
              "release_id": args.release_id, "approved_plan_sha256": APPROVED_PLAN, "verified_shards": []}
    save(report_path, report)
    try:
        plan, full, shards, inventories = load_plan(args.plan, args.inventory)
        repository = api(f"repos/{REPO}")
        release = api(f"repos/{REPO}/releases/{args.release_id}")
        require_public_destination(repository, release, REPO, TAG)
        live = list_assets(args.release_id)
        expected_markers = {f"SHARD-{index:02d}-COMPLETE.json" for index in range(8)}
        observed_markers = {name for name in live if re.fullmatch(r"SHARD-[0-9]+-COMPLETE\.json", name)}
        require(observed_markers == expected_markers, "Missing/extra completion markers: " + str(sorted(expected_markers - observed_markers)))
        verified = []
        metadata_names = set()
        for index in range(8):
            name = f"SHARD-{index:02d}-COMPLETE.json"
            marker_path = download_metadata(live[name], folder / "downloads", 8 * 1024**2)
            marker = read(marker_path)
            expected_control = f"shard-{index:02d}-control.zip"
            require(marker["control_asset"]["name"] == expected_control, "Unexpected control asset name")
            control_asset = check_receipt(marker["control_asset"], live)
            control = download_metadata(control_asset, folder / "downloads", 512 * 1024**2)
            paths = safe_extract(control, folder / "extracted" / f"shard-{index:02d}", index)
            result = verify_shard(index, marker, paths, plan, shards[index], inventories[index], live, args.release_id)
            result["marker_asset"] = asset_identity(live[name])
            result["control_asset"] = asset_identity(control_asset)
            verified.append(result)
            metadata_names.update((name, expected_control))
            report["verified_shards"].append(index)
            save(report_path, report)
            print(json.dumps({"event": "shard_cloud_proof_verified", "shard": index,
                              "objects": result["source_object_count"], "source_bytes": result["source_bytes"]}), flush=True)
        objects = unique([item for shard in verified for item in shard["objects"]], "key", "cross-shard source keys")
        volumes = unique([item for shard in verified for item in shard["volumes"]], "name", "cross-shard volume names")
        require(set(objects) == set(full) and len(objects) == EXPECTED_COUNT
                and sum(item["source_size"] for item in objects.values()) == EXPECTED_BYTES, "Full-corpus exact coverage failed")
        require(len({item["workflow_run_id"] for item in verified}) == 1
                and len({item["workflow_run_attempt"] for item in verified}) == 1, "Shard run provenance is inconsistent")
        require(set(volumes) == {name for name in live if CANONICAL_VOLUME.fullmatch(name)}, "Missing or extra canonical cloud volume assets")
        fresh = list_assets(args.release_id)
        require(set(volumes) == {name for name in fresh if CANONICAL_VOLUME.fullmatch(name)}, "Cloud volume set changed during audit")
        require({name for name in fresh if re.fullmatch(r"SHARD-[0-9]+-COMPLETE\.json", name)} == expected_markers,
                "Cloud completion marker set changed during audit")
        for name in set(volumes) | metadata_names:
            require(name in fresh and asset_identity(fresh[name]) == asset_identity(live[name]), "Cloud asset changed during audit: " + name)
        require_public_destination(api(f"repos/{REPO}"), api(f"repos/{REPO}/releases/{args.release_id}"), REPO, TAG)
        report = {"status": "COMPLETE", "verified_at": now(), "repository": repository["html_url"], "private": False, "visibility": "public",
                  "release_id": args.release_id, "release_tag": TAG, "release_url": release["html_url"],
                  "approved_plan_sha256": APPROVED_PLAN, "full_inventory_sha256": plan["full_inventory_sha256"],
                  "source_object_count": len(objects), "source_bytes": EXPECTED_BYTES, "shard_count": 8,
                  "volume_count": len(volumes), "cloud_volume_bytes": sum(item["bytes"] for item in volumes.values()),
                  "all_metadata_download_hashes_match": True, "all_cloud_volume_sha256_match": True,
                  "exact_disjoint_source_union": True, "every_source_bound_to_runner_recovery_proof": True,
                  "bulk_volumes_downloaded_by_this_verifier": False,
                  "method": "Authenticated metadata-byte verification, exact approved-inventory coverage, recomputed source-recovery fingerprints, and live cloud-volume SHA256 equivalence to runner-restored ZIPs.",
                  "shards": verified, "objects": list(objects.values()), "volumes": list(volumes.values())}
        save(report_path, report)
        print(json.dumps({key: value for key, value in report.items() if key not in ("shards", "objects", "volumes")}, indent=2))
        print("Full verification report: " + str(report_path))
        return 0
    except Exception as error:
        report.update(status="INCOMPLETE", error=str(error), failed_at=now())
        save(report_path, report)
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
