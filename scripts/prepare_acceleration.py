#!/usr/bin/env python3
"""Preview/freeze eight complete-corpus cloud shards. Never starts Actions."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

from public_destination import REPOSITORY, RELEASE_TAG, EXPECTED_VISIBILITY


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=Path("discovery/s3-reporting-manifest.json"))
    parser.add_argument("--output", type=Path, default=Path("acceleration/frozen"))
    parser.add_argument("--freeze", action="store_true", help="Write the local immutable review snapshot; does not start a workflow or spend money")
    parser.add_argument("--repo", default=REPOSITORY)
    parser.add_argument("--release-tag", default=RELEASE_TAG)
    args = parser.parse_args()
    source = [item for item in json.loads(args.inventory.read_text(encoding="utf-8-sig")) if not item["key"].endswith("/")]
    if len({item["key"] for item in source}) != len(source):
        raise ValueError("Duplicate source keys")
    if len(source) != 3934 or sum(item["size"] for item in source) != 462291303835:
        raise ValueError("Unexpected full-source inventory; review before creating any workflow")
    shards, loads = [[] for _ in range(8)], [0]*8
    for item in sorted(source, key=lambda item: (-item["size"], item["key"])):
        index = min(range(8), key=lambda candidate: (loads[candidate], candidate))
        shards[index].append(item)
        loads[index] += item["size"]
    plan = {"format_version": 1, "full_inventory_sha256": digest(args.inventory),
        "source_object_count": len(source), "source_bytes": sum(loads),
        "jobs": 8, "timeout_minutes_each": 45, "nominal_max_runner_minutes": 360,
        "expected_standard_public_runner_compute_usd": 0,
        "billing_note": "Public repository with standard ubuntu-24.04 hosted runners only. No larger runners, caches or Actions artifacts.",
        "expected_repository_visibility": EXPECTED_VISIBILITY,
        "repository": args.repo, "release_tag": args.release_tag,
        "compression": "gzip", "compression_level": 6, "jobs_per_shard": 2, "volume_mib": 512,
        "shards": [{"index": index, "objects": len(items), "source_bytes": loads[index],
            "original_gzip_bytes": sum(item["size"] for item in items if item["key"].endswith(".gz")),
            "sequence_start": (index+1)*100000} for index, items in enumerate(shards)]}
    if not args.freeze:
        print(json.dumps({"mode": "read_only_preview", **plan}, indent=2))
        return
    if args.output.exists():
        raise FileExistsError("Refusing to replace an existing frozen snapshot")
    for index, items in enumerate(shards):
        path = args.output/f"inventory-{index:02d}.json"
        save(path, sorted(items, key=lambda item: item["key"]))
        plan["shards"][index].update(filename=path.name, inventory_sha256=digest(path))
    plan["frozen_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    save(args.output/"PLAN.json", plan)
    print(json.dumps({"frozen": True, "directory": str(args.output), "plan_sha256": digest(args.output/"PLAN.json")}, indent=2))


if __name__ == "__main__":
    main()
