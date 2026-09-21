#!/usr/bin/env python3
"""Build the public cloud snapshot's final metadata bundle, entirely locally.

Requires the independent COMPLETE cloud proof and its exact downloaded metadata.
No network, credential access, uploads, bulk-volume reads, or source restoration.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import zipfile

import verify_acceleration_cloud as proofcheck

ROOT = Path(__file__).resolve().parents[1]
require, read, sha, unique = proofcheck.require, proofcheck.read, proofcheck.sha, proofcheck.unique
EXPECTED_COUNT, EXPECTED_BYTES = 3934, 462291303835
EXPECTED_INVENTORY = "c044fef1eaab07651cfd442be182804d68d23e646fb3a72ab7e114afc111d5e1"
STABLE_RELEASE_URL = f"https://github.com/{proofcheck.REPO}/releases/tag/{proofcheck.TAG}"
PUBLIC_PROVENANCE = ("Volume and OI changes.pdf", "s3-reporting-page-1.xml", "s3-reporting-page-2.xml",
                     "s3-reporting-page-3.xml", "s3-reporting-page-4.xml")


def encode(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def cached_metadata(asset, folder):
    name = asset["name"]
    require(Path(name).name == name and asset["state"] == "uploaded", "Unsafe/unuploaded metadata asset")
    path = folder / "downloads" / name
    require(path.is_file() and path.stat().st_size == asset["size"]
            and "sha256:" + sha(path) == asset["digest"], "Cached cloud metadata bytes changed: " + name)
    return path


def cached_control_paths(control, extracted, index):
    """Validate cached extracted metadata against the verified control ZIP; write nothing."""
    top = {"PLAN.json", f"inventory-{index:02d}.json", "RESTORE_VERIFICATION.json", "CLOUD_UPLOADS.json", "SHARD_PROOF.json"}
    pattern = re.compile(r"(?:records|recovery-receipts)/[0-9a-f]{64}\.json\Z|volumes/volume-[0-9]{6}\.json\Z")
    base, paths = extracted.resolve(), {}
    with zipfile.ZipFile(control) as archive:
        infos = archive.infolist()
        require(len(infos) == len({entry.filename for entry in infos}) and len(infos) <= 10000
                and sum(entry.file_size for entry in infos) <= 512 * 1024**2, "Invalid/oversized control metadata ZIP")
        for entry in infos:
            name = entry.filename
            require(name in top or pattern.fullmatch(name) is not None, "Unexpected control metadata path")
            require(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16)
                    and not entry.flag_bits & 1 and entry.file_size <= 64 * 1024**2, "Unsafe control metadata entry")
            target = extracted.joinpath(*name.split("/"))
            require(target.resolve().is_relative_to(base) and target.is_file(), "Missing/unsafe extracted metadata")
            content = archive.read(entry)
            require(target.stat().st_size == len(content) and sha(target) == hashlib.sha256(content).hexdigest(),
                    "Extracted metadata differs from hash-verified cloud control: " + name)
            paths[name] = target
    require(top <= set(paths), "Missing required control metadata")
    return paths


def validate(root, report_path):
    report = read(report_path)
    require(report.get("status") == "COMPLETE", "Independent cloud verification is not COMPLETE")
    require(report.get("private") is False and report.get("visibility") == "public"
            and report.get("release_tag") == proofcheck.TAG
            and report.get("repository") == "https://github.com/" + proofcheck.REPO,
            "Cloud report destination/privacy differs")
    for field in ("all_metadata_download_hashes_match", "all_cloud_volume_sha256_match", "exact_disjoint_source_union",
                  "every_source_bound_to_runner_recovery_proof"):
        require(report.get(field) is True, "Cloud proof is missing required assurance: " + field)
    require(report.get("source_object_count") == EXPECTED_COUNT and report.get("source_bytes") == EXPECTED_BYTES
            and report.get("shard_count") == 8 and report.get("approved_plan_sha256") == proofcheck.APPROVED_PLAN
            and report.get("full_inventory_sha256") == EXPECTED_INVENTORY, "Cloud report corpus/plan binding differs")
    plan, inventory, shards, shard_inventories = proofcheck.load_plan(root / "acceleration/frozen/PLAN.json",
                                                                  root / "discovery/s3-reporting-manifest.json")
    verified_shards = unique(report["shards"], "index", "cloud report shard indexes")
    require(set(verified_shards) == set(range(8)), "Cloud proof is missing shard results")
    volumes = unique(report["volumes"], "name", "cloud report volume names")
    summaries = unique(report["objects"], "key", "cloud report source keys")
    require(set(summaries) == set(inventory) and len(volumes) == report["volume_count"], "Cloud report coverage differs")
    require(sum(row["bytes"] for row in volumes.values()) == report["cloud_volume_bytes"], "Cloud volume byte sum differs")
    # Simulate the exact live metadata already certified in the terminal report.
    # This rechecks immutable proof bindings; it does not claim a new network read.
    certified = {name: {"name": name, "id": item["asset_id"], "size": item["bytes"], "state": "uploaded",
                        "digest": item["cloud_digest"], "browser_download_url": item["url"]}
                 for name, item in volumes.items()}
    contexts, records, sidecars, receipts = {}, {}, {}, {}
    replayed_shards = []
    for index in range(8):
        shard_result = verified_shards[index]
        marker_asset, control_asset = shard_result["marker_asset"], shard_result["control_asset"]
        require(marker_asset["name"] == f"SHARD-{index:02d}-COMPLETE.json"
                and control_asset["name"] == f"shard-{index:02d}-control.zip", "Unexpected cached metadata asset names")
        marker_path = cached_metadata(marker_asset, report_path.parent)
        control_path = cached_metadata(control_asset, report_path.parent)
        marker = read(marker_path)
        control_receipt = marker["control_asset"]
        require(control_receipt["name"] == control_asset["name"] and control_receipt["asset_id"] == control_asset["id"]
                and control_receipt["bytes"] == control_asset["size"]
                and control_receipt["cloud_digest"] == "sha256:" + control_receipt["sha256"] == control_asset["digest"],
                "Marker/control asset binding differs")
        paths = cached_control_paths(control_path, report_path.parent / "extracted" / f"shard-{index:02d}", index)
        replayed = proofcheck.verify_shard(index, marker, paths, plan, shards[index], shard_inventories[index],
                                          certified, report["release_id"])
        replayed.update(marker_asset=marker_asset, control_asset=control_asset)
        require(replayed == shard_result, "Replayed immutable shard proof differs from terminal cloud report")
        replayed_shards.append(replayed)
        contexts[index] = {"paths": paths, "marker_path": marker_path}
        for name, path in paths.items():
            if name.startswith("records/"):
                record = read(path)
                require(record["key"] not in records, "Duplicate source record across shards")
                records[record["key"]] = record
            elif name.startswith("recovery-receipts/"):
                receipt = read(path)
                require(receipt["key"] not in receipts, "Duplicate source recovery across shards")
                receipts[receipt["key"]] = receipt
            elif name.startswith("volumes/"):
                journal = read(path)
                require(journal["filename"] not in sidecars, "Duplicate volume sidecar across shards")
                sidecars[journal["filename"]] = path
    require(set(records) == set(receipts) == set(summaries) == set(inventory) and set(sidecars) == set(volumes),
            "Combined immutable proof coverage differs")
    require(unique([row for shard in replayed_shards for row in shard["objects"]], "key", "combined source keys") == summaries
            and unique([row for shard in replayed_shards for row in shard["volumes"]], "name", "combined volume names") == volumes,
            "Terminal report combined indexes differ from shard proofs")
    require(sum(row["source_size"] for row in records.values()) == EXPECTED_BYTES, "Combined source byte sum differs")
    return report, inventory, contexts, records, receipts, sidecars, volumes


def indexes(records, receipts, volumes):
    rows, dates = [], {}
    pattern = re.compile(r"reporting/(market_data|trade_data|perps_market_data)_(\d{4}-\d{2}-\d{2})\.json(?:\.gz|\.backup)?\Z")
    for key, record in sorted(records.items()):
        match = pattern.fullmatch(key)
        require(match is not None, "Unexpected source key format in frozen reporting inventory")
        family, date = match.groups()
        groups = collections.defaultdict(list)
        for dependency in receipts[key]["dependencies"]:
            groups[dependency["volume"]].append(dependency["entry"])
        dated = dates.setdefault(date, {"source_keys": [], "datasets": set(), "volume_names": set(), "original_bytes": 0})
        dated["source_keys"].append(key)
        dated["datasets"].add(family)
        dated["volume_names"].update(groups)
        dated["original_bytes"] += record["source_size"]
        for name, parts in sorted(groups.items()):
            rows.append({"source_key": key, "source_date": date, "dataset": family,
                         "backup_object": key.endswith(".backup"), "source_bytes": record["source_size"],
                         "source_sha256": record["source_sha256"], "source_etag": record["inventory_etag"],
                         "blob_compression": record["compression"], "volume_name": name,
                         "volume_sha256": volumes[name]["sha256"],
                         "cloud_asset_url": f"https://github.com/{proofcheck.REPO}/releases/download/{proofcheck.TAG}/{name}",
                         "cloud_asset_url_at_verification": volumes[name]["url"],
                         "parts_in_volume": len(parts), "blob_bytes_in_volume": sum(part["length"] for part in parts)})
    return rows, {date: {**value, "datasets": sorted(value["datasets"]), "volume_names": sorted(value["volume_names"]),
                         "source_count": len(value["source_keys"])} for date, value in sorted(dates.items())}


def instructions(report):
    return f"""# Kalshi market-data cloud snapshot: control files

This bundle indexes all 3,934 original files (462,291,303,835 original bytes)
preserved across eight independent shards and {report['volume_count']} ZIP volumes.
It contains metadata and restoration tools; download bulk volumes separately.

Public release: {STABLE_RELEASE_URL}
Cloud verification timestamp: {report['verified_at']}
Frozen approved plan SHA256: {proofcheck.APPROVED_PLAN}

`reports/CLOUD_SNAPSHOT_VERIFICATION.json` certifies the exact source inventory,
runner restoration proofs, and matching live cloud-volume SHA256 values.
`reports/ACQUISITION_MANIFEST.json` consolidates source metadata and hashes.
The eight `reports/shards/*/RESTORE_VERIFICATION.json` files preserve the detailed
source recovery evidence. This bundle was built locally after those checks;
its creation alone does not mean this control ZIP has been uploaded.

## Restore one day across all shards

`SOURCE_TO_VOLUME.csv` contains one row per source-file/volume pair.
`DATE_TO_VOLUMES.json` provides dates, source keys, and all required volume names.
One source file can span several ZIPs, and each ZIP may contain other dates.
The combined index accounts for splits and all eight shards automatically.

Extract this control ZIP to a new folder. In PowerShell, with GitHub CLI installed
and signed in:

```powershell
$wantedDay = '2026-09-19'
$wanted = Import-Csv .\\SOURCE_TO_VOLUME.csv | Where-Object source_date -eq $wantedDay | Select-Object -ExpandProperty volume_name -Unique
New-Item -ItemType Directory -Force .\\packages | Out-Null
foreach ($name in $wanted) {{ gh release download {proofcheck.TAG} --repo {proofcheck.REPO} --pattern $name --dir .\\packages }}
Copy-Item .\\volume-sidecars\\*.json .\\packages\\
python scripts/restore_reporting.py --packages packages --verify-only --inventory discovery/s3-reporting-manifest.json --include 'reporting/*2026-09-19*' --report day-verification.json
```

After verification, restore that day's exact originals into a new directory:

```powershell
python scripts/restore_reporting.py --packages packages --destination restored-day --inventory discovery/s3-reporting-manifest.json --include 'reporting/*2026-09-19*' --report day-restoration.json
```

Change the date glob to select other files; repeat `--include` for several globs.
The CSV supplies final-tag browser download URLs and retains the URLs captured
during verification in a separate column. Draft `untagged-*` links can change
when the release is published; the commands above use the approved release tag.
Existing restored
files are never overwritten. All necessary parts must be present for each
selected source file. SHA256 verification uses the copied sidecars, then each
part, reassembled blob, and decoded original source bytes.

## Full restoration

Download all ZIP names listed in `VOLUME_SHA256SUMS.txt`, copy the sidecars as
above, and omit `--include`. A full restore needs more than 462,291,303,835 free
bytes plus filesystem overhead. `--verify-only` streams and hashes the same
original bytes without writing the full restored dataset.

Raw JSON objects use an outer gzip layer in this cloud snapshot. Source files
already ending in `.json.gz` retain their original gzip bytes; restoration yields
those exact original gzip files. The helper uses each object's recorded encoding,
so shared ZIPs and split objects across shard sequence ranges restore normally.

## Coverage, units, and bundle integrity

Coverage is the captured public S3 `reporting/` inventory, including two backup
objects and four initial empty arrays. It does not claim inaccessible internal
records or all historical revisions. The four saved public S3 listings establish
the captured source inventory. The official `provenance/Volume and OI changes.pdf`
explains the December 24, 2021 change to counting each Yes/No pair as one contract,
including historical statistics. Daily market and trade files cover June 28, 2021
through September 19, 2026; perps files cover June 1 through September 20, 2026.

`VOLUME_SHA256SUMS.txt` lists bulk volume hashes. `METADATA_SHA256SUMS.txt` hashes
the metadata members and `CONTROL_MANIFEST.json` (the checksum list excludes
itself). The build receipt beside this ZIP records the final ZIP SHA256 and its
local read-back result. `scripts/ARCHIVE_FORMAT.md` describes the general format;
this cloud snapshot uses gzip rather than the document's example XZ setting.

No credentials, tokens, browser state, screenshot, raw dataset, bulk volumes,
runtime logs, or QA fixtures are included. This builder performs no network
requests, uploads, or repeat restoration of the 462 GB source corpus.
"""


def assemble_files(root, report_path, validated):
    report, inventory, contexts, records, receipts, sidecars, volumes = validated
    rows, dates = indexes(records, receipts, volumes)
    files = {}
    allowed = {"discovery/s3-reporting-manifest.json": "discovery/s3-reporting-manifest.json",
               "acceleration/frozen/PLAN.json": "plan/PLAN.json",
               "scripts/restore_reporting.py": "scripts/restore_reporting.py",
               "scripts/ARCHIVE_FORMAT.md": "scripts/ARCHIVE_FORMAT.md"}
    for name in PUBLIC_PROVENANCE:
        allowed["provenance/" + name] = "provenance/" + name
    for relative, member in allowed.items():
        path = root / relative
        require(path.is_file() and path.stat().st_size <= 128 * 1024**2, "Missing/oversized allowlisted metadata: " + relative)
        files[member] = path.read_bytes()
    files["reports/CLOUD_SNAPSHOT_VERIFICATION.json"] = report_path.read_bytes()
    for index, context in contexts.items():
        prefix = f"reports/shards/shard-{index:02d}/"
        for name in ("RESTORE_VERIFICATION.json", "SHARD_PROOF.json", "CLOUD_UPLOADS.json"):
            files[prefix + name] = context["paths"][name].read_bytes()
        files[prefix + context["marker_path"].name] = context["marker_path"].read_bytes()
        files[f"plan/inventory-{index:02d}.json"] = context["paths"][f"inventory-{index:02d}.json"].read_bytes()
    for name, path in sidecars.items():
        files["volume-sidecars/" + path.name] = path.read_bytes()
    consolidated = {"format_version": 1, "status": "VERIFIED_METADATA", "source_object_count": EXPECTED_COUNT,
                    "source_bytes": EXPECTED_BYTES, "inventory_sha256": EXPECTED_INVENTORY,
                    "approved_plan_sha256": proofcheck.APPROVED_PLAN, "cloud_verification_sha256": sha(report_path),
                    "objects": [records[key] for key in sorted(records)], "volumes": list(volumes.values())}
    files["reports/ACQUISITION_MANIFEST.json"] = encode(consolidated)
    text = io.StringIO(newline="")
    writer = csv.DictWriter(text, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    files["SOURCE_TO_VOLUME.csv"] = text.getvalue().encode()
    files["DATE_TO_VOLUMES.json"] = encode(dates)
    files["VOLUME_SHA256SUMS.txt"] = "".join(f"{item['sha256']}  {name}\n" for name, item in sorted(volumes.items())).encode()
    files["README.md"] = instructions(report).encode()
    return files, rows, dates


def package_files(files, output, binding, rows, dates):
    secret = re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
    require(sum(map(len, files.values())) <= 512 * 1024**2, "Final control metadata is unexpectedly large")
    for name, content in files.items():
        require(not secret.search(content), "Credential-like material in allowlisted metadata: " + name)
        require(not name.lower().endswith((".jpg", ".jpeg", ".png", ".zip", ".gz", ".xz"))
                and not any(part in ("..", "transfer", "logs", "qa") for part in name.split("/")),
                "Forbidden control bundle member: " + name)
    manifest = {"format_version": 1, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(), **binding,
                "bulk_volumes_included": False, "uploaded_by_builder": False,
                "members": [{"name": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                            for name, content in sorted(files.items())]}
    files["CONTROL_MANIFEST.json"] = encode(manifest)
    files["METADATA_SHA256SUMS.txt"] = "".join(f"{hashlib.sha256(content).hexdigest()}  {name}\n"
                                              for name, content in sorted(files.items())).encode()
    target = output / "kalshi-public-snapshot-control-2026-09-20.zip"
    require(not target.exists(), "Refusing to replace an existing final control ZIP")
    output.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".zip.partial")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, content in sorted(files.items()):
            archive.writestr(name, content)
    with zipfile.ZipFile(temporary) as archive:
        require(archive.testzip() is None and set(archive.namelist()) == set(files), "Control ZIP read-back CRC/member mismatch")
        for name, content in files.items():
            require(hashlib.sha256(archive.read(name)).digest() == hashlib.sha256(content).digest(), "Control ZIP read-back byte mismatch")
    temporary.replace(target)
    for name in ("README.md", "SOURCE_TO_VOLUME.csv", "DATE_TO_VOLUMES.json", "VOLUME_SHA256SUMS.txt",
                 "CONTROL_MANIFEST.json", "METADATA_SHA256SUMS.txt"):
        (output / name).write_bytes(files[name])
    receipt = {"status": "BUILT_AND_READ_BACK", "created_at": manifest["created_at"], **binding,
               "filename": target.name, "bytes": target.stat().st_size, "sha256": sha(target),
               "source_to_volume_rows": len(rows), "date_count": len(dates), "metadata_members": len(files),
               "uploaded": False, "bulk_volumes_read": False, "source_restoration_repeated": False}
    (output / "CONTROL_BUILD.json").write_bytes(encode(receipt))
    (output / (target.name + ".sha256")).write_text(f"{receipt['sha256']}  {target.name}\n", encoding="utf-8")
    return receipt


def build(root, report_path, output, check_only=False):
    validated = validate(root, report_path)
    report = validated[0]
    if check_only:
        return {"validation": "passed", "source_object_count": EXPECTED_COUNT, "source_bytes": EXPECTED_BYTES,
                "volume_count": report["volume_count"], "outputs_written": False}
    files, rows, dates = assemble_files(root, report_path, validated)
    binding = {"source_object_count": EXPECTED_COUNT, "source_bytes": EXPECTED_BYTES,
               "repository": proofcheck.REPO, "visibility": "public", "release_tag": proofcheck.TAG,
               "source_inventory_sha256": EXPECTED_INVENTORY, "approved_plan_sha256": proofcheck.APPROVED_PLAN,
               "cloud_verification_sha256": sha(report_path), "release_id": report["release_id"],
               "cloud_release_url": STABLE_RELEASE_URL, "cloud_release_url_at_verification": report["release_url"],
               "volume_count": report["volume_count"]}
    return package_files(files, output, binding, rows, dates)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verification-report", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    output = args.output or args.verification_report.parent / "final-control"
    try:
        print(json.dumps(build(args.root.resolve(), args.verification_report.resolve(), output.resolve(), args.check_only), indent=2))
        return 0
    except (ValueError, KeyError, FileNotFoundError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "REFUSED", "reason": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
