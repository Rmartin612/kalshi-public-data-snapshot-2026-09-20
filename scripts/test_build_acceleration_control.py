"""Offline control-bundle gates, metadata integrity, indexing, and ZIP read-back."""
import hashlib
import json
from pathlib import Path
import time
import zipfile

import build_acceleration_control as builder


def expect_failure(action, expected):
    try:
        action()
    except (ValueError, KeyError, FileNotFoundError) as error:
        assert expected.lower() in str(error).lower(), str(error)
    else:
        raise AssertionError("Invalid metadata was accepted")


def main():
    work = builder.ROOT / "acceleration-runtime" / ("control-builder-qa-" + str(time.time_ns()))
    work.mkdir(parents=True)
    incomplete = work / "INCOMPLETE.json"
    incomplete.write_text('{"status":"INCOMPLETE"}')
    refused_output = work / "must-not-exist"
    expect_failure(lambda: builder.build(builder.ROOT, incomplete, refused_output), "not COMPLETE")
    assert not refused_output.exists()
    # A COMPLETE flag alone cannot authorize a private or mismatched destination.
    destination = {"status": "COMPLETE", "private": True, "visibility": "private",
                   "release_tag": builder.proofcheck.TAG, "repository": "https://github.com/" + builder.proofcheck.REPO}
    wrong_destination = work / "WRONG_DESTINATION.json"
    wrong_destination.write_bytes(builder.encode(destination))
    expect_failure(lambda: builder.build(builder.ROOT, wrong_destination, refused_output), "destination/privacy differs")
    destination.update(private=False, visibility="public", repository="https://github.com/example/wrong")
    wrong_destination.write_bytes(builder.encode(destination))
    expect_failure(lambda: builder.build(builder.ROOT, wrong_destination, refused_output), "destination/privacy differs")
    assert not refused_output.exists()
    # Validate the actual public frozen plan through the public verifier interface.
    plan, inventory, shards, shard_inventories = builder.proofcheck.load_plan(
        builder.ROOT / "acceleration/frozen/PLAN.json", builder.ROOT / "discovery/s3-reporting-manifest.json")
    assert plan["expected_repository_visibility"] == "public" and len(inventory) == 3934
    assert sum(item["size"] for item in inventory.values()) == 462291303835
    assert set(shards) == set(shard_inventories) == set(range(8))
    # Metadata read-back validates the immutable cached ZIP and rejects changed extracted text.
    cached = work / "cached"
    extracted = cached / "extracted"
    extracted.mkdir(parents=True)
    members = {name: b'{}' for name in ("PLAN.json", "inventory-00.json", "RESTORE_VERIFICATION.json", "CLOUD_UPLOADS.json", "SHARD_PROOF.json")}
    archive_path = cached / "shard-00-control.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
            (extracted / name).write_bytes(content)
    assert set(builder.cached_control_paths(archive_path, extracted, 0)) == set(members)
    (extracted / "PLAN.json").write_bytes(b'{"changed":true}')
    expect_failure(lambda: builder.cached_control_paths(archive_path, extracted, 0), "Extracted metadata differs")
    # The combined date index must include each split volume exactly once, even across shards.
    keys = ["reporting/market_data_2026-09-19.json", "reporting/trade_data_2026-09-19.json.gz",
            "reporting/market_data_2023-03-11.json.backup"]
    volumes = {name: {"sha256": str(index) * 64, "url": "https://example.test/" + name}
               for index, name in enumerate(("volume-100000.zip", "volume-100001.zip", "volume-200000.zip"), start=1)}
    records, receipts = {}, {}
    names = list(volumes)
    for index, key in enumerate(keys):
        records[key] = {"source_size": (index + 1) * 10, "source_sha256": "a" * 64,
                        "inventory_etag": '"etag"', "compression": "identity" if key.endswith(".gz") else "gzip"}
        chosen = names[:2] if index == 0 else [names[2]]
        receipts[key] = {"dependencies": [{"volume": name, "entry": {"length": 5}} for name in chosen]}
    rows, dates = builder.indexes(records, receipts, volumes)
    assert len(rows) == 4
    assert rows[0]["cloud_asset_url"] == (
        f"https://github.com/{builder.proofcheck.REPO}/releases/download/{builder.proofcheck.TAG}/" + rows[0]["volume_name"])
    assert rows[0]["cloud_asset_url_at_verification"].startswith("https://example.test/")
    assert dates["2026-09-19"]["source_count"] == 2 and dates["2026-09-19"]["original_bytes"] == 30
    assert set(dates["2026-09-19"]["volume_names"]) == set(names)
    assert next(row for row in rows if row["source_key"].endswith(".backup"))["backup_object"] is True
    assert sum(item["original_bytes"] for item in dates.values()) == 60
    # Exercise the complete real-file allowlist; no private audit or screenshot is eligible.
    fixture_report = {"volume_count": 3, "verified_at": "synthetic-fixture-only"}
    fixture_path = work / "SYNTHETIC_ASSEMBLY.json"
    fixture_path.write_bytes(builder.encode(fixture_report))
    assembled, _, _ = builder.assemble_files(builder.ROOT, fixture_path,
        (fixture_report, {}, {}, records, receipts, {}, volumes))
    assert {name for name in assembled if name.startswith("provenance/")} == {
        "provenance/" + name for name in builder.PUBLIC_PROVENANCE}
    assert len(builder.PUBLIC_PROVENANCE) == 5
    assert not any(name in assembled for name in ("provenance/SOURCE_AUDIT.md",
        "provenance/source-audit.json", "provenance/market-data-page-extracted.txt"))
    assert ("Public release: " + builder.STABLE_RELEASE_URL).encode() in assembled["README.md"]
    assert b"private repository" not in assembled["README.md"]
    # Exercise package byte read-back and generated checksum files with explicitly synthetic metadata.
    files = {"README.md": b'Synthetic fixture only.\n', "SOURCE_TO_VOLUME.csv": b'source_key,volume_name\n',
             "DATE_TO_VOLUMES.json": builder.encode(dates), "VOLUME_SHA256SUMS.txt": b''}
    binding = {"source_object_count": 3, "source_bytes": 60, "volume_count": 3, "fixture_only": True}
    output = work / "bundle"
    receipt = builder.package_files(files, output, binding, rows, dates)
    assert receipt["status"] == "BUILT_AND_READ_BACK" and receipt["uploaded"] is False
    assert receipt["bulk_volumes_read"] is False and receipt["source_restoration_repeated"] is False
    package = output / receipt["filename"]
    assert builder.sha(package) == receipt["sha256"]
    with zipfile.ZipFile(package) as archive:
        assert archive.testzip() is None
        manifest = json.loads(archive.read("CONTROL_MANIFEST.json"))
        for member in manifest["members"]:
            assert hashlib.sha256(archive.read(member["name"])).hexdigest() == member["sha256"]
    expect_failure(lambda: builder.package_files({"README.md": b'ghp_' + b'A' * 36}, work / "secret-refused", binding, rows, dates), "Credential-like")
    assert not (work / "secret-refused").exists()
    expect_failure(lambda: builder.package_files({"photo.jpg": b'fixture'}, work / "photo-refused", binding, rows, dates), "Forbidden")
    assert not (work / "photo-refused").exists()
    print(json.dumps({"status": "PASS", "fixture_directory": str(work), "tests": ["incomplete-proof-produces-no-bundle",
          "cached-control-byte-tamper-rejected", "split-volume-date-index-and-backup-marker", "ZIP-readback-and-metadata-checksums",
          "credential-like-input-rejected", "screenshot-input-rejected", "private-or-wrong-destination-rejected",
          "public-frozen-plan-interface-and-exact-corpus", "public-provenance-only-allowlist", "canonical-public-download-URLs"]}, indent=2))


if __name__ == "__main__":
    main()
