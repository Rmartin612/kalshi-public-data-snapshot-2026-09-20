# Kalshi public reporting snapshot

This repository preserves the public `reporting/` object inventory from [Kalshi market data](https://kalshi.com/market-data), captured on September 20, 2026 (America/Phoenix; September 21 UTC). The source is the public `kalshi-public-docs` S3 bucket.

The frozen inventory contains 3,934 data files totaling 462,291,303,835 original bytes, plus a zero-byte directory marker. Daily market and trade data cover June 28, 2021 through September 19, 2026; perpetual-market data cover June 1 through September 20, 2026. Two backup files are also included. This is a snapshot of the publicly listed reporting objects at capture time.

**[The completed cloud archive is available here](https://github.com/Rmartin612/kalshi-public-data-snapshot-2026-09-20/releases/tag/snapshot-2026-09-20).** All 3,934 original files are preserved losslessly in 93 ZIP volumes totaling 34,663,383,402 bytes. All eight shard proofs and the independent combined audit passed. The release includes the complete file index, source and cloud checksums, recovery tools, and final delivery verification.

Start with the [restore guide](https://github.com/Rmartin612/kalshi-public-data-snapshot-2026-09-20/releases/download/snapshot-2026-09-20/ARCHIVE_README.md) or the [control bundle](https://github.com/Rmartin612/kalshi-public-data-snapshot-2026-09-20/releases/download/snapshot-2026-09-20/kalshi-public-snapshot-control-2026-09-20.zip). The date index lets you retrieve selected days. Completion was verified on September 21, 2026 at 04:38 UTC.

## Verify the cloud snapshot

With Python 3 and the GitHub CLI available, run the independent metadata and cloud-digest check using the release ID:

```sh
python scripts/verify_acceleration_cloud.py --release-id RELEASE_ID
```

Each complete shard includes its source checksums, exact-byte restoration proof, volume checksums and acquisition metadata in `shard-XX-control.zip`. The cloud verifier checks these against the frozen inventory and freshly retrieved GitHub release-asset SHA256 digests. It downloads proof metadata; it does not download all bulk volumes.

## Verify or restore original files

Download every `volume-*.zip` asset from the completed snapshot release into `packages/`. The ZIPs contain self-describing manifests. Then stream through every original byte without writing the full restored dataset:

```sh
python scripts/restore_reporting.py --packages packages --verify-only --inventory discovery/s3-reporting-manifest.json --report restore-verification.json
```

To restore the original files, replace `--verify-only` with `--destination restored`. Full restoration requires at least 462,291,303,835 free bytes plus filesystem overhead. Existing files are never overwritten. Original `.json.gz` files retain their exact source gzip bytes. Raw `.json` files use lossless outer gzip compression. See [the format documentation](scripts/ARCHIVE_FORMAT.md) for selective restoration and manifest details.

The manual preservation workflow uses eight standard `ubuntu-24.04` hosted jobs in this public repository. Public visibility, the frozen plan hash, exact source coverage and all verification checks are enforced before a completion marker is written.
