"""Explicit public-only defaults for this independently reviewed snapshot."""

REPOSITORY = "Rmartin612/kalshi-public-data-snapshot-2026-09-20"
RELEASE_TAG = "snapshot-2026-09-20"
EXPECTED_VISIBILITY = "public"


def require_public_destination(repository, release, repo, tag, *, draft=False):
    if (repository.get("private") is not False
            or repository.get("visibility") != "public"
            or repository.get("full_name") != repo
            or release.get("tag_name") != tag
            or (draft and release.get("draft") is not True)):
        raise ValueError("Destination is not the expected public repository/release")
