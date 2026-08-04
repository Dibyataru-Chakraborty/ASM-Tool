import gzip
import json

import pytest

from app.services.scan_archive_service import ScanArchiveService


def test_compact_archive_round_trip_and_explicit_delete(tmp_path):
    service = ScanArchiveService(root=tmp_path)
    payload = {
        "schema_version": 1,
        "scan": {"id": "scan-123", "status": "completed"},
        "subdomains": [
            {"subdomain": f"host-{index}.example.test", "technologies": ["nginx"]}
            for index in range(50)
        ],
    }

    archive = service.write_payload("user-123", "scan-123", payload)

    assert archive.name == "scan-123.json.gz"
    assert not archive.with_suffix("").exists()
    assert service.read_archive("user-123", "scan-123") == payload
    with gzip.open(archive, "rt", encoding="utf-8") as source:
        raw_json = source.read()
    assert raw_json == json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    # Merely reading and writing without overwrite retains the old immutable
    # snapshot; only the explicit delete operation removes it.
    service.write_payload(
        "user-123",
        "scan-123",
        {"scan": {"status": "changed"}},
    )
    assert service.read_archive("user-123", "scan-123") == payload
    assert service.delete_archive("user-123", "scan-123") is True
    assert service.read_archive("user-123", "scan-123") is None
    assert service.delete_archive("user-123", "scan-123") is False


@pytest.mark.parametrize("unsafe", ["../scan", "a/b", "a\\b", "", ".hidden"])
def test_archive_rejects_unsafe_path_components(tmp_path, unsafe):
    service = ScanArchiveService(root=tmp_path)

    with pytest.raises(ValueError):
        service.archive_path("user-123", unsafe)
