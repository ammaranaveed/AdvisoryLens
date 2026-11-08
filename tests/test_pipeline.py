"""
Tests for the AdvisoryLens ETL pipeline.

All tests are OFFLINE and use temporary folders, so they never call the
GitHub API and never touch your real data/ or database/ folders.

Run from the project root:
    python -m pytest -v
"""

import json
import os
import sqlite3
import sys

import pandas as pd
import pytest

# Make "from src.xxx import ..." work no matter where pytest is started.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import extract  # noqa: E402
from src.load import load_advisories_to_db  # noqa: E402
from src.transform import transform_advisories  # noqa: E402
from src.validate import validate_dataset  # noqa: E402


def make_advisory(ghsa_id, severity="high", v3=None, v4=None, **extra):
    """Build one fake raw advisory shaped like the GitHub API response."""
    advisory = {
        "ghsa_id": ghsa_id,
        "cve_id": "CVE-2026-1000",
        "summary": f"Summary of {ghsa_id}",
        "severity": severity,
        "published_at": "2026-10-01T10:00:00Z",
        "updated_at": "2026-10-02T10:00:00Z",
        "withdrawn_at": None,
        "cvss": {"vector_string": None, "score": None},
        "cvss_severities": {
            "cvss_v3": {"vector_string": None, "score": 0.0},
            "cvss_v4": {"vector_string": None, "score": 0.0},
        },
        "cwes": [{"cwe_id": "CWE-79", "name": "XSS"}],
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "left-pad"}}],
    }
    if v3 is not None:
        block = {"vector_string": "CVSS:3.1/AV:N", "score": v3}
        advisory["cvss"] = dict(block)
        advisory["cvss_severities"]["cvss_v3"] = block
    if v4 is not None:
        advisory["cvss_severities"]["cvss_v4"] = {"vector_string": "CVSS:4.0/AV:N", "score": v4}
    advisory.update(extra)
    return advisory


@pytest.fixture
def raw_file(tmp_path):
    """A small raw JSON file that covers the important cases."""
    records = [
        make_advisory("GHSA-aaaa-aaaa-aaaa", "high", v3=7.5),                 # v3 only
        make_advisory("GHSA-bbbb-bbbb-bbbb", "medium", v4=6.9),               # v4 only
        make_advisory("GHSA-cccc-cccc-cccc", "critical", v3=10.0, v4=9.3),    # both -> v4 wins
        make_advisory("GHSA-dddd-dddd-dddd", "low", cve_id=None, cwes=[]),    # no CVSS, no CVE, no CWE
        make_advisory(
            "GHSA-eeee-eeee-eeee", "high", v3=7.0, withdrawn_at="2026-10-05T00:00:00Z",
            vulnerabilities=[
                {"package": {"ecosystem": "pip", "name": "b-pkg"}},
                {"package": {"ecosystem": "npm", "name": "a-pkg"}},
                {"package": {"ecosystem": "npm", "name": "a-pkg"}},
            ],
        ),
        make_advisory("GHSA-aaaa-aaaa-aaaa", "high", v3=7.5),                 # duplicate id
    ]
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    return str(path)


# ----------------------------------------------------------------- transform
def test_transform_keeps_missing_cvss_as_nan(raw_file, tmp_path):
    df = transform_advisories(raw_file, str(tmp_path / "out.csv"))
    row = df.set_index("ghsa_id").loc["GHSA-dddd-dddd-dddd"]
    assert pd.isna(row["cvss_score"])          # must NOT be 0.0
    assert pd.isna(row["cvss_version"])


def test_transform_prefers_v4_then_v3(raw_file, tmp_path):
    df = transform_advisories(raw_file, str(tmp_path / "out.csv")).set_index("ghsa_id")
    assert df.loc["GHSA-aaaa-aaaa-aaaa", "cvss_score"] == 7.5
    assert df.loc["GHSA-aaaa-aaaa-aaaa", "cvss_version"] == "3.x"
    assert df.loc["GHSA-bbbb-bbbb-bbbb", "cvss_score"] == 6.9
    assert df.loc["GHSA-bbbb-bbbb-bbbb", "cvss_version"] == "4.0"
    assert df.loc["GHSA-cccc-cccc-cccc", "cvss_score"] == 9.3
    assert df.loc["GHSA-cccc-cccc-cccc", "cvss_v3_score"] == 10.0


def test_transform_removes_duplicates_and_flags_withdrawn(raw_file, tmp_path):
    df = transform_advisories(raw_file, str(tmp_path / "out.csv")).set_index("ghsa_id")
    assert len(df) == 5
    assert bool(df.loc["GHSA-eeee-eeee-eeee", "is_withdrawn"]) is True
    assert bool(df.loc["GHSA-aaaa-aaaa-aaaa", "is_withdrawn"]) is False


def test_transform_joins_values_sorted_and_unique(raw_file, tmp_path):
    df = transform_advisories(raw_file, str(tmp_path / "out.csv")).set_index("ghsa_id")
    assert df.loc["GHSA-eeee-eeee-eeee", "ecosystem"] == "npm, pip"
    assert df.loc["GHSA-eeee-eeee-eeee", "package_name"] == "a-pkg, b-pkg"


def test_transform_missing_cve_and_cwe_are_empty(raw_file, tmp_path):
    df = transform_advisories(raw_file, str(tmp_path / "out.csv")).set_index("ghsa_id")
    assert pd.isna(df.loc["GHSA-dddd-dddd-dddd", "cve_id"])
    assert pd.isna(df.loc["GHSA-dddd-dddd-dddd", "cwe_ids"])


def test_transform_missing_raw_file_returns_none(tmp_path):
    assert transform_advisories(str(tmp_path / "nope.json"), str(tmp_path / "o.csv")) is None


# ------------------------------------------------------------------ validate
def test_validation_accepts_clean_data_and_missing_cvss(raw_file, tmp_path):
    csv_path = str(tmp_path / "out.csv")
    transform_advisories(raw_file, csv_path)
    valid = validate_dataset(csv_path)
    assert len(valid) == 5                      # the no-CVSS row is still valid


def test_validation_rejects_bad_rows_and_writes_report(raw_file, tmp_path):
    csv_path = str(tmp_path / "out.csv")
    transform_advisories(raw_file, csv_path)
    df = pd.read_csv(csv_path)
    df.loc[0, "severity"] = "banana"            # not an allowed severity
    df.loc[1, "cvss_score"] = 42.0              # outside 0-10
    df.to_csv(csv_path, index=False)

    valid = validate_dataset(csv_path)
    assert len(valid) == 3
    rejected = pd.read_csv(str(tmp_path / "rejected_records.csv"))
    assert len(rejected) == 2
    assert "rejection_reason" in rejected.columns


# ---------------------------------------------------------------------- load
def test_load_creates_primary_key_and_all_rows(raw_file, tmp_path):
    csv_path = str(tmp_path / "out.csv")
    db_path = str(tmp_path / "db" / "test.db")
    transform_advisories(raw_file, csv_path)
    assert load_advisories_to_db(csv_path, db_path) == 5

    conn = sqlite3.connect(db_path)
    try:
        columns = {row[1]: row[5] for row in conn.execute("PRAGMA table_info(advisories)")}
        assert columns["ghsa_id"] == 1           # 1 = primary key column
        nulls = conn.execute("SELECT COUNT(*) FROM advisories WHERE cvss_score IS NULL").fetchone()[0]
        assert nulls == 1                        # missing CVSS stored as NULL, not 0
    finally:
        conn.close()


def test_load_only_valid_ids(raw_file, tmp_path):
    csv_path = str(tmp_path / "out.csv")
    db_path = str(tmp_path / "test.db")
    transform_advisories(raw_file, csv_path)
    count = load_advisories_to_db(csv_path, db_path, valid_ids=["GHSA-aaaa-aaaa-aaaa"])
    assert count == 1


def test_load_can_be_run_twice(raw_file, tmp_path):
    csv_path = str(tmp_path / "out.csv")
    db_path = str(tmp_path / "test.db")
    transform_advisories(raw_file, csv_path)
    load_advisories_to_db(csv_path, db_path)
    assert load_advisories_to_db(csv_path, db_path) == 5   # no duplicates after a re-run


# ------------------------------------------------------------------- extract
def test_extraction_follows_next_page_link(monkeypatch, tmp_path):
    """Fake the GitHub API: page 1 has a 'next' link, page 2 does not."""

    class FakeResponse:
        def __init__(self, data, link=""):
            self.status_code = 200
            self._data = data
            self.headers = {"Link": link} if link else {}

        def json(self):
            return self._data

    pages = [
        FakeResponse([{"ghsa_id": "A"}, {"ghsa_id": "B"}], '<https://api.github.com/p2?x=1>; rel="next"'),
        FakeResponse([{"ghsa_id": "C"}]),
    ]
    monkeypatch.setattr(extract.requests, "get", lambda *a, **k: pages.pop(0))

    records = extract.fetch_github_advisories(per_page=2, max_records=10)
    assert [r["ghsa_id"] for r in records] == ["A", "B", "C"]

    saved = extract.save_raw_json(records, filepath=str(tmp_path / "raw" / "x.json"))
    assert os.path.exists(saved)


def test_extraction_stops_on_http_error(monkeypatch):
    class BadResponse:
        status_code = 403
        headers = {}

        def json(self):
            return {}

    monkeypatch.setattr(extract.requests, "get", lambda *a, **k: BadResponse())
    assert extract.fetch_github_advisories(per_page=2, max_records=10) == []


# ------------------------------------------------------------------ pipeline
def test_pipeline_does_not_overwrite_raw_file_with_a_partial_download(monkeypatch, tmp_path):
    """If the API stops half way, the good saved raw file must stay untouched."""
    import pipeline

    raw_file = tmp_path / "raw_advisories.json"
    raw_file.write_text(json.dumps([{"ghsa_id": "GHSA-old0-old0-old0"}]), encoding="utf-8")
    monkeypatch.setattr(pipeline, "RAW_PATH", str(raw_file))
    monkeypatch.setattr(pipeline, "fetch_github_advisories", lambda **kwargs: [{"ghsa_id": "GHSA-new0-new0-new0"}])

    with pytest.raises(SystemExit):
        pipeline.run_complete_pipeline(refresh=True)

    saved = json.loads(raw_file.read_text(encoding="utf-8"))
    assert saved == [{"ghsa_id": "GHSA-old0-old0-old0"}]        


def test_pipeline_skips_extraction_when_the_raw_file_exists(monkeypatch, tmp_path):
    """A normal run must not call the GitHub API when the raw file already exists."""
    import pipeline

    raw_file = tmp_path / "raw_advisories.json"
    raw_file.write_text(json.dumps([make_advisory("GHSA-aaaa-aaaa-aaaa", v3=7.5)]), encoding="utf-8")
    monkeypatch.setattr(pipeline, "RAW_PATH", str(raw_file))
    monkeypatch.setattr(pipeline, "PROCESSED_PATH", str(tmp_path / "processed.csv"))
    monkeypatch.setattr(pipeline, "DB_PATH", str(tmp_path / "test.db"))

    def api_must_not_be_called(**kwargs):
        raise AssertionError("the GitHub API was called")

    monkeypatch.setattr(pipeline, "fetch_github_advisories", api_must_not_be_called)
    pipeline.run_complete_pipeline(refresh=False)                 # must finish without calling the API
    assert (tmp_path / "test.db").exists()