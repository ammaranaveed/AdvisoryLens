"""
transform.py  --  Stage 2 of the AdvisoryLens ETL pipeline.

Reads the raw GitHub advisories JSON, flattens every advisory into one clean
row, cleans it with pandas and saves the result as a CSV file.

Main data-quality rules used here
---------------------------------
* A missing CVSS score stays MISSING (NaN). It is never replaced by 0.0,
  because 0.0 would look like a real "zero risk" score.
* CVSS v3 and CVSS v4 scores are both extracted. GitHub's `severity` label
  follows CVSS v4 when it exists, so the preferred score (`cvss_score`) is
  v4 first, then v3.
* Missing CVE / CWE values are stored as empty values (NULL), not as the
  text "N/A" (pandas silently turns the text "N/A" into NaN when reading
  a CSV, which made the old file confusing).
* Multi-value fields (ecosystem, package, CWE) are joined in a fixed,
  sorted order so every run of the pipeline gives the same CSV.
"""

import json
import os

import pandas as pd

# Columns of the processed dataset, in the order they are written.
PROCESSED_COLUMNS = [
    "ghsa_id",
    "cve_id",
    "summary",
    "severity",
    "cvss_score",
    "cvss_version",
    "cvss_v3_score",
    "cvss_v4_score",
    "published_at",
    "updated_at",
    "is_withdrawn",
    "cwe_ids",
    "ecosystem",
    "package_name",
]


def _valid_cvss_score(block):
    """
    Return a float score from a GitHub CVSS block, or None if it is missing.

    A block looks like {"vector_string": "...", "score": 7.5}. When that CVSS
    version is not available GitHub sends {"vector_string": None, "score": 0.0}
    or {"score": None}; both mean "no score", not "score of zero".
    """
    if not isinstance(block, dict):
        return None
    score = block.get("score")
    if score is None or not block.get("vector_string"):
        return None
    try:
        return float(score)
    except (TypeError, ValueError):
        return None


def _join_unique(values):
    """Join unique, non-empty values in sorted order; return None if empty."""
    cleaned = sorted({str(v).strip() for v in values if v and str(v).strip()})
    return ", ".join(cleaned) if cleaned else None


def _extract_cwes(cwes):
    """Collect CWE ids whether GitHub sends dicts or plain strings."""
    found = []
    if isinstance(cwes, list):
        for cwe in cwes:
            if isinstance(cwe, dict):
                found.append(cwe.get("cwe_id") or cwe.get("id"))
            elif isinstance(cwe, str):
                found.append(cwe)
    return _join_unique(found)


def _flatten_advisory(item):
    """Turn one raw advisory dictionary into one flat row (a dict)."""
    # --- CVSS: read v3 and v4 separately -----------------------------------
    severities = item.get("cvss_severities") or {}
    v3 = _valid_cvss_score(severities.get("cvss_v3"))
    if v3 is None:  # older records only have the top-level "cvss" block (v3)
        v3 = _valid_cvss_score(item.get("cvss"))
    v4 = _valid_cvss_score(severities.get("cvss_v4"))

    if v4 is not None:
        cvss_score, cvss_version = v4, "4.0"
    elif v3 is not None:
        cvss_score, cvss_version = v3, "3.x"
    else:
        cvss_score, cvss_version = None, None

    # --- Ecosystems and packages (one advisory can affect several) ---------
    ecosystems, packages = [], []
    for vuln in item.get("vulnerabilities") or []:
        package = (vuln or {}).get("package") or {}
        ecosystems.append(package.get("ecosystem"))
        packages.append(package.get("name"))

    return {
        "ghsa_id": item.get("ghsa_id"),
        "cve_id": item.get("cve_id") or None,
        "summary": item.get("summary"),
        "severity": item.get("severity"),
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "cvss_v3_score": v3,
        "cvss_v4_score": v4,
        "published_at": item.get("published_at"),
        "updated_at": item.get("updated_at"),
        "is_withdrawn": bool(item.get("withdrawn_at")),
        "cwe_ids": _extract_cwes(item.get("cwes")),
        "ecosystem": _join_unique(ecosystems) or "Unknown",
        "package_name": _join_unique(packages) or "Unknown",
    }


def transform_advisories(
    input_path="data/raw/raw_advisories.json",
    output_path="data/processed/processed_advisories.csv",
):
    """
    Read raw JSON advisories, clean them with pandas and save a CSV file.

    Returns the cleaned DataFrame, or None if the raw file does not exist.
    """
    print("Starting data transformation process...")

    # 1. Check that the raw file exists
    if not os.path.exists(input_path):
        print(f"Error: Raw file not found at {input_path}")
        return None

    # 2. Load raw JSON
    with open(input_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    # 3. Flatten every advisory into one row
    df = pd.DataFrame([_flatten_advisory(item) for item in raw_data])
    df = df.reindex(columns=PROCESSED_COLUMNS)
    print(f"Initial records loaded into DataFrame: {len(df)}")

    # 4. Remove duplicate advisories (same GHSA id)
    before = len(df)
    df = df.drop_duplicates(subset=["ghsa_id"]).reset_index(drop=True)
    print(f"Duplicate advisories removed: {before - len(df)}")

    # 5. Clean types
    df["severity"] = df["severity"].astype("string").str.strip().str.lower()
    df["severity"] = df["severity"].fillna("unknown")
    df["summary"] = df["summary"].fillna("No summary available")
    for col in ["cvss_score", "cvss_v3_score", "cvss_v4_score"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")  # missing stays NaN
    df["published_at"] = pd.to_datetime(df["published_at"], errors="coerce", utc=True)
    df["updated_at"] = pd.to_datetime(df["updated_at"], errors="coerce", utc=True)
    df["is_withdrawn"] = df["is_withdrawn"].astype(bool)

    # 6. Short quality report (helps to see problems straight away)
    print(f"Records without any CVSS score (kept as missing): {df['cvss_score'].isna().sum()}")
    print(f"Records with CVSS v4 score: {df['cvss_v4_score'].notna().sum()}")
    print(f"Withdrawn advisories (flagged, not removed): {df['is_withdrawn'].sum()}")

    # 7. Save as CSV
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    df.to_csv(output_path, index=False, encoding="utf-8")

    print(f"Data transformation completed successfully! Saved to: {output_path}")
    print(f"Final clean records count: {len(df)}")
    return df


if __name__ == "__main__":
    transform_advisories()
