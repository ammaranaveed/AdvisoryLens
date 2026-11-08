"""
validate.py  --  Stage 3 of the AdvisoryLens ETL pipeline.

Checks every row of the processed CSV with a Pydantic schema BEFORE the data
is loaded into SQLite. Rows that fail are written to a separate
`rejected_records.csv` file (with the reason), so nothing disappears silently.
"""

import os
from datetime import datetime
from typing import Literal, Optional

import pandas as pd
from pydantic import BaseModel, Field, ValidationError, model_validator


class AdvisoryRecord(BaseModel):
    """Schema for one processed advisory row."""

    ghsa_id: str = Field(..., pattern=r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$")
    cve_id: Optional[str] = Field(None, pattern=r"^CVE-\d{4}-\d{4,}$")
    summary: str = Field(..., min_length=1)
    severity: Literal["low", "medium", "high", "critical"]
    # A missing CVSS score is allowed (None). A score, when present, must be 0-10.
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_version: Optional[Literal["3.x", "4.0"]] = None
    cvss_v3_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_v4_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    published_at: datetime
    updated_at: datetime
    is_withdrawn: bool = False
    cwe_ids: Optional[str] = None
    ecosystem: str = Field(..., min_length=1)
    package_name: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def check_consistency(self):
        """Cross-field rules."""
        if (self.cvss_score is None) != (self.cvss_version is None):
            raise ValueError("cvss_score and cvss_version must both be present or both missing")
        if self.updated_at < self.published_at:
            raise ValueError("updated_at is earlier than published_at")
        return self


def _clean(value):
    """Convert pandas NaN / NaT / <NA> to None so Pydantic sees a real 'missing'."""
    return None if pd.isna(value) else value


def validate_dataset(
    input_path="data/processed/processed_advisories.csv",
    rejected_path=None,
):
    """
    Validate each CSV row with the Pydantic schema.

    Returns a list of valid records (dictionaries). Invalid rows are saved to
    `rejected_path` (default: rejected_records.csv next to the input file).
    """
    print("Starting Pydantic data validation process...")

    if not os.path.exists(input_path):
        print(f"Error: Processed file not found at {input_path}")
        return []

    # keep_default_na=False would hide real missing values, so we read normally
    # and convert missing values ourselves.
    df = pd.read_csv(input_path)

    valid_records = []
    rejected_rows = []

    for _, row in df.iterrows():
        data = {col: _clean(row[col]) for col in df.columns}
        try:
            record = AdvisoryRecord(**data)
            valid_records.append(record.model_dump())
        except ValidationError as err:
            reason = "; ".join(
                f"{'.'.join(str(p) for p in e['loc']) or 'record'}: {e['msg']}"
                for e in err.errors()
            )
            rejected_rows.append({**data, "rejection_reason": reason})

    if rejected_path is None:
        rejected_path = os.path.join(os.path.dirname(input_path), "rejected_records.csv")
    if rejected_rows:
        pd.DataFrame(rejected_rows).to_csv(rejected_path, index=False, encoding="utf-8")
        print(f"Rejected rows saved to: {rejected_path}")
    elif os.path.exists(rejected_path):
        os.remove(rejected_path)  # remove an old report from a previous run

    print("Validation completed!")
    print(f"Total rows checked: {len(df)}")
    print(f"Successfully validated records: {len(valid_records)}")
    print(f"Invalid records rejected: {len(rejected_rows)}")

    return valid_records


if __name__ == "__main__":
    validate_dataset()
