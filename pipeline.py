"""
pipeline.py  --  AdvisoryLens master ETL pipeline.

Stages:  1) Extract  ->  2) Transform  ->  3) Validate  ->  4) Load

Usage (run from the project root folder):
    python pipeline.py             # normal run: reuses data/raw/raw_advisories.json
                                   # (the GitHub API is called only if that file is missing)
    python pipeline.py --refresh   # force a NEW download from the GitHub API
                                   # (WARNING: the newest 1500 advisories will replace your dataset)
"""

import argparse
import os
import sys

# Project root = the folder that contains this file. All paths are built from
# it, so the pipeline works no matter which folder it is started from.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

from extract import fetch_github_advisories, save_raw_json  # noqa: E402
from transform import transform_advisories  # noqa: E402
from validate import validate_dataset  # noqa: E402
from load import load_advisories_to_db  # noqa: E402

RAW_PATH = os.path.join(PROJECT_ROOT, "data", "raw", "raw_advisories.json")
PROCESSED_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "processed_advisories.csv")
DB_PATH = os.path.join(PROJECT_ROOT, "database", "advisories.db")

EXPECTED_RECORDS = 1500    # how many advisories the extraction asks for


def run_complete_pipeline(refresh=False):
    print("=" * 50)
    print("STARTING ADVISORYLENS MASTER ETL PIPELINE")
    print("=" * 50)

    # Stage 1: Extraction (only when needed, so the dataset stays the same between runs)
    if os.path.exists(RAW_PATH) and not refresh:
        print("\n[Stage 1/4] Skipped: raw file already exists (use --refresh to download again).")
    else:
        print("\n[Stage 1/4] Extracting raw data from GitHub API...")
        raw_data = fetch_github_advisories(per_page=100, max_records=EXPECTED_RECORDS)
        if not raw_data:
            print("[ERROR] Extraction failed or returned empty data. Stopping pipeline.")
            sys.exit(1)
        # Safety check: if the download stopped half way (internet problem, API rate limit), do NOT
        # overwrite the saved raw file with incomplete data.
        if len(raw_data) < EXPECTED_RECORDS:
            print(f"[ERROR] Only {len(raw_data)} records were downloaded (expected {EXPECTED_RECORDS}). "
                  "The raw file was NOT overwritten. Check your connection and try again.")
            sys.exit(1)
        save_raw_json(raw_data, filepath=RAW_PATH)

    # Stage 2: Transformation
    print("\n[Stage 2/4] Transforming and cleaning data...")
    try:
        df_processed = transform_advisories(input_path=RAW_PATH, output_path=PROCESSED_PATH)
    except Exception as e:
        print(f"[ERROR] Transformation failed: {e}")
        sys.exit(1)
    if df_processed is None:
        print("[ERROR] Transformation returned no data. Stopping pipeline.")
        sys.exit(1)

    # Stage 3: Pydantic validation (BEFORE loading)
    print("\n[Stage 3/4] Running Pydantic schema validation...")
    try:
        valid_records = validate_dataset(input_path=PROCESSED_PATH)
    except Exception as e:
        print(f"[ERROR] Validation failed: {e}")
        sys.exit(1)
    if not valid_records:
        print("[ERROR] No valid records. Stopping pipeline.")
        sys.exit(1)
    valid_ids = [record["ghsa_id"] for record in valid_records]
    print(f"[OK] Validation passed with {len(valid_ids)} valid records.")

    # Stage 4: Load only the validated rows into SQLite
    print("\n[Stage 4/4] Loading validated data into SQLite database...")
    try:
        load_advisories_to_db(input_path=PROCESSED_PATH, db_path=DB_PATH, valid_ids=valid_ids)
    except Exception as e:
        print(f"[ERROR] Loading failed: {e}")
        sys.exit(1)

    print("\n" + "=" * 50)
    print("ETL & VALIDATION PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the AdvisoryLens ETL pipeline.")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="download fresh data from the GitHub API even if the raw file already exists",
    )
    args = parser.parse_args()
    run_complete_pipeline(refresh=args.refresh)