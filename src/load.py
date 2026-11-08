"""
load.py  --  Stage 4 of the AdvisoryLens ETL pipeline.

Loads the validated advisories into a SQLite table. The table is created
with an explicit schema (including the PRIMARY KEY on ghsa_id) and the rows
are APPENDED into it, so the schema is no longer overwritten by pandas.
"""

import os
import sqlite3

import pandas as pd

CREATE_TABLE_SQL = """
CREATE TABLE advisories (
    ghsa_id        TEXT PRIMARY KEY,
    cve_id         TEXT,
    summary        TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    cvss_score     REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    cvss_version   TEXT,
    cvss_v3_score  REAL,
    cvss_v4_score  REAL,
    published_at   TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    is_withdrawn   INTEGER NOT NULL DEFAULT 0,
    cwe_ids        TEXT,
    ecosystem      TEXT NOT NULL,
    package_name   TEXT NOT NULL
)
"""

INDEX_SQL = [
    "CREATE INDEX idx_advisories_severity ON advisories (severity)",
    "CREATE INDEX idx_advisories_published ON advisories (published_at)",
    "CREATE INDEX idx_advisories_ecosystem ON advisories (ecosystem)",
]


def load_advisories_to_db(
    input_path="data/processed/processed_advisories.csv",
    db_path="database/advisories.db",
    valid_ids=None,
):
    """
    Load the processed CSV into the SQLite table `advisories`.

    valid_ids : optional collection of ghsa_id values. When given, only those
                rows are loaded (used to load only rows that passed validation).

    Returns the number of rows in the table after loading (None on error).
    """
    print("Starting database loading process...")

    if not os.path.exists(input_path):
        print(f"Error: Processed file not found at {input_path}")
        return None

    # 1. Make sure the database folder exists
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    # 2. Read the processed CSV and keep only validated rows (if requested)
    df = pd.read_csv(input_path)
    if valid_ids is not None:
        df = df[df["ghsa_id"].isin(set(valid_ids))]

    # SQLite has no boolean type: store True/False as 1/0
    df = df.assign(is_withdrawn=df["is_withdrawn"].astype(int))

    # 3. Rebuild the table inside one transaction (all-or-nothing)
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            conn.execute("DROP TABLE IF EXISTS advisories")
            conn.execute(CREATE_TABLE_SQL)
            # append keeps our schema; "replace" would delete it
            df.to_sql("advisories", conn, if_exists="append", index=False)
            for statement in INDEX_SQL:
                conn.execute(statement)

        total_rows = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
    finally:
        conn.close()

    if total_rows != len(df):
        raise RuntimeError(f"Row count mismatch: CSV has {len(df)} rows, database has {total_rows}")

    print(f"Data successfully loaded into SQLite database: {db_path}")
    print(f"Total rows currently in 'advisories' table: {total_rows}")
    return total_rows


if __name__ == "__main__":
    load_advisories_to_db()
