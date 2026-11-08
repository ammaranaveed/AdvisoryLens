"""
eda.py  --  Reusable EDA script for AdvisoryLens.

This script repeats the analysis of notebooks/eda.ipynb automatically:
    load data -> overview -> data quality -> severity -> ecosystem -> CVSS
    -> CWE -> temporal -> packages -> key findings

Input : database/advisories.db (falls back to data/processed/processed_advisories.csv)
Output: charts in outputs/visualizations/ and a text report in the terminal

Run it from the project root:
    python src/eda.py
"""

from contextlib import closing
from pathlib import Path
import sqlite3
import sys

import matplotlib

matplotlib.use("Agg")  # draw charts straight into files (no pop-up windows needed)
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import seaborn as sns  # noqa: E402

# =====================================================================
# SETTINGS (same values as the notebook)
# =====================================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent      # folder that contains src/
DB_PATH = PROJECT_ROOT / "database" / "advisories.db"
CSV_PATH = PROJECT_ROOT / "data" / "processed" / "processed_advisories.csv"
VIZ_DIR = PROJECT_ROOT / "outputs" / "visualizations"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {"critical": "#b30000", "high": "#e65c00", "medium": "#d4ac0d", "low": "#0066cc"}
PRIMARY_COLOR = "#1f4e79"

# Short names from the public MITRE CWE list (only used to make chart labels readable)
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-94": "Code Injection",
    "CWE-200": "Sensitive Information Exposure",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-407": "Inefficient Algorithmic Complexity",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-770": "Resources Allocated Without Limits",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1333": "Inefficient Regular Expression (ReDoS)",
}


# =====================================================================
# SMALL HELPER FUNCTIONS
# =====================================================================
def set_plot_style():
    """One shared style so every chart looks consistent."""
    plt.style.use("seaborn-v0_8-whitegrid")
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 11,
        "axes.titlesize": 14,
        "axes.titleweight": "bold",
        "axes.labelweight": "bold",
        "axes.spines.top": False,
        "axes.spines.right": False,
    })


def print_header(title):
    """Print a clear section title in the terminal."""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def show(*lines):
    """Print observation lines (the notebook shows them as Markdown)."""
    for line in lines:
        print(line.replace("**", "").replace("`", ""))


def save_figure(fig, filename):
    """Save a chart into outputs/visualizations/ and close it (frees memory)."""
    VIZ_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(VIZ_DIR / filename, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: outputs/visualizations/{filename}")


def explode_multi(frame, column):
    """
    Turn a column such as "npm, pip" into one row per value, so multi-value
    fields (ecosystem, package, CWE) are counted correctly.
    """
    out = frame.dropna(subset=[column]).copy()
    out[column] = out[column].str.split(", ")
    out = out.explode(column)
    out[column] = out[column].str.strip()
    return out.reset_index(drop=True)


# =====================================================================
# LOADING
# =====================================================================
def load_data():
    """Load advisories from SQLite (preferred) or from the processed CSV."""
    if DB_PATH.exists():
        with closing(sqlite3.connect(DB_PATH)) as conn:
            df = pd.read_sql_query("SELECT * FROM advisories", conn)
        source = "SQLite database (database/advisories.db)"
    elif CSV_PATH.exists():
        df = pd.read_csv(CSV_PATH)
        source = "processed CSV (data/processed/processed_advisories.csv)"
    else:
        raise FileNotFoundError("No data found. From the project root run:  python pipeline.py")

    # Correct data types
    df["published_at"] = pd.to_datetime(df["published_at"], utc=True)
    df["updated_at"] = pd.to_datetime(df["updated_at"], utc=True)
    df["is_withdrawn"] = df["is_withdrawn"].astype(bool)

    print(f"Data source    : {source}")
    print(f"Records loaded : {len(df):,}")

    # Cross-check: database and CSV must contain the same advisories
    if CSV_PATH.exists() and DB_PATH.exists():
        csv_ids = set(pd.read_csv(CSV_PATH, usecols=["ghsa_id"])["ghsa_id"])
        print(f"DB and CSV hold the same advisories: {csv_ids == set(df['ghsa_id'])}")
    return df


# =====================================================================
# 3. DATASET OVERVIEW
# =====================================================================
def dataset_overview(df):
    """Print size, data types, numeric summary and the date range."""
    print_header("3. DATASET OVERVIEW")
    print(f"Records : {len(df):,}")
    print(f"Columns : {df.shape[1]}")
    print(f"Published from {df['published_at'].min():%d %b %Y} to {df['published_at'].max():%d %b %Y} (UTC)\n")

    print("--- Data types and non-null counts ---")
    df.info()

    print("\n--- Numeric summary (missing CVSS scores are excluded, not counted as 0) ---")
    print(df[["cvss_score", "cvss_v3_score", "cvss_v4_score"]].describe().round(2).to_string())

    print("\n--- Distinct values per column (\"npm, pip\" counts as one value here) ---")
    distinct = df[["ghsa_id", "severity", "ecosystem", "package_name", "cwe_ids", "cvss_version"]].nunique()
    print(distinct.to_string())


# =====================================================================
# 4. DATA QUALITY
# =====================================================================
def data_quality_analysis(df):
    """Missing values, duplicates, CVSS availability, withdrawn advisories + chart."""
    print_header("4. DATA QUALITY ASSESSMENT")

    # Missing values
    missing = pd.DataFrame({
        "missing_count": df.isna().sum(),
        "missing_pct": (df.isna().mean() * 100).round(1),
    })
    print("--- Columns with missing values ---")
    print(missing[missing["missing_count"] > 0].to_string())

    # Duplicates
    dup_ids = int(df["ghsa_id"].duplicated().sum())
    dup_rows = int(df.duplicated().sum())
    print(f"\nDuplicate ghsa_id values : {dup_ids}")
    print(f"Fully duplicated rows    : {dup_rows}")

    # Which CVSS version scored each advisory?
    has_v3 = df["cvss_v3_score"].notna()
    has_v4 = df["cvss_v4_score"].notna()
    cvss_source = pd.Series(
        np.select([has_v3 & has_v4, has_v3, has_v4], ["v3 and v4", "v3 only", "v4 only"], default="no score"),
        index=df.index,
    )
    cvss_source_counts = cvss_source.value_counts().reindex(
        ["v3 only", "v4 only", "v3 and v4", "no score"], fill_value=0
    )
    print("\n--- CVSS availability ---")
    print(cvss_source_counts.to_string())

    n_withdrawn = int(df["is_withdrawn"].sum())
    print(f"\nWithdrawn advisories (kept, flagged with is_withdrawn): {n_withdrawn}")

    # Chart: completeness per column + CVSS version availability
    completeness = (df.notna().mean() * 100).sort_values()
    fig, axes = plt.subplots(1, 2, figsize=(15, 6), gridspec_kw={"width_ratios": [1.3, 1]})

    ax = axes[0]
    colors = ["#e65c00" if v < 100 else PRIMARY_COLOR for v in completeness]
    ax.barh(completeness.index, completeness.values, color=colors)
    ax.set_xlim(0, 115)
    ax.grid(axis="y", visible=False)
    for y, v in enumerate(completeness.values):
        ax.text(v + 1, y, f"{v:.1f}%", va="center", fontsize=9, fontweight="bold")
    ax.set_title(f"Column Completeness ({len(df):,} records)")
    ax.set_xlabel("Share of records with a value (%)")
    ax.set_ylabel("Column")

    ax = axes[1]
    ax.bar(cvss_source_counts.index, cvss_source_counts.values,
           color=[PRIMARY_COLOR, "#2e86c1", "#5dade2", "#e65c00"], width=0.65)
    for x, v in enumerate(cvss_source_counts.values):
        ax.text(x, v + len(df) * 0.01, f"{v:,}\n({v / len(df) * 100:.1f}%)", ha="center", fontsize=9, fontweight="bold")
    ax.set_ylim(0, cvss_source_counts.max() * 1.18)
    ax.set_title("CVSS Version Available per Advisory")
    ax.set_xlabel("CVSS version(s) with a score")
    ax.set_ylabel("Number of advisories")

    plt.tight_layout()
    save_figure(fig, "data_quality.png")

    # Observations
    n_no_cvss = int(df["cvss_score"].isna().sum())
    n_no_cve = int(df["cve_id"].isna().sum())
    n_no_cwe = int(df["cwe_ids"].isna().sum())
    print()
    show(
        "Key observations",
        f"- No duplicate advisories ({dup_ids} duplicate ids, {dup_rows} duplicate rows).",
        f"- Only **{n_no_cvss}** advisories ({n_no_cvss / len(df) * 100:.1f}%) have no CVSS score at all; "
        f"**{int(has_v4.sum())}** ({has_v4.mean() * 100:.1f}%) have a CVSS v4 score and **{int(has_v3.sum())}** ({has_v3.mean() * 100:.1f}%) have a v3 score.",
        f"- **{n_no_cve}** advisories ({n_no_cve / len(df) * 100:.1f}%) have no CVE id and **{n_no_cwe}** ({n_no_cwe / len(df) * 100:.1f}%) have no CWE.",
        f"- **{n_withdrawn}** advisories ({n_withdrawn / len(df) * 100:.1f}%) are withdrawn but still in the dataset (flagged by is_withdrawn).",
    )
    return {"n_no_cvss": n_no_cvss, "n_withdrawn": n_withdrawn}


# =====================================================================
# 5. SEVERITY
# =====================================================================
def severity_analysis(df):
    """Severity counts and percentages + bar chart."""
    print_header("5. SEVERITY ANALYSIS")
    sev_counts = df["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0).astype(int)
    sev_pct = sev_counts / len(df) * 100

    print("Severity breakdown:")
    for sev in SEVERITY_ORDER:
        print(f"- {sev.capitalize():<9}: {sev_counts[sev]:>4} ({sev_pct[sev]:.1f}%)")

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar([s.capitalize() for s in SEVERITY_ORDER], sev_counts.values,
           color=[SEVERITY_COLORS[s] for s in SEVERITY_ORDER], width=0.65)
    for x, sev in enumerate(SEVERITY_ORDER):
        ax.annotate(f"{sev_counts[sev]:,} ({sev_pct[sev]:.1f}%)", (x, sev_counts[sev]),
                    ha="center", va="bottom", fontsize=10, fontweight="bold",
                    xytext=(0, 5), textcoords="offset points")
    ax.set_ylim(0, sev_counts.max() * 1.15)
    ax.set_title("Security Advisories by Severity Level", pad=15)
    ax.set_xlabel("Severity level (GitHub classification)")
    ax.set_ylabel("Number of advisories")
    plt.tight_layout()
    save_figure(fig, "severity_distribution.png")

    total = len(df)
    top_sev = sev_counts.idxmax()
    high_medium = int(sev_counts[["high", "medium"]].sum())
    critical_high = int(sev_counts[["critical", "high"]].sum())
    print()
    show(
        "Key observations",
        f"- **{top_sev.capitalize()}** is the most common level: {sev_counts[top_sev]:,} advisories ({sev_pct[top_sev]:.1f}%).",
        f"- High and medium together account for **{high_medium / total * 100:.1f}%** of all advisories.",
        f"- Critical and high together make up **{critical_high:,}** advisories ({critical_high / total * 100:.1f}%).",
        f"- Critical ({sev_pct['critical']:.1f}%) and low ({sev_pct['low']:.1f}%) are the two smallest groups.",
    )
    return {"sev_counts": sev_counts, "sev_pct": sev_pct, "top_sev": top_sev}


# =====================================================================
# 6. ECOSYSTEM
# =====================================================================
def ecosystem_analysis(df):
    """Advisories per ecosystem + severity mix inside the larger ecosystems."""
    print_header("6. ECOSYSTEM ANALYSIS")
    eco = explode_multi(df, "ecosystem")                    # one row per (advisory, ecosystem)
    eco_counts = eco["ecosystem"].value_counts()
    n_multi_eco = int(df["ecosystem"].str.contains(",").sum())

    print(f"Distinct ecosystems: {eco_counts.size}")
    print(f"Advisories affecting more than one ecosystem: {n_multi_eco}\n")
    print("Advisories per ecosystem:")
    print(eco_counts.rename("advisories").to_string())

    # Chart 1: advisories per ecosystem
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(eco_counts.index, eco_counts.values, color=PRIMARY_COLOR)
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    for y, v in enumerate(eco_counts.values):
        ax.text(v + eco_counts.max() * 0.01, y, f"{v:,} ({v / len(df) * 100:.1f}%)",
                va="center", fontsize=10, fontweight="bold")
    ax.set_xlim(0, eco_counts.max() * 1.18)
    ax.set_title("Security Advisories by Software Ecosystem", pad=15)
    ax.set_xlabel(f"Number of advisories (percentage of all {len(df):,} advisories)")
    ax.set_ylabel("Software ecosystem")
    plt.tight_layout()
    save_figure(fig, "ecosystem_analysis.png")

    # Chart 2: severity mix inside the larger ecosystems (small groups are unreliable)
    min_size = 40
    big_ecosystems = eco_counts[eco_counts >= min_size].index
    ct = (pd.crosstab(eco["ecosystem"], eco["severity"])
          .reindex(index=big_ecosystems, columns=SEVERITY_ORDER, fill_value=0))
    ct_pct = ct.div(ct.sum(axis=1), axis=0) * 100

    print(f"\nSeverity counts for ecosystems with at least {min_size} advisories:")
    print(ct.to_string())

    fig, ax = plt.subplots(figsize=(10, 5.5))
    left = np.zeros(len(ct_pct))
    for sev in SEVERITY_ORDER:
        values = ct_pct[sev].values
        ax.barh(range(len(ct_pct)), values, left=left, color=SEVERITY_COLORS[sev],
                edgecolor="white", label=sev.capitalize())
        for i, (start, width) in enumerate(zip(left, values)):
            if width >= 5:
                ax.text(start + width / 2, i, f"{width:.0f}%", ha="center", va="center", fontsize=9,
                        fontweight="bold", color="black" if sev == "medium" else "white")
        left += values
    ax.set_yticks(range(len(ct_pct)))
    ax.set_yticklabels([f"{e}  (n={int(ct.loc[e].sum())})" for e in ct_pct.index])
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, 100)
    ax.set_title("Severity Mix within Each Major Ecosystem", pad=15)
    ax.set_xlabel("Share of the ecosystem's advisories (%)")
    ax.set_ylabel("Ecosystem (n = advisories)")
    ax.legend(title="Severity", ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.12), frameon=False)
    plt.tight_layout()
    save_figure(fig, "ecosystem_severity.png")

    # Observations
    top3 = list(eco_counts.index[:3])
    top3_adv = eco.loc[eco["ecosystem"].isin(top3), "ghsa_id"].nunique()
    crit_leader = ct_pct["critical"].idxmax()
    high_leader = ct_pct["high"].idxmax()
    low_leader = ct_pct["low"].idxmax()
    print()
    show(
        "Key observations",
        f"- **{top3[0]}** ({eco_counts[top3[0]]:,}), **{top3[1]}** ({eco_counts[top3[1]]:,}) and **{top3[2]}** ({eco_counts[top3[2]]:,}) are the three largest ecosystems; "
        f"together they cover **{top3_adv / len(df) * 100:.1f}%** of all advisories.",
        f"- Only **{n_multi_eco}** advisories ({n_multi_eco / len(df) * 100:.1f}%) affect more than one ecosystem.",
        f"- Among the {len(big_ecosystems)} ecosystems with at least {min_size} advisories, **{crit_leader}** has the highest critical share "
        f"({ct_pct.loc[crit_leader, 'critical']:.1f}%, n={int(ct.loc[crit_leader].sum())}), "
        f"**{high_leader}** the highest high share ({ct_pct.loc[high_leader, 'high']:.1f}%) and "
        f"**{low_leader}** the highest low share ({ct_pct.loc[low_leader, 'low']:.1f}%).",
    )
    return {"top3": top3, "top3_adv": top3_adv}


# =====================================================================
# 7. CVSS
# =====================================================================
def cvss_analysis(df):
    """CVSS distribution, statistics and comparison with the severity label."""
    print_header("7. CVSS ANALYSIS")
    scored = df.dropna(subset=["cvss_score"])            # missing scores are excluded, not zero
    n_scored = len(scored)
    mean_cvss = scored["cvss_score"].mean()
    median_cvss = scored["cvss_score"].median()

    print(f"Advisories with a CVSS score: {n_scored:,} of {len(df):,}\n")
    print(scored["cvss_score"].agg(["count", "mean", "median", "std", "min", "max"]).round(2).to_string())

    # Chart 1: histogram
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.hist(scored["cvss_score"], bins=np.arange(0, 10.5, 0.5), color=PRIMARY_COLOR, edgecolor="white")
    ax.axvline(mean_cvss, color="#e65c00", linestyle="--", linewidth=2, label=f"Mean = {mean_cvss:.2f}")
    ax.axvline(median_cvss, color="#b30000", linestyle="-", linewidth=2, label=f"Median = {median_cvss:.2f}")
    ax.set_title(f"Distribution of CVSS Scores (n = {n_scored:,})", pad=15)
    ax.set_xlabel("CVSS base score (0.0 - 10.0)")
    ax.set_ylabel("Number of advisories")
    ax.set_xlim(0, 10)
    ax.set_xticks(range(0, 11))
    ax.legend(frameon=False)
    plt.tight_layout()
    save_figure(fig, "cvss_distribution.png")

    # Chart 2: boxplot by severity
    by_sev = (scored.groupby("severity")["cvss_score"]
              .agg(["count", "min", "median", "mean", "max"]).reindex(SEVERITY_ORDER).round(2))
    print("\nCVSS score by severity level:")
    print(by_sev.to_string())

    fig, ax = plt.subplots(figsize=(9, 5.5))
    sns.boxplot(data=scored, x="severity", y="cvss_score", order=SEVERITY_ORDER,
                hue="severity", palette=SEVERITY_COLORS, legend=False, width=0.55, ax=ax)
    ax.set_xticks(range(len(SEVERITY_ORDER)))
    ax.set_xticklabels([f"{s.capitalize()}\n(n={int(by_sev.loc[s, 'count'])})" for s in SEVERITY_ORDER])
    ax.set_ylim(0, 10.5)
    ax.set_title("CVSS Score by Severity Level", pad=15)
    ax.set_xlabel("Severity level (GitHub classification)")
    ax.set_ylabel("CVSS base score")
    plt.tight_layout()
    save_figure(fig, "cvss_by_severity.png")

    print("\nCVSS score by scoring version:")
    print(scored.groupby("cvss_version")["cvss_score"].agg(["count", "mean", "median"]).round(2).to_string())

    # Observations
    low_to_high = ["low", "medium", "high", "critical"]
    ranges = scored.groupby("severity")["cvss_score"].agg(["min", "max"]).reindex(low_to_high)
    bands_do_not_overlap = all(
        ranges.loc[lower, "max"] < ranges.loc[upper, "min"]
        for lower, upper in zip(low_to_high[:-1], low_to_high[1:])
    )
    skew_text = ("left-skewed (a tail of low scores pulls the mean below the median)"
                 if median_cvss > mean_cvss else "right-skewed")
    ver = scored.groupby("cvss_version")["cvss_score"].mean()
    hist_counts, hist_edges = np.histogram(scored["cvss_score"], bins=np.arange(0, 10.5, 0.5))
    peak_i = int(hist_counts.argmax())
    share_5_to_9 = scored["cvss_score"].between(5.0, 9.0).mean() * 100
    zero_labels = ", ".join(sorted(scored.loc[scored["cvss_score"] == 0, "severity"].unique()))
    print()
    show(
        "Key observations",
        f"- Scores cover the range **{scored['cvss_score'].min():.1f} - {scored['cvss_score'].max():.1f}** with mean **{mean_cvss:.2f}** and median **{median_cvss:.2f}**; the distribution is {skew_text}.",
        f"- **{share_5_to_9:.1f}%** of the scores lie between 5.0 and 9.0, and the tallest bar of the histogram is the {hist_edges[peak_i]:.1f}-{hist_edges[peak_i + 1]:.1f} range ({hist_counts[peak_i]} advisories).",
        f"- The four severity levels occupy separate, non-overlapping score bands: {bands_do_not_overlap}. "
        f"Critical: {ranges.loc['critical', 'min']:.1f}-{ranges.loc['critical', 'max']:.1f}, high: {ranges.loc['high', 'min']:.1f}-{ranges.loc['high', 'max']:.1f}, "
        f"medium: {ranges.loc['medium', 'min']:.1f}-{ranges.loc['medium', 'max']:.1f}, low: {ranges.loc['low', 'min']:.1f}-{ranges.loc['low', 'max']:.1f}.",
        f"- Advisories scored with CVSS 4.0 have a mean of {ver['4.0']:.2f}, those scored with 3.x have a mean of {ver['3.x']:.2f}.",
        f"- {int((scored['cvss_score'] == 0).sum())} advisories have a genuine score of 0.0 (a vector with no impact), labelled: {zero_labels}.",
    )
    return {"n_scored": n_scored, "mean_cvss": mean_cvss, "median_cvss": median_cvss,
            "bands_do_not_overlap": bands_do_not_overlap}


# =====================================================================
# 8. CWE
# =====================================================================
def cwe_analysis(df):
    """Most frequent weaknesses; every CWE of a multi-CWE advisory is counted."""
    print_header("8. CWE ANALYSIS")
    cwe = explode_multi(df, "cwe_ids").rename(columns={"cwe_ids": "cwe"})   # one row per (advisory, CWE)
    n_with_cwe = int(df["cwe_ids"].notna().sum())
    cwe_counts = cwe["cwe"].value_counts()
    top_cwes = cwe_counts.head(10)

    print(f"Advisories with at least one CWE : {n_with_cwe:,} of {len(df):,}")
    print(f"Distinct CWE identifiers         : {cwe_counts.size}")
    print(f"Total CWE tags (after splitting) : {len(cwe):,}\n")

    # Chart: top 10 CWEs
    labels = [f"{c}  {CWE_NAMES.get(c, '')}".strip() for c in top_cwes.index]
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.barh(labels, top_cwes.values, color=PRIMARY_COLOR)
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    for y, v in enumerate(top_cwes.values):
        ax.text(v + top_cwes.max() * 0.01, y, f"{v} ({v / n_with_cwe * 100:.1f}%)",
                va="center", fontsize=10, fontweight="bold")
    ax.set_xlim(0, top_cwes.max() * 1.15)
    ax.set_title("Top 10 Most Frequent CWE Weaknesses", pad=15)
    ax.set_xlabel(f"Number of advisories (percentage of the {n_with_cwe:,} advisories that have a CWE)")
    ax.set_ylabel("CWE identifier and name")
    plt.tight_layout()
    save_figure(fig, "cwe_analysis.png")

    # Which weaknesses are typical for CRITICAL advisories?
    crit_cwe = cwe.loc[cwe["severity"] == "critical", "cwe"].value_counts().head(5)
    crit_table = pd.DataFrame({
        "name": [CWE_NAMES.get(c, "") for c in crit_cwe.index],
        "critical_advisories": crit_cwe.values,
    }, index=crit_cwe.index)
    print("Top 5 CWEs among CRITICAL advisories:")
    print(crit_table.to_string())

    # Resource exhaustion (denial-of-service) group
    dos_ids = {"CWE-400", "CWE-770", "CWE-407", "CWE-1333"}
    dos_adv = cwe.loc[cwe["cwe"].isin(dos_ids), "ghsa_id"].nunique()
    dos_df = cwe.loc[cwe["cwe"].isin(dos_ids)].drop_duplicates("ghsa_id")
    dos_critical = int((dos_df["severity"] == "critical").sum())
    dos_high_medium = dos_df["severity"].isin(["high", "medium"]).mean() * 100
    inj_df = cwe.loc[cwe["cwe"].isin({"CWE-94", "CWE-78"})].drop_duplicates("ghsa_id")
    inj_critical_share = (inj_df["severity"] == "critical").mean() * 100
    n_multi_cwe = int(df["cwe_ids"].str.contains(",", na=False).sum())
    critical_share_all = (df["severity"] == "critical").mean() * 100

    print()
    show(
        "Key observations",
        f"- **{top_cwes.index[0]}** ({CWE_NAMES.get(top_cwes.index[0], '')}) is the most frequent weakness with **{top_cwes.iloc[0]}** advisories ({top_cwes.iloc[0] / n_with_cwe * 100:.1f}%), "
        f"followed by **{top_cwes.index[1]}** ({top_cwes.iloc[1]}) and **{top_cwes.index[2]}** ({top_cwes.iloc[2]}).",
        f"- **{n_multi_cwe}** advisories ({n_multi_cwe / len(df) * 100:.1f}%) list more than one CWE, which is why splitting matters.",
        f"- Resource-exhaustion weaknesses (CWE-400, 770, 407, 1333) appear in **{dos_adv}** distinct advisories ({dos_adv / n_with_cwe * 100:.1f}% of advisories with a CWE).",
        f"- Of the resource-exhaustion advisories, **{dos_high_medium:.1f}%** are high or medium and **{dos_critical}** are critical.",
        f"- Advisories with code or OS command injection (CWE-94 / CWE-78) are critical in **{inj_critical_share:.1f}%** of cases, compared with {critical_share_all:.1f}% for all advisories.",
        f"- The most common CWEs among **critical** advisories are **{crit_cwe.index[0]}** ({CWE_NAMES.get(crit_cwe.index[0], '')}, {crit_cwe.iloc[0]}) and **{crit_cwe.index[1]}** ({CWE_NAMES.get(crit_cwe.index[1], '')}, {crit_cwe.iloc[1]}).",
        f"- The long tail is large: {cwe_counts.size} distinct CWEs occur, and the top 10 cover {top_cwes.sum() / len(cwe) * 100:.1f}% of all CWE tags.",
    )
    return {"top_cwes": top_cwes, "crit_cwe": crit_cwe}


# =====================================================================
# 9. TEMPORAL
# =====================================================================
def temporal_analysis(df):
    """Advisories per day (with 7-day average), per weekday, and a monthly summary."""
    print_header("9. TEMPORAL ANALYSIS")
    published_day = df["published_at"].dt.tz_convert("UTC").dt.tz_localize(None).dt.normalize()
    all_days = pd.date_range(published_day.min(), published_day.max(), freq="D")
    daily = published_day.value_counts().reindex(all_days, fill_value=0).sort_index()
    rolling_7 = daily.rolling(window=7, min_periods=7).mean()          # trailing 7-day average

    weekday_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    weekday_totals = published_day.dt.day_of_week.value_counts().reindex(range(7), fill_value=0)
    peak_day = daily.idxmax()
    peak_rows = df.loc[published_day == peak_day]

    fig, axes = plt.subplots(1, 2, figsize=(15, 5.5), gridspec_kw={"width_ratios": [2.6, 1]})

    # Left: daily counts and rolling average
    ax = axes[0]
    bar_colors = ["#9aa5b1" if d.day_of_week >= 5 else PRIMARY_COLOR for d in daily.index]
    ax.bar(daily.index, daily.values, color=bar_colors, width=0.8, label="Advisories per day (grey = weekend)")
    ax.plot(rolling_7.index, rolling_7.values, color="#e65c00", linewidth=2.5, label="7-day rolling average")
    ax.annotate(f"Peak: {daily.max()} advisories\n{peak_day:%d %b %Y}",
                xy=(peak_day, daily.max()), xytext=(10, -5), textcoords="offset points",
                fontsize=10, fontweight="bold", va="top")
    ax.xaxis.set_major_locator(mdates.WeekdayLocator(byweekday=mdates.MO))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    ax.set_ylim(0, daily.max() * 1.1)
    ax.set_title("Advisories Published per Day", pad=15)
    ax.set_xlabel("Publication date (UTC), Mondays labelled")
    ax.set_ylabel("Number of advisories")
    ax.legend(frameon=False, loc="upper left")

    # Right: total per weekday
    ax = axes[1]
    wk_colors = [PRIMARY_COLOR if i < 5 else "#9aa5b1" for i in range(7)]
    ax.bar(weekday_names, weekday_totals.values, color=wk_colors, width=0.7)
    for x, v in enumerate(weekday_totals.values):
        ax.text(x, v + weekday_totals.max() * 0.01, f"{v}", ha="center", fontsize=9, fontweight="bold")
    ax.set_ylim(0, weekday_totals.max() * 1.12)
    ax.set_title("Total by Weekday", pad=15)
    ax.set_xlabel("Day of week")
    ax.set_ylabel("Number of advisories")

    plt.tight_layout()
    save_figure(fig, "temporal_trends.png")

    # Monthly summary (September is only partly covered)
    month = published_day.dt.to_period("M")
    monthly = published_day.groupby(month).agg(first_day="min", last_day="max")
    monthly["advisories"] = month.value_counts().sort_index()
    monthly["calendar_days_covered"] = (monthly["last_day"] - monthly["first_day"]).dt.days + 1
    monthly["advisories_per_calendar_day"] = (monthly["advisories"] / monthly["calendar_days_covered"]).round(1)
    monthly["first_day"] = monthly["first_day"].dt.strftime("%d %b")
    monthly["last_day"] = monthly["last_day"].dt.strftime("%d %b")
    print("\nMonthly summary (September is only partly covered):")
    print(monthly.to_string())

    # Observations
    weekday_share = weekday_totals.iloc[:5].sum() / weekday_totals.sum() * 100
    weekend_total = int(weekday_totals.iloc[5:].sum())
    zero_days = daily[daily == 0]
    zero_weekend = int((zero_days.index.day_of_week >= 5).sum())
    busiest_weekday = weekday_names[int(weekday_totals.idxmax())]
    peak_eco = peak_rows["ecosystem"].value_counts()
    peak_pkg = peak_rows["package_name"].value_counts()
    print()
    show(
        "Key observations",
        f"- Advisories were published on **{int((daily > 0).sum())} of {len(daily)}** calendar days; the average is **{daily.mean():.1f}** per day.",
        f"- **{weekday_share:.1f}%** were published Monday to Friday; only **{weekend_total}** appeared on a weekend. {busiest_weekday} is the busiest weekday.",
        f"- The peak day is **{peak_day:%d %b %Y}** with **{daily.max()}** advisories; on that day **{peak_eco.index[0]}** accounts for {peak_eco.iloc[0]} advisories "
        f"and the most frequent package is **{peak_pkg.index[0]}** ({peak_pkg.iloc[0]}).",
        f"- Of the {len(zero_days)} days without any advisory, {zero_weekend} were weekend days.",
    )
    return {"daily": daily, "weekday_share": weekday_share, "peak_day": peak_day}


# =====================================================================
# 10. PACKAGES
# =====================================================================
def package_analysis(df):
    """Most affected packages; the package column is split so nothing is double counted."""
    print_header("10. PACKAGE ANALYSIS")
    pkg = explode_multi(df, "package_name").rename(columns={"package_name": "package"})
    pkg = pkg.drop_duplicates(subset=["ghsa_id", "package"])           # one count per advisory and package
    pkg_counts = pkg["package"].value_counts()
    top_pkgs = pkg_counts.head(10)

    n_unique_pkgs = pkg_counts.size
    single_pkgs = int((pkg_counts == 1).sum())
    repeat_pkgs = int((pkg_counts >= 5).sum())
    print(f"Distinct packages: {n_unique_pkgs:,}")
    print(f"Packages with exactly one advisory: {single_pkgs:,}")
    print(f"Packages with five or more advisories: {repeat_pkgs}\n")

    fig, ax = plt.subplots(figsize=(11, 6))
    ax.barh(top_pkgs.index, top_pkgs.values, color=PRIMARY_COLOR)
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    for y, v in enumerate(top_pkgs.values):
        ax.text(v + top_pkgs.max() * 0.01, y, f"{v}", va="center", fontsize=10, fontweight="bold")
    ax.set_xlim(0, top_pkgs.max() * 1.1)
    ax.set_title("Top 10 Packages by Number of Advisories", pad=15)
    ax.set_xlabel("Number of advisories")
    ax.set_ylabel("Package name")
    plt.tight_layout()
    save_figure(fig, "package_analysis.png")

    top10_share = top_pkgs.sum() / len(pkg) * 100
    print()
    show(
        "Key observations",
        f"- **{n_unique_pkgs:,}** distinct packages appear in the {len(df):,} advisories.",
        f"- **{top_pkgs.index[0]}** has the most advisories (**{top_pkgs.iloc[0]}**), followed by **{top_pkgs.index[1]}** ({top_pkgs.iloc[1]}) and **{top_pkgs.index[2]}** ({top_pkgs.iloc[2]}).",
        f"- **{single_pkgs / n_unique_pkgs * 100:.1f}%** of the packages ({single_pkgs:,}) have just one advisory.",
        f"- The ten most affected packages together account for only **{top10_share:.1f}%** of all package-advisory pairs, so the problem is spread over many packages.",
    )
    return {"n_unique_pkgs": n_unique_pkgs, "single_pkgs": single_pkgs, "top_pkgs": top_pkgs,
            "top10_share": top10_share}


# =====================================================================
# 11. KEY FINDINGS
# =====================================================================
def print_key_findings(df, quality, severity, ecosystem, cvss, cwe, temporal, packages):
    """Summarise the results of all sections (numbers come from the analysis above)."""
    print_header("11. KEY FINDINGS")
    sev_counts, sev_pct, top_sev = severity["sev_counts"], severity["sev_pct"], severity["top_sev"]
    top3, top3_adv = ecosystem["top3"], ecosystem["top3_adv"]
    top_cwes, crit_cwe = cwe["top_cwes"], cwe["crit_cwe"]
    daily = temporal["daily"]

    show(
        f"1. Dataset: {len(df):,} GitHub-reviewed advisories published between {df['published_at'].min():%d %b %Y} and {df['published_at'].max():%d %b %Y} ({len(daily)} days).",
        f"2. Data quality: no duplicates; only {quality['n_no_cvss']} advisories ({quality['n_no_cvss'] / len(df) * 100:.1f}%) lack a CVSS score; {quality['n_withdrawn']} advisories are withdrawn and flagged.",
        f"3. Severity: {top_sev} ({sev_pct[top_sev]:.1f}%) and medium ({sev_pct['medium']:.1f}%) dominate; critical is {sev_pct['critical']:.1f}% ({sev_counts['critical']} advisories).",
        f"4. Ecosystems: {top3[0]}, {top3[1]} and {top3[2]} cover {top3_adv / len(df) * 100:.1f}% of all advisories; the severity mix is similar in these three.",
        f"5. CVSS: mean {cvss['mean_cvss']:.2f}, median {cvss['median_cvss']:.2f} (n = {cvss['n_scored']:,}). Severity levels map to separate score bands (no overlap: {cvss['bands_do_not_overlap']}).",
        f"6. CWE: the most frequent weakness is {top_cwes.index[0]} ({CWE_NAMES.get(top_cwes.index[0], '')}, {top_cwes.iloc[0]} advisories); "
        f"critical advisories are led by {crit_cwe.index[0]} ({CWE_NAMES.get(crit_cwe.index[0], '')}) and {crit_cwe.index[1]} ({CWE_NAMES.get(crit_cwe.index[1], '')}).",
        f"7. Time: {temporal['weekday_share']:.1f}% of advisories were published on weekdays; the busiest day was {temporal['peak_day']:%d %b %Y} with {daily.max()} advisories.",
        f"8. Packages: {packages['n_unique_pkgs']:,} distinct packages are affected; {packages['single_pkgs'] / packages['n_unique_pkgs'] * 100:.1f}% have only one advisory, "
        f"and the top ten make up only {packages['top10_share']:.1f}% of all package-advisory pairs.",
    )


# =====================================================================
# MAIN
# =====================================================================
def main():
    """Run the complete EDA, exactly in the order of the notebook."""
    print("=" * 70)
    print("ADVISORYLENS EDA")
    print("=" * 70)
    set_plot_style()

    try:
        df = load_data()
    except FileNotFoundError as error:
        print(f"[ERROR] {error}")
        sys.exit(1)

    dataset_overview(df)
    quality = data_quality_analysis(df)
    severity = severity_analysis(df)
    ecosystem = ecosystem_analysis(df)
    cvss = cvss_analysis(df)
    cwe = cwe_analysis(df)
    temporal = temporal_analysis(df)
    packages = package_analysis(df)
    print_key_findings(df, quality, severity, ecosystem, cvss, cwe, temporal, packages)

    print_header("EDA COMPLETED")
    print("Charts saved in outputs/visualizations/:")
    for path in sorted(VIZ_DIR.glob("*.png")):
        print(f"  - {path.name}")


if __name__ == "__main__":
    main()
