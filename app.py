"""
app.py  --  AdvisoryLens Security Analytics Dashboard (Streamlit + Plotly).

An interactive layer on top of the finished ETL + EDA project. It only READS the
existing data (SQLite database, or the processed CSV as a fallback); it never
changes the database, the ETL pipeline, the notebook or src/eda.py.

Run from the project root:
    streamlit run app.py
"""

from contextlib import closing
from html import escape
import itertools
from pathlib import Path
import sqlite3
from datetime import datetime

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# =====================================================================
# SETTINGS
# =====================================================================
PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = PROJECT_ROOT / "database" / "advisories.db"
CSV_PATH = PROJECT_ROOT / "data" / "processed" / "processed_advisories.csv"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLORS = {"critical": "#ff3b6b", "high": "#ff8a2b", "medium": "#ffd23f", "low": "#2ee6a6"}

# Theme "Neon Aurora": near-black midnight background, glowing violet/cyan, vivid chart colours.
# (COLOR_BG, COLOR_TEXT and the accent are repeated in .streamlit/config.toml)
COLOR_BG = "#070b18"                      # page background
COLOR_PANEL = "#0f1634"                   # cards and panels
COLOR_BORDER = "rgba(255,255,255,0.12)"
COLOR_GRID = "rgba(255,255,255,0.08)"     # chart grid lines
COLOR_TEXT = "#f5f7ff"
COLOR_MUTED = "#9aa7d0"
COLOR_ACCENT = "#22d3ee"                  # electric cyan: main accent
COLOR_ACCENT_2 = "#f472b6"                # hot pink: second accent
COLOR_VIOLET = "#8b5cf6"
COLOR_MIXED = "#64748b"                   # neutral slate (weekends, "other", unknown)

# One-colour bar charts use a gradient: small values violet -> large values cyan
GRADIENT_STOPS = ["#7c3aed", "#3b82f6", "#22d3ee"]

# Short names from the public MITRE CWE list (only used to make labels readable)
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
DOS_CWES = ["CWE-400", "CWE-770", "CWE-407", "CWE-1333"]     # resource exhaustion / denial of service
INJECTION_CWES = ["CWE-94", "CWE-78"]                        # code and OS command injection

# Colours for ecosystems (used when a chart is coloured by ecosystem)
ECOSYSTEM_COLORS = ["#22d3ee", "#a78bfa", "#f472b6", "#fbbf24", "#34d399", "#fb7185",
                    "#60a5fa", "#fb923c", "#c084fc", "#a3e635", "#94a3b8"]

# The columns the dashboard needs. If one is missing we show a clear message.
REQUIRED_COLUMNS = [
    "ghsa_id", "cve_id", "summary", "severity", "cvss_score", "published_at",
    "updated_at", "is_withdrawn", "cwe_ids", "ecosystem", "package_name",
]

PAGES = ["Overview", "Severity", "Ecosystem", "CVSS", "CWE", "Timeline", "Packages", "Advisory Explorer"]

st.set_page_config(page_title="AdvisoryLens | Security Analytics", page_icon="🛡️", layout="wide")


# =====================================================================
# STYLE
# =====================================================================
def build_animation_css():
    """
    CSS animations that make the dashboard feel alive. They run whenever an element appears, which also happens
    after every filter change, so charts rise again with the new numbers. Users whose system asks for
    reduced motion do not get them (prefers-reduced-motion).
    """
    ease = "cubic-bezier(.2,.8,.2,1)"
    bars_vertical = "[class*='st-key-viz-vbars-'] .barlayer .point"
    bars_horizontal = "[class*='st-key-viz-hbars-'] .barlayer .point"
    stagger = "".join(
        f"{prefix}:nth-child({n}) path, {prefix}:nth-child({n}) text {{ animation-delay: {0.05 * (n - 1):.2f}s; }}\n"
        for prefix in (bars_vertical, bars_horizontal) for n in range(2, 14)
    )
    tiles = "".join(f"[class*='st-key-viz-tree-'] .slice:nth-child({n}) {{ animation-delay: {0.04 * (n - 1):.2f}s; }}\n"
                    for n in range(2, 20))
    return f"""
    @media (prefers-reduced-motion: no-preference) {{
        @keyframes growY {{ from {{ transform: scaleY(0); }} to {{ transform: scaleY(1); }} }}
        @keyframes growX {{ from {{ transform: scaleX(0); }} to {{ transform: scaleX(1); }} }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
        @keyframes riseIn {{ from {{ opacity: 0; transform: translateY(24px); }} to {{ opacity: 1; transform: none; }} }}
        @keyframes popIn {{ from {{ opacity: 0; transform: scale(.45) rotate(-80deg); }} to {{ opacity: 1; transform: none; }} }}
        @keyframes popTile {{ from {{ opacity: 0; transform: scale(.35); }} to {{ opacity: 1; transform: none; }} }}

        /* Cards, headings, tables and panels slide up */
        .kpi {{ animation: riseIn .65s {ease} backwards; }}
        div[data-testid="stColumn"]:nth-child(2) .kpi {{ animation-delay: .08s; }}
        div[data-testid="stColumn"]:nth-child(3) .kpi {{ animation-delay: .16s; }}
        div[data-testid="stColumn"]:nth-child(4) .kpi {{ animation-delay: .24s; }}
        .page-title {{ animation: riseIn .6s {ease} backwards; }}
        .page-sub {{ animation: riseIn .6s .08s {ease} backwards; }}
        div[data-testid="stDataFrame"], div[data-testid="stVerticalBlockBorderWrapper"] {{ animation: riseIn .7s .1s {ease} backwards; }}
        [class*="st-key-viz-"] {{ animation: fadeIn .5s ease-out backwards; }}

        /* Bars grow from the baseline, one after the other */
        {bars_vertical} path {{ transform-box: fill-box; transform-origin: 50% 100%; animation: growY .95s {ease} backwards; }}
        {bars_horizontal} path {{ transform-box: fill-box; transform-origin: 0% 50%; animation: growX .95s {ease} backwards; }}
        {bars_vertical} text, {bars_horizontal} text {{ animation: fadeIn .6s .55s ease-out backwards; }}
        {stagger}
        /* Lines and areas rise; a line on top of bars fades in after them */
        [class*="st-key-viz-lines-"] .scatterlayer {{ transform-box: fill-box; transform-origin: 50% 100%; animation: growY 1.1s {ease} backwards; }}
        [class*="st-key-viz-vbars-"] .scatterlayer {{ animation: fadeIn .9s .5s ease-out backwards; }}
        /* Donut spins in, treemap tiles pop in, box plots rise */
        [class*="st-key-viz-pie-"] .pielayer .trace {{ transform-box: fill-box; transform-origin: 50% 50%; animation: popIn 1.1s {ease} backwards; }}
        [class*="st-key-viz-pie-"] .annotation {{ animation: fadeIn 1s .6s ease-out backwards; }}
        [class*="st-key-viz-tree-"] .slice {{ transform-box: fill-box; transform-origin: 50% 50%; animation: popTile .7s {ease} backwards; }}
        {tiles}
        [class*="st-key-viz-box-"] .boxlayer .trace {{ transform-box: fill-box; transform-origin: 50% 100%; animation: growY .95s {ease} backwards; }}
    }}
    """


def inject_css(animations=True):
    """Custom CSS: glowing background, glass cards, gradient headings, sidebar details (+ animations)."""
    animation_css = build_animation_css() if animations else ""
    st.markdown(
        f"""
        <style>
        /* ---- Page background: midnight with two soft colour glows ---- */
        [data-testid="stAppViewContainer"] {{
            background:
                radial-gradient(1100px 560px at 90% -8%, rgba(139,92,246,0.34), transparent 62%),
                radial-gradient(900px 520px at 4% 108%, rgba(34,211,238,0.20), transparent 58%),
                radial-gradient(700px 400px at 50% 50%, rgba(244,114,182,0.05), transparent 70%),
                {COLOR_BG};
        }}
        [data-testid="stHeader"] {{ background: transparent; }}
        .block-container {{ padding-top: 3.2rem; max-width: 1400px; }}
        #MainMenu, footer, .stAppDeployButton {{ visibility: hidden; display: none; }}

        /* ---- Sidebar ---- */
        section[data-testid="stSidebar"] > div:first-child {{
            background: linear-gradient(185deg, #151b4d 0%, #0d1233 48%, #0a0e25 100%);
        }}
        section[data-testid="stSidebar"] {{ border-right: 1px solid rgba(34,211,238,0.25); }}

        /* ---- Filter chips ---- */
        span[data-tag] {{ background-color: rgba(34,211,238,0.16) !important; border: 1px solid rgba(34,211,238,0.55) !important; }}
        span[data-tag] span, span[data-tag] button {{ color: {COLOR_TEXT} !important; }}

        /* ---- Text styles ---- */
        .brand {{ font-size: 1.45rem; font-weight: 800; color: {COLOR_TEXT}; letter-spacing: .3px; }}
        .brand span {{ background: linear-gradient(90deg, {COLOR_ACCENT}, {COLOR_VIOLET} 55%, {COLOR_ACCENT_2});
                       -webkit-background-clip: text; background-clip: text; color: transparent; }}
        .brand-sub {{ color: {COLOR_MUTED}; font-size: .78rem; margin-bottom: .6rem; }}

        .page-title {{ font-size: 1.9rem; font-weight: 800; margin-bottom: 0;
                       background: linear-gradient(90deg, #ffffff 0%, #c7f6ff 55%, #e9d5ff 100%);
                       -webkit-background-clip: text; background-clip: text; color: transparent; }}
        .page-sub {{ color: {COLOR_MUTED}; font-size: .92rem; margin-bottom: 1.2rem; }}

        .section-title {{ font-size: 1.08rem; font-weight: 700; color: {COLOR_TEXT}; margin: .4rem 0 .1rem 0; }}
        .section-sub {{ color: {COLOR_MUTED}; font-size: .82rem; margin-bottom: .5rem; }}

        /* ---- KPI cards: glass look with a coloured glow ---- */
        .kpi {{ background: linear-gradient(150deg, rgba(255,255,255,0.09) 0%, rgba(255,255,255,0.025) 100%);
                border: 1px solid {COLOR_BORDER}; border-top: 3px solid var(--accent);
                border-radius: 14px; padding: 14px 18px; height: 100%;
                box-shadow: 0 14px 34px -18px var(--accent); backdrop-filter: blur(6px); }}
        .kpi-label {{ color: {COLOR_MUTED}; font-size: .72rem; text-transform: uppercase; letter-spacing: .9px; }}
        .kpi-value {{ color: {COLOR_TEXT}; font-size: clamp(1.3rem, 2vw, 1.9rem); font-weight: 800; line-height: 1.25;
                      white-space: nowrap; }}
        .kpi-sub {{ color: {COLOR_MUTED}; font-size: .78rem; }}

        .pill {{ display: inline-block; background: rgba(34,211,238,0.12); border: 1px solid rgba(34,211,238,0.45);
                 border-radius: 999px; padding: 4px 12px; font-size: .78rem; color: {COLOR_TEXT}; }}

        /* ---- Bordered containers (panels) ---- */
        div[data-testid="stVerticalBlockBorderWrapper"] {{
            background: linear-gradient(160deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.015) 100%);
            border: 1px solid {COLOR_BORDER}; border-radius: 14px;
        }}

        table.kv {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
        table.kv td {{ padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.08); }}
        table.kv td:first-child {{ color: {COLOR_MUTED}; }}
        table.kv td:last-child {{ text-align: right; color: {COLOR_TEXT}; font-weight: 600; }}
        table.kv tr:last-child td {{ border-bottom: none; }}

        /* ---- Hover effects: cards lift, sidebar menu items slide ---- */
        .kpi {{ transition: transform .25s cubic-bezier(.2,.8,.2,1), box-shadow .25s ease; }}
        .kpi:hover {{ transform: translateY(-5px); box-shadow: 0 22px 42px -14px var(--accent); }}
        section[data-testid="stSidebar"] div[role="radiogroup"] label {{ transition: transform .18s ease; }}
        section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {{ transform: translateX(5px); }}

        {animation_css}

        /* Responsive: on smaller screens columns wrap (2 per row, then 1 per row) */
        @media (max-width: 1100px) {{
            div[data-testid="stHorizontalBlock"] {{ flex-wrap: wrap; row-gap: .8rem; }}
            div[data-testid="stColumn"] {{ min-width: calc(50% - 1rem) !important; flex: 1 1 calc(50% - 1rem) !important; }}
        }}
        @media (max-width: 700px) {{
            div[data-testid="stColumn"] {{ min-width: 100% !important; flex: 1 1 100% !important; }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def page_header(title, subtitle):
    st.markdown(f'<div class="page-title">{escape(title)}</div><div class="page-sub">{escape(subtitle)}</div>',
                unsafe_allow_html=True)


def section_title(title, subtitle=""):
    html = f'<div class="section-title">{escape(title)}</div>'
    if subtitle:
        html += f'<div class="section-sub">{escape(subtitle)}</div>'
    st.markdown(html, unsafe_allow_html=True)


def kpi_card(label, value, sub="", accent=COLOR_ACCENT):
    """One KPI card (HTML, so we control the look)."""
    st.markdown(
        f'<div class="kpi" style="--accent:{accent}"><div class="kpi-label">{escape(label)}</div>'
        f'<div class="kpi-value">{escape(str(value))}</div><div class="kpi-sub">{escape(sub)}</div></div>',
        unsafe_allow_html=True,
    )


def style_figure(fig, height=380):
    """Same look for every Plotly chart: transparent background, light text, soft grid."""
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLOR_TEXT, size=13),
        margin=dict(l=10, r=10, t=10, b=10),
        hoverlabel=dict(bgcolor="#141c44", bordercolor=COLOR_ACCENT, font_color=COLOR_TEXT),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(gridcolor=COLOR_GRID, zerolinecolor=COLOR_GRID, linecolor=COLOR_BORDER, automargin=True)
    fig.update_yaxes(gridcolor=COLOR_GRID, zerolinecolor=COLOR_GRID, linecolor=COLOR_BORDER, automargin=True)
    fig.update_traces(marker_cornerradius=6, selector=dict(type="bar"))     # softly rounded bars
    return fig


def blend_colors(color_a, color_b, t):
    """Blend two '#rrggbb' colours (t=0 gives color_a, t=1 gives color_b)."""
    a = [int(color_a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(color_b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def gradient_colors(values, vmax=None):
    """One colour per value on the violet -> blue -> cyan gradient (bigger value = brighter)."""
    values = list(values)
    vmax = vmax if vmax else (max(values) if values else 1)
    colors = []
    for value in values:
        t = min(max(value / vmax, 0), 1) if vmax else 0
        position = t * (len(GRADIENT_STOPS) - 1)
        index = min(int(position), len(GRADIENT_STOPS) - 2)
        colors.append(blend_colors(GRADIENT_STOPS[index], GRADIENT_STOPS[index + 1], position - index))
    return colors


CHART_NUMBER = itertools.count(1)       # restarts at 1 on every script run, so chart keys are stable


def show_chart(fig, kind="other"):
    """
    Draw a Plotly chart at full width (works with old and new Streamlit versions).

    `kind` tells the animation CSS how the chart should appear:
    vbars / hbars (bars grow), lines (area rises), pie (donut spins in), tree (tiles pop in), box.
    The chart is wrapped in a container whose key becomes the CSS class "st-key-viz-<kind>-<number>".
    """
    config = {"displaylogo": False}
    with st.container(key=f"viz-{kind}-{next(CHART_NUMBER)}"):
        try:
            st.plotly_chart(fig, width="stretch", theme=None, config=config)
        except TypeError:
            st.plotly_chart(fig, use_container_width=True, theme=None, config=config)


def show_table(table, **options):
    """Draw a table at full width without the row index (works with old and new Streamlit versions)."""
    try:
        st.dataframe(table, width="stretch", hide_index=True, **options)
    except TypeError:
        st.dataframe(table, use_container_width=True, hide_index=True, **options)


# =====================================================================
# DATA LOADING (cached)
# =====================================================================
def locate_source():
    """Use the SQLite database (same source as the notebook); CSV is the fallback."""
    if DB_PATH.exists():
        return "db", DB_PATH
    if CSV_PATH.exists():
        return "csv", CSV_PATH
    return None, None


@st.cache_data(show_spinner="Loading advisories...")
def load_data(kind, path_text, modified_time):
    """
    Read the advisories. `modified_time` is only part of the cache key: when the
    database file changes (pipeline re-run), the cache refreshes automatically.
    The database is opened READ-ONLY, so the dashboard can never change it.
    """
    if kind == "db":
        uri = Path(path_text).resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            df = pd.read_sql_query("SELECT * FROM advisories", conn)
    else:
        df = pd.read_csv(path_text)
    return df


def prepare_data(df):
    """Fix data types and add helper columns used by filters and charts."""
    df = df.copy()
    df["severity"] = df["severity"].astype("string").str.lower()
    df["published_at"] = pd.to_datetime(df["published_at"], utc=True)
    df["updated_at"] = pd.to_datetime(df["updated_at"], utc=True)
    df["is_withdrawn"] = df["is_withdrawn"].astype(bool)
    df["published_date"] = df["published_at"].dt.date

    # Multi-value columns ("npm, pip") become real lists, so they can be counted correctly.
    for source, target in (("ecosystem", "ecosystem_list"), ("package_name", "package_list"), ("cwe_ids", "cwe_list")):
        df[target] = df[source].fillna("").map(lambda text: [p.strip() for p in str(text).split(",") if p.strip()])
    return df


def get_data():
    """Load and prepare the data, or show a friendly error and stop the app."""
    kind, path = locate_source()
    if path is None:
        st.error("No data found. Please run the ETL pipeline first.")
        st.code("python pipeline.py", language="bash")
        st.stop()
    try:
        raw = load_data(kind, str(path), path.stat().st_mtime)
    except (sqlite3.Error, pd.errors.ParserError, OSError) as error:
        st.error(f"The data could not be read: {error}")
        st.stop()

    missing = [column for column in REQUIRED_COLUMNS if column not in raw.columns]
    if missing:
        st.error("The data is missing required columns: " + ", ".join(missing)
                 + ". The database was probably built with an older version of the pipeline. Rebuild it:")
        st.code("python pipeline.py", language="bash")
        st.stop()
    if raw.empty:
        st.warning("The data source is empty. Please run the ETL pipeline again.")
        st.stop()
    return prepare_data(raw), kind, path


# =====================================================================
# FILTERS
# =====================================================================
def ecosystem_options(df):
    """Ecosystem names (each one separately), most frequent first."""
    return df["ecosystem_list"].explode().value_counts().index.tolist()


def reset_filters(severities, ecosystems, date_range):
    """Callback of the Reset button: put every filter back to 'everything'."""
    st.session_state["f_severity"] = severities
    st.session_state["f_ecosystem"] = ecosystems
    st.session_state["f_dates"] = date_range


def apply_filters(df, severities, ecosystems, date_range):
    """Return only the advisories that match all selected filters."""
    start, end = date_range
    selected = set(ecosystems)
    mask = (
        df["severity"].isin(severities)
        & df["published_date"].between(start, end)
        # an advisory that affects several ecosystems matches if ANY of them is selected
        & df["ecosystem_list"].map(lambda items: not selected.isdisjoint(items))
    )
    return df[mask]


def render_sidebar(df, kind, path):
    """Sidebar: brand, navigation, filters. Returns (page, filtered_df)."""
    sev_options = [s for s in SEVERITY_ORDER if s in set(df["severity"])]
    eco_options = ecosystem_options(df)
    date_min, date_max = df["published_date"].min(), df["published_date"].max()

    # First visit: every filter starts as 'everything'. Also drop old values that no longer exist.
    st.session_state.setdefault("f_severity", sev_options)
    st.session_state.setdefault("f_ecosystem", eco_options)
    st.session_state.setdefault("f_dates", (date_min, date_max))
    st.session_state["f_severity"] = [v for v in st.session_state["f_severity"] if v in sev_options]
    st.session_state["f_ecosystem"] = [v for v in st.session_state["f_ecosystem"] if v in eco_options]

    with st.sidebar:
        st.markdown('<div class="brand">Advisory<span>Lens</span></div>'
                    '<div class="brand-sub">Open-source security analytics</div>', unsafe_allow_html=True)
        page = st.radio("Navigation", PAGES, label_visibility="collapsed")

        st.divider()
        st.markdown("**Filters**")
        st.multiselect("Severity", sev_options, key="f_severity", format_func=str.capitalize)
        st.multiselect("Ecosystem", eco_options, key="f_ecosystem")
        st.date_input("Publication date", min_value=date_min, max_value=date_max, key="f_dates")
        st.button("Reset filters", on_click=reset_filters, args=(sev_options, eco_options, (date_min, date_max)),
                  width="stretch")

        dates = st.session_state["f_dates"]
        if not isinstance(dates, (tuple, list)) or len(dates) != 2:
            st.info("Pick an end date to complete the date range.")
            dates = (dates[0] if isinstance(dates, (tuple, list)) and dates else date_min, date_max)

        filtered = apply_filters(df, st.session_state["f_severity"], st.session_state["f_ecosystem"], tuple(dates))
        st.markdown(f'<span class="pill">Showing {len(filtered):,} of {len(df):,} advisories</span>',
                    unsafe_allow_html=True)

        st.divider()
        st.toggle("Animations", value=True, key="animations", help="Charts rise and cards slide in. Turn off for a still dashboard.")
        source_name = "SQLite database" if kind == "db" else "processed CSV"
        st.caption(f"Data source: {source_name}  \nGitHub Global Security Advisories")
    return page, filtered


# =====================================================================
# SMALL CALCULATION HELPERS
# =====================================================================
def format_date_range(start, end):
    """
    Returns (short text, year text) for the KPI card, e.g. ('18 Sep - 30 Oct', '2026').
    When the range spans several years, the years are shown in the main text.
    """
    if start.year == end.year:
        return f"{start:%d %b} \u2013 {end:%d %b}", str(end.year)
    return f"{start:%b %Y} \u2013 {end:%b %Y}", ""


def severity_counts(df):
    """Advisory count per severity level, in the fixed order critical -> low."""
    return df["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0).astype(int)


# =====================================================================
# SHARED CHART BUILDERS
# =====================================================================
def daily_series(df):
    """Advisories per calendar day (UTC). Days without any advisory are included as 0."""
    days = df["published_at"].dt.tz_convert("UTC").dt.tz_localize(None).dt.normalize()
    all_days = pd.date_range(days.min(), days.max(), freq="D")
    return days.value_counts().reindex(all_days, fill_value=0).sort_index()


def fig_top_ecosystems(df, top_n=5, height=300):
    """Horizontal bar chart of the largest ecosystems."""
    counts = exploded_ecosystems(df)["ecosystem"].value_counts().head(top_n)
    fig = go.Figure(go.Bar(
        x=counts.values, y=counts.index, orientation="h", marker_color=gradient_colors(counts.values),
        text=[f"{c:,}" for c in counts.values], textposition="outside",
        hovertemplate="<b>%{y}</b><br>Advisories: %{x:,}<extra></extra>",
    ))
    style_figure(fig, height=height)
    fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)")
    fig.update_xaxes(title="Number of advisories", range=[0, max(counts.max() * 1.2, 1)])
    return fig


def fig_daily_publications(df, height=300):
    """Area chart of advisories published per day."""
    daily = daily_series(df)
    fig = go.Figure(go.Scatter(
        x=daily.index, y=daily.values, mode="lines", line=dict(color=COLOR_ACCENT, width=2.5),
        fill="tozeroy", fillgradient=dict(type="vertical", colorscale=[[0, "rgba(34,211,238,0.02)"], [1, "rgba(139,92,246,0.55)"]]),
        hovertemplate="%{x|%a, %d %b %Y}<br>Advisories: %{y:,}<extra></extra>",
    ))
    style_figure(fig, height=height)
    fig.update_xaxes(title="Publication date (UTC)")
    fig.update_yaxes(title="Advisories per day", rangemode="tozero")
    return fig


# =====================================================================
# PAGE: OVERVIEW
# =====================================================================
def page_overview(df, full_df, kind, path):
    page_header("Security Advisory Overview", "A summary of the advisories that match the current filters.")

    total = len(df)
    critical = int((df["severity"] == "critical").sum())
    scores = df["cvss_score"].dropna()
    start, end = df["published_at"].min(), df["published_at"].max()
    days = (end.normalize() - start.normalize()).days + 1

    # ---- KPI cards -------------------------------------------------
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        kpi_card("Total advisories", f"{total:,}",
                 f"{total / len(full_df) * 100:.0f}% of {len(full_df):,} in the database", COLOR_ACCENT)
    with col2:
        kpi_card("Critical advisories", f"{critical:,}",
                 f"{critical / total * 100:.1f}% of the selection", SEVERITY_COLORS["critical"])
    with col3:
        if scores.empty:
            kpi_card("Average CVSS score", "n/a", "no scored advisories in the selection", SEVERITY_COLORS["high"])
        else:
            kpi_card("Average CVSS score", f"{scores.mean():.2f}",
                     f"median {scores.median():.2f} \u00b7 {len(scores):,} scored", SEVERITY_COLORS["high"])
    with col4:
        range_text, year_text = format_date_range(start, end)
        kpi_card("Date range", range_text, f"{year_text} \u00b7 {days} calendar days" if year_text else f"{days} calendar days", COLOR_ACCENT_2)

    st.write("")

    # ---- Severity summary + dataset panels -------------------------
    left, right = st.columns([3, 2], gap="large")

    with left:
        section_title("Severity summary", "Number of advisories per severity level (GitHub classification).")
        counts = severity_counts(df)
        percentages = counts / total * 100
        fig = go.Figure(go.Bar(
            x=[s.capitalize() for s in SEVERITY_ORDER],
            y=counts.values,
            marker_color=[SEVERITY_COLORS[s] for s in SEVERITY_ORDER],
            text=[f"{c:,} ({p:.1f}%)" for c, p in zip(counts.values, percentages.values)],
            textposition="outside",
            customdata=percentages.values,
            hovertemplate="<b>%{x}</b><br>Advisories: %{y:,}<br>Share: %{customdata:.1f}%<extra></extra>",
        ))
        style_figure(fig, height=360)
        fig.update_yaxes(title="Number of advisories", range=[0, max(counts.max() * 1.18, 1)])
        fig.update_xaxes(title="Severity level")
        show_chart(fig, "vbars")

        top = counts.idxmax()
        st.caption(f"{top.capitalize()} is the most common severity in this selection "
                   f"({counts[top]:,} advisories, {percentages[top]:.1f}%).")

    with right:
        with st.container(border=True):
            section_title("Dataset overview")
            packages = df["package_list"].explode().nunique()
            ecosystems = df["ecosystem_list"].explode().nunique()
            with_cwe = int((df["cwe_list"].map(len) > 0).sum())
            refreshed = datetime.fromtimestamp(path.stat().st_mtime)
            rows = [
                ("Advisories in view", f"{total:,}"),
                ("Advisories in database", f"{len(full_df):,}"),
                ("Ecosystems", f"{ecosystems}"),
                ("Distinct packages", f"{packages:,}"),
                ("Advisories with CWE", f"{with_cwe:,}"),
                ("Advisories with CVSS score", f"{len(scores):,}"),
                ("Withdrawn advisories", f"{int(df['is_withdrawn'].sum()):,}"),
                ("Latest advisory update", f"{df['updated_at'].max():%d %b %Y}"),
                ("Database built", f"{refreshed:%d %b %Y, %H:%M}" if kind == "db" else f"{refreshed:%d %b %Y}"),
            ]
            table = "".join(f"<tr><td>{escape(k)}</td><td>{escape(v)}</td></tr>" for k, v in rows)
            st.markdown(f'<table class="kv">{table}</table>', unsafe_allow_html=True)

        with st.container(border=True):
            section_title("Data completeness", "Share of advisories that have a value.")
            completeness = {
                "CVSS score": df["cvss_score"].notna().mean(),
                "CVE id": df["cve_id"].notna().mean(),
                "CWE": (df["cwe_list"].map(len) > 0).mean(),
            }
            for label, share in completeness.items():
                st.progress(float(share), text=f"{label}: {share * 100:.1f}%")

    # ---- Two small charts: where and when --------------------------
    st.write("")
    mini_left, mini_right = st.columns(2, gap="large")
    with mini_left:
        section_title("Top ecosystems", "The five ecosystems with the most advisories.")
        show_chart(fig_top_ecosystems(df, top_n=5, height=300), "hbars")
    with mini_right:
        section_title("Publications over time", "Advisories published per day.")
        show_chart(fig_daily_publications(df, height=300), "lines")


# =====================================================================
# PAGE: SEVERITY
# =====================================================================
def page_severity(df, full_df):
    page_header("Severity Analytics", "How the selected advisories are distributed across severity levels.")

    total = len(df)
    counts = severity_counts(df)
    shares = counts / total * 100

    # One card per severity level (colour = severity)
    for column, severity in zip(st.columns(4), SEVERITY_ORDER):
        with column:
            kpi_card(severity.capitalize(), f"{counts[severity]:,}",
                     f"{shares[severity]:.1f}% of the selection", SEVERITY_COLORS[severity])
    st.write("")

    left, right = st.columns([3, 2], gap="large")

    with left:
        section_title("Advisories per severity level", "Number of advisories and share of the selection.")
        fig = go.Figure(go.Bar(
            x=[s.capitalize() for s in SEVERITY_ORDER],
            y=counts.values,
            marker_color=[SEVERITY_COLORS[s] for s in SEVERITY_ORDER],
            text=[f"{c:,} ({p:.1f}%)" for c, p in zip(counts.values, shares.values)],
            textposition="outside",
            customdata=shares.values,
            hovertemplate="<b>%{x}</b><br>Advisories: %{y:,}<br>Share: %{customdata:.1f}%<extra></extra>",
        ))
        style_figure(fig, height=380)
        fig.update_yaxes(title="Number of advisories", range=[0, max(counts.max() * 1.18, 1)])
        fig.update_xaxes(title="Severity level")
        show_chart(fig, "vbars")

    with right:
        section_title("Share of advisories", "Percentage of the selection per severity level.")
        fig = go.Figure(go.Pie(
            labels=[s.capitalize() for s in SEVERITY_ORDER],
            values=counts.values,
            marker=dict(colors=[SEVERITY_COLORS[s] for s in SEVERITY_ORDER], line=dict(color=COLOR_BG, width=2)),
            hole=0.62,
            sort=False,                      # keep the order critical -> low
            texttemplate="%{percent:.1%}",
            textposition="outside",
            textfont=dict(color=COLOR_TEXT, size=13),
            hovertemplate="<b>%{label}</b><br>Advisories: %{value:,}<br>Share: %{percent:.1%}<extra></extra>",
        ))
        style_figure(fig, height=380)
        fig.update_layout(
            legend=dict(orientation="h", yanchor="top", y=-0.02, xanchor="center", x=0.5),
            margin=dict(l=30, r=30, t=30, b=10),
            annotations=[dict(text=f"<b>{total:,}</b><br>advisories", x=0.5, y=0.5, showarrow=False,
                              font=dict(size=15, color=COLOR_TEXT))],
        )
        show_chart(fig, "pie")

    # Comparison table
    section_title("Severity comparison", "Advisory count, share and average CVSS score for each level.")
    average_cvss = df.groupby("severity")["cvss_score"].mean().reindex(SEVERITY_ORDER)
    table = pd.DataFrame({
        "Severity": [s.capitalize() for s in SEVERITY_ORDER],
        "Advisories": counts.values,
        "Share (%)": shares.round(1).values,
        "Average CVSS": average_cvss.round(2).values,
    })
    show_table(table, column_config={
        "Advisories": st.column_config.NumberColumn(format="%d"),
        "Share (%)": st.column_config.NumberColumn(format="%.1f"),
        "Average CVSS": st.column_config.NumberColumn(format="%.2f"),
    })

    top = counts.idxmax()
    urgent = int(counts[["critical", "high"]].sum())
    st.markdown(
        f"**Key observations**\n"
        f"- **{top.capitalize()}** is the most common level ({counts[top]:,} advisories, {shares[top]:.1f}%).\n"
        f"- Critical and high together: **{urgent:,}** advisories ({urgent / total * 100:.1f}%), the group that normally needs urgent patching.\n"
        f"- Critical ({shares['critical']:.1f}%) and low ({shares['low']:.1f}%) are the smallest groups in this selection."
    )
    st.caption("Severity is GitHub's classification (it follows the CVSS score). Counts describe advisories, "
               "not exploitation or the number of affected users.")


# =====================================================================
# PAGE: ECOSYSTEM
# =====================================================================
def exploded_ecosystems(df):
    """
    One row per (advisory, ecosystem). An advisory that affects several ecosystems is counted once
    under each of them. Ecosystems that are not selected in the sidebar filter are left out.
    """
    rows = (df[["ghsa_id", "severity", "cvss_score", "ecosystem_list"]]
            .explode("ecosystem_list").rename(columns={"ecosystem_list": "ecosystem"})
            .dropna(subset=["ecosystem"]).reset_index(drop=True))      # explode repeats index labels
    selected = set(st.session_state.get("f_ecosystem", []))
    return rows[rows["ecosystem"].isin(selected)] if selected else rows


def page_ecosystem(df, full_df):
    page_header("Ecosystem Analytics", "Which package ecosystems are affected, and how severe the advisories are in each.")

    eco = exploded_ecosystems(df)
    counts = eco["ecosystem"].value_counts()
    n_multi = int((df["ecosystem_list"].map(len) > 1).sum())

    section_title("Advisories per ecosystem",
                  "An advisory that affects several ecosystems is counted once under each of them.")
    fig = go.Figure(go.Bar(
        x=counts.values, y=counts.index, orientation="h", marker_color=gradient_colors(counts.values),
        text=[f"{c:,} ({c / len(df) * 100:.1f}%)" for c in counts.values], textposition="outside",
        customdata=counts.values / len(df) * 100,
        hovertemplate="<b>%{y}</b><br>Advisories: %{x:,}<br>Share of selection: %{customdata:.1f}%<extra></extra>",
    ))
    style_figure(fig, height=max(300, 34 * len(counts) + 90))
    fig.update_yaxes(autorange="reversed", title="Ecosystem", gridcolor="rgba(0,0,0,0)")
    fig.update_xaxes(title="Number of advisories", range=[0, counts.max() * 1.22])
    show_chart(fig, "hbars")

    # ---- Severity mix inside the larger ecosystems -------------------
    section_title("Severity mix per ecosystem",
                  "Share of each severity level inside an ecosystem. Small ecosystems give unstable percentages, "
                  "so only larger ones are shown.")
    # The slider maximum follows the data (largest ecosystem), and the saved value is kept inside the range.
    max_size = int(max(counts.max(), 2))
    st.session_state.setdefault("eco_min", 40)
    st.session_state["eco_min"] = int(min(max(st.session_state["eco_min"], 1), max_size))
    min_size = st.slider("Minimum advisories per ecosystem", min_value=1, max_value=max_size, key="eco_min")
    big = counts[counts >= min_size].index
    if len(big) == 0:
        st.info(f"No ecosystem has at least {min_size} advisories in the current selection. Lower the minimum above.")
        crosstab = pd.DataFrame()
    else:
        crosstab = (pd.crosstab(eco["ecosystem"], eco["severity"])
                    .reindex(index=big, columns=SEVERITY_ORDER, fill_value=0))
        percent = crosstab.div(crosstab.sum(axis=1), axis=0) * 100
        labels = [f"{name}  (n={int(crosstab.loc[name].sum())})" for name in percent.index]
        fig = go.Figure()
        for severity in SEVERITY_ORDER:
            fig.add_trace(go.Bar(
                y=labels, x=percent[severity], orientation="h", name=severity.capitalize(),
                marker=dict(color=SEVERITY_COLORS[severity], line=dict(color=COLOR_BG, width=1)),
                customdata=crosstab[severity],
                text=[f"{v:.0f}%" if v >= 5 else "" for v in percent[severity]],
                textposition="inside", insidetextanchor="middle",
                textfont=dict(color="black" if severity == "medium" else "white"),
                hovertemplate=f"<b>%{{y}}</b><br>{severity.capitalize()}: %{{customdata:,}} advisories "
                              "(%{x:.1f}%)<extra></extra>",
            ))
        style_figure(fig, height=max(320, 52 * len(labels) + 120))
        fig.update_layout(barmode="stack", legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, traceorder="normal"))
        fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)")
        fig.update_xaxes(title="Share of the ecosystem's advisories (%)", range=[0, 100])
        show_chart(fig, "hbars")

    # ---- Comparison table -------------------------------------------
    section_title("Ecosystem comparison", "Counts by severity and average CVSS score for every ecosystem.")
    severity_table = pd.crosstab(eco["ecosystem"], eco["severity"]).reindex(columns=SEVERITY_ORDER, fill_value=0)
    table = pd.DataFrame({
        "Ecosystem": counts.index,
        "Advisories": counts.values,
        "Share (%)": (counts.values / len(df) * 100).round(1),
    })
    for severity in SEVERITY_ORDER:
        table[severity.capitalize()] = severity_table[severity].reindex(counts.index).values
    table["Average CVSS"] = eco.groupby("ecosystem")["cvss_score"].mean().reindex(counts.index).round(2).values
    show_table(table, height=35 * (len(table) + 1) + 3, column_config={
        "Share (%)": st.column_config.NumberColumn(format="%.1f"),
        "Average CVSS": st.column_config.NumberColumn(format="%.2f"),
    })

    # ---- Observations -----------------------------------------------
    top3 = list(counts.index[:3])
    lines = [f"**Key observations**",
             f"- Largest ecosystems: **{', '.join(top3)}**; together they appear in "
             f"**{eco.loc[eco['ecosystem'].isin(top3), 'ghsa_id'].nunique() / len(df) * 100:.1f}%** of the selected advisories.",
             f"- **{n_multi}** selected advisories ({n_multi / len(df) * 100:.1f}%) affect more than one ecosystem."]
    if len(crosstab) >= 2:
        crit_share = (crosstab["critical"] / crosstab.sum(axis=1) * 100)
        high_share = (crosstab["high"] / crosstab.sum(axis=1) * 100)
        lines.append(f"- Among the ecosystems shown above, **{crit_share.idxmax()}** has the highest critical share "
                     f"({crit_share.max():.1f}%) and **{high_share.idxmax()}** the highest high share ({high_share.max():.1f}%).")
    st.markdown("\n".join(lines))
    st.caption("Raw counts are not divided by the size or popularity of an ecosystem, so they show where advisories "
               "occur, not which ecosystem is less secure.")


# =====================================================================
# PAGE: CVSS
# =====================================================================
def page_cvss(df, full_df):
    page_header("CVSS Insights", "How CVSS scores are distributed and how they relate to the severity label.")

    scored = df.dropna(subset=["cvss_score"])
    if scored.empty:
        st.info("No advisory in the current selection has a CVSS score.")
        return

    scores = scored["cvss_score"]
    n_scored = len(scored)
    mean, median, std = scores.mean(), scores.median(), scores.std()

    # ---- KPI cards ----------------------------------------------------
    cards = st.columns(4)
    with cards[0]:
        kpi_card("Scored advisories", f"{n_scored:,}",
                 f"{n_scored / len(df) * 100:.1f}% of the selection", COLOR_ACCENT)
    with cards[1]:
        kpi_card("Mean score", f"{mean:.2f}", "average CVSS base score", SEVERITY_COLORS["high"])
    with cards[2]:
        kpi_card("Median score", f"{median:.2f}", f"std. deviation {std:.2f}" if pd.notna(std) else "", SEVERITY_COLORS["medium"])
    with cards[3]:
        kpi_card("Score range", f"{scores.min():.1f} \u2013 {scores.max():.1f}", "lowest to highest score", COLOR_ACCENT_2)
    st.write("")

    left, right = st.columns([3, 2], gap="large")

    # ---- Histogram ----------------------------------------------------
    with left:
        section_title("Distribution of CVSS scores",
                      "Advisories per 0.5-point score band. Colours follow the severity bands: low < 4, medium 4\u20136.9, high 7\u20138.9, critical 9+.")
        edges = np.arange(0, 10.5, 0.5)
        hist, _ = np.histogram(scores, bins=edges)          # same bins as the notebook
        ranges = [f"{a:.1f} \u2013 {b:.1f}" for a, b in zip(edges[:-1], edges[1:])]
        fig = go.Figure(go.Bar(
            x=edges[:-1] + 0.25, y=hist, width=0.46, customdata=ranges,
            marker_color=[SEVERITY_COLORS["low"] if a < 4 else SEVERITY_COLORS["medium"] if a < 7
                          else SEVERITY_COLORS["high"] if a < 9 else SEVERITY_COLORS["critical"] for a in edges[:-1]],
            hovertemplate="Score band: %{customdata}<br>Advisories: %{y:,}<extra></extra>",
        ))
        fig.add_vline(x=mean, line_dash="dash", line_color="#ffffff", line_width=2,
                      annotation_text=f"Mean {mean:.2f}", annotation_position="top left",
                      annotation_font_color="#ffffff")
        fig.add_vline(x=median, line_color=COLOR_ACCENT, line_width=2.5,
                      annotation_text=f"Median {median:.2f}", annotation_position="top right",
                      annotation_font_color=COLOR_ACCENT)
        style_figure(fig, height=400)
        fig.update_xaxes(title="CVSS base score (0.0 - 10.0)", range=[0, 10], tickvals=list(range(11)))
        fig.update_yaxes(title="Number of advisories", range=[0, max(hist.max() * 1.2, 1)])
        show_chart(fig, "vbars")

    # ---- Box plot by severity ----------------------------------------
    with right:
        section_title("CVSS score by severity level", "Spread of scores inside each severity level.")
        fig = go.Figure()
        for severity in SEVERITY_ORDER:
            values = scored.loc[scored["severity"] == severity, "cvss_score"]
            if values.empty:
                continue
            fig.add_trace(go.Box(
                y=values, name=f"{severity.capitalize()}<br>n={len(values)}",
                marker_color=SEVERITY_COLORS[severity], line_color=SEVERITY_COLORS[severity],
                hovertemplate="%{y:.1f}<extra>" + severity.capitalize() + "</extra>",
            ))
        style_figure(fig, height=400)
        fig.update_layout(showlegend=False)
        fig.update_yaxes(title="CVSS base score", range=[0, 10.5])
        fig.update_xaxes(title="Severity level")
        show_chart(fig, "box")

    # ---- Statistics tables --------------------------------------------
    table_left, table_right = st.columns(2, gap="large")
    with table_left:
        section_title("CVSS score by severity level")
        by_severity = (scored.groupby("severity")["cvss_score"].agg(["count", "min", "median", "mean", "max"])
                       .reindex(SEVERITY_ORDER).dropna(how="all").reset_index())
        by_severity.columns = ["Severity", "Advisories", "Min", "Median", "Mean", "Max"]
        by_severity["Severity"] = by_severity["Severity"].str.capitalize()
        show_table(by_severity.round(2), column_config={
            "Advisories": st.column_config.NumberColumn(format="%d"),
            **{c: st.column_config.NumberColumn(format="%.2f") for c in ("Min", "Median", "Mean", "Max")},
        })
    with table_right:
        section_title("CVSS score by scoring version")
        by_version = scored.groupby("cvss_version")["cvss_score"].agg(["count", "mean", "median"]).reset_index()
        by_version.columns = ["CVSS version", "Advisories", "Mean", "Median"]
        show_table(by_version.round(2), column_config={
            "Advisories": st.column_config.NumberColumn(format="%d"),
            "Mean": st.column_config.NumberColumn(format="%.2f"),
            "Median": st.column_config.NumberColumn(format="%.2f"),
        })

    # ---- Observations (all numbers come from the selected data) ---------
    lines = ["**Key observations**",
             f"- Scores cover **{scores.min():.1f} \u2013 {scores.max():.1f}** with mean **{mean:.2f}** and median **{median:.2f}**"
             + (" (a tail of low scores pulls the mean below the median)." if median > mean else ".")]
    share_5_to_9 = scores.between(5.0, 9.0).mean() * 100
    lines.append(f"- **{share_5_to_9:.1f}%** of the scored advisories lie between 5.0 and 9.0.")

    ordered = [s for s in ["low", "medium", "high", "critical"] if s in set(scored["severity"])]
    if len(ordered) >= 2:
        bands = scored.groupby("severity")["cvss_score"].agg(["min", "max"]).reindex(ordered)
        separate = all(bands.loc[a, "max"] < bands.loc[b, "min"] for a, b in zip(ordered[:-1], ordered[1:]))
        lines.append("- Severity levels occupy **separate, non-overlapping score bands**: "
                     f"{'yes' if separate else 'no (in this selection)'}. The severity label is the CVSS score put into categories.")
    versions = scored.groupby("cvss_version")["cvss_score"].mean()
    if {"3.x", "4.0"} <= set(versions.index):
        lines.append(f"- Mean score is {versions['4.0']:.2f} for advisories scored with CVSS 4.0 and "
                     f"{versions['3.x']:.2f} for those scored with CVSS 3.x.")
    st.markdown("\n".join(lines))
    st.caption(f"{len(df) - n_scored} advisories in the selection have no CVSS score and are excluded (never counted as 0). "
               "CVSS v3 and v4 are different scoring systems; the groups contain different advisories, so the "
               "version comparison does not prove that v4 rates the same vulnerability higher.")


# =====================================================================
# PAGE: CWE
# =====================================================================
def exploded_cwe(df):
    """One row per (advisory, CWE). Every CWE of a multi-CWE advisory is counted once for that advisory."""
    rows = (df[["ghsa_id", "severity", "cvss_score", "cwe_list"]]
            .explode("cwe_list").rename(columns={"cwe_list": "cwe"})
            .dropna(subset=["cwe"]).drop_duplicates(["ghsa_id", "cwe"]).reset_index(drop=True))
    return rows[rows["cwe"] != ""].reset_index(drop=True)


def cwe_label(cwe_id):
    """'CWE-400  Uncontrolled Resource Consumption' (just the id if the name is not known)."""
    name = CWE_NAMES.get(cwe_id, "")
    return f"{cwe_id}  {name}".strip()


def page_cwe(df, full_df):
    page_header("CWE Analysis", "Which types of weakness (CWE) appear most often in the selected advisories.")

    cwe = exploded_cwe(df)
    if cwe.empty:
        st.info("No advisory in the current selection has CWE information.")
        return

    counts = cwe["cwe"].value_counts()
    n_with_cwe = int((df["cwe_list"].map(len) > 0).sum())
    n_multi = int((df["cwe_list"].map(len) > 1).sum())

    # ---- KPI cards -------------------------------------------------
    cards = st.columns(4)
    with cards[0]:
        kpi_card("Advisories with CWE", f"{n_with_cwe:,}", f"{n_with_cwe / len(df) * 100:.1f}% of the selection", COLOR_ACCENT)
    with cards[1]:
        kpi_card("Distinct CWEs", f"{counts.size:,}", f"{len(cwe):,} CWE tags in total", COLOR_ACCENT_2)
    with cards[2]:
        kpi_card("Most frequent CWE", counts.index[0],
                 f"{counts.iloc[0]:,} advisories \u00b7 {CWE_NAMES.get(counts.index[0], 'name not listed')}", SEVERITY_COLORS["high"])
    with cards[3]:
        kpi_card("With several CWEs", f"{n_multi:,}", f"{n_multi / n_with_cwe * 100:.1f}% of advisories with a CWE", SEVERITY_COLORS["medium"])
    st.write("")

    # ---- How many CWEs to show --------------------------------------
    max_n = int(max(min(25, counts.size), 2))
    st.session_state.setdefault("cwe_top_n", 10)
    st.session_state["cwe_top_n"] = int(min(max(st.session_state["cwe_top_n"], 1), max_n))
    top_n = st.slider("Number of CWEs to show", min_value=1, max_value=max_n, key="cwe_top_n")
    top = counts.head(top_n)

    left, right = st.columns([3, 2], gap="large")

    # ---- Top CWEs, split by severity --------------------------------
    with left:
        section_title(f"Top {len(top)} most frequent weaknesses",
                      "Number of advisories per CWE, split by severity level.")
        by_severity = pd.crosstab(cwe["cwe"], cwe["severity"]).reindex(index=top.index, columns=SEVERITY_ORDER, fill_value=0)
        labels = [cwe_label(c) for c in top.index]
        fig = go.Figure()
        for severity in SEVERITY_ORDER:
            fig.add_trace(go.Bar(
                y=labels, x=by_severity[severity], orientation="h", name=severity.capitalize(),
                marker=dict(color=SEVERITY_COLORS[severity], line=dict(color=COLOR_BG, width=1)),
                hovertemplate=f"<b>%{{y}}</b><br>{severity.capitalize()}: %{{x:,}} advisories<extra></extra>",
            ))
        # invisible trace that only writes the total at the end of each bar
        fig.add_trace(go.Scatter(
            x=top.values, y=labels, mode="text", text=[f"{v:,}" for v in top.values],
            textposition="middle right", showlegend=False, hoverinfo="skip", textfont=dict(color=COLOR_TEXT),
        ))
        style_figure(fig, height=max(340, 38 * len(top) + 130))
        fig.update_layout(barmode="stack", legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, traceorder="normal"))
        fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)")
        fig.update_xaxes(title="Number of advisories", range=[0, top.max() * 1.12])
        show_chart(fig, "hbars")

    # ---- Distribution (treemap): top CWEs and the long tail ----------
    with right:
        section_title("CWE distribution", "Tile size = number of advisories. The grey tile groups all other CWEs.")
        shown = counts.head(15)
        names = list(shown.index)
        values = [int(v) for v in shown.values]
        colors = [blend_colors("#0ea5e9", "#7c3aed", i / max(len(shown) - 1, 1)) for i in range(len(shown))]
        details = [CWE_NAMES.get(c, "") for c in shown.index]
        rest = counts.iloc[15:]
        if len(rest):
            names.append(f"Other ({len(rest)} CWEs)")
            values.append(int(rest.sum()))
            colors.append(COLOR_MIXED)
            details.append("All remaining weakness types")
        fig = go.Figure(go.Treemap(
            labels=names, parents=[""] * len(names), values=values, customdata=details,
            marker=dict(colors=colors, line=dict(color=COLOR_BG, width=2)),
            texttemplate="<b>%{label}</b><br>%{value:,}", textfont=dict(color="white"),
            hovertemplate="<b>%{label}</b><br>%{customdata}<br>CWE tags: %{value:,}<br>Share: %{percentRoot:.1%}<extra></extra>",
            tiling=dict(pad=2),
        ))
        style_figure(fig, height=max(340, 38 * len(top) + 130))
        show_chart(fig, "tree")

    # ---- Full table -------------------------------------------------
    section_title("All weaknesses", "Every CWE in the selection with its severity counts and average CVSS score.")
    all_severity = pd.crosstab(cwe["cwe"], cwe["severity"]).reindex(index=counts.index, columns=SEVERITY_ORDER, fill_value=0)
    table = pd.DataFrame({
        "CWE": counts.index,
        "Name": [CWE_NAMES.get(c, "") for c in counts.index],
        "Advisories": counts.values,
        "Share (%)": (counts.values / n_with_cwe * 100).round(1),
    })
    for severity in SEVERITY_ORDER:
        table[severity.capitalize()] = all_severity[severity].values
    table["Average CVSS"] = cwe.groupby("cwe")["cvss_score"].mean().reindex(counts.index).round(2).values
    show_table(table, height=360, column_config={
        "Share (%)": st.column_config.NumberColumn(format="%.1f", help="Percentage of advisories that have a CWE"),
        "Average CVSS": st.column_config.NumberColumn(format="%.2f"),
    })

    # ---- Observations (all numbers come from the selected data) --------
    lines = ["**Key observations**",
             f"- **{counts.index[0]}** ({CWE_NAMES.get(counts.index[0], 'name not listed')}) is the most frequent weakness: "
             f"**{counts.iloc[0]:,}** advisories ({counts.iloc[0] / n_with_cwe * 100:.1f}% of advisories with a CWE)."]
    dos = cwe[cwe["cwe"].isin(DOS_CWES)].drop_duplicates("ghsa_id")
    if len(dos):
        lines.append(f"- Resource-exhaustion weaknesses ({', '.join(c.replace('CWE-', '') for c in DOS_CWES)}) appear in **{len(dos):,}** advisories "
                     f"({len(dos) / n_with_cwe * 100:.1f}%); **{dos['severity'].isin(['high', 'medium']).mean() * 100:.1f}%** of them are high or medium "
                     f"and **{int((dos['severity'] == 'critical').sum())}** are critical.")
    injection = cwe[cwe["cwe"].isin(INJECTION_CWES)].drop_duplicates("ghsa_id")
    if len(injection):
        lines.append(f"- Code or OS command injection (CWE-94 / CWE-78) is critical in **{(injection['severity'] == 'critical').mean() * 100:.1f}%** of cases, "
                     f"compared with {(df['severity'] == 'critical').mean() * 100:.1f}% for all advisories in the selection.")
    critical_top = cwe.loc[cwe["severity"] == "critical", "cwe"].value_counts().head(2)
    if len(critical_top):
        lines.append("- Most common weaknesses among critical advisories: "
                     + ", ".join(f"**{c}** ({CWE_NAMES.get(c, 'name not listed')}, {n})" for c, n in critical_top.items()) + ".")
    lines.append(f"- The long tail is large: {counts.size} distinct CWEs occur, and the top 10 cover "
                 f"{counts.head(10).sum() / len(cwe) * 100:.1f}% of all CWE tags.")
    st.markdown("\n".join(lines))
    st.caption("An advisory with several CWEs is counted under each of them, so percentages do not add up to 100%. "
               "CWE labels are assigned by advisory authors; names come from the public MITRE CWE list.")


# =====================================================================
# PAGE: TIMELINE
# =====================================================================
def page_timeline(df, full_df):
    page_header("Timeline Analysis", "When the selected advisories were published (UTC dates).")

    published_day = df["published_at"].dt.tz_convert("UTC").dt.tz_localize(None).dt.normalize()
    daily = daily_series(df)
    n_days = len(daily)
    active_days = int((daily > 0).sum())
    peak_day = daily.idxmax()
    weekday_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    weekday_totals = published_day.dt.day_of_week.value_counts().reindex(range(7), fill_value=0)
    weekday_share = weekday_totals.iloc[:5].sum() / weekday_totals.sum() * 100
    weekend_total = int(weekday_totals.iloc[5:].sum())

    # ---- KPI cards -------------------------------------------------
    cards = st.columns(4)
    with cards[0]:
        kpi_card("Days covered", f"{n_days}", f"{active_days} {'day' if active_days == 1 else 'days'} with at least one advisory", COLOR_ACCENT)
    with cards[1]:
        kpi_card("Average per day", f"{daily.mean():.1f}", "advisories per calendar day", COLOR_ACCENT_2)
    with cards[2]:
        kpi_card("Busiest day", f"{daily.max():,}", f"{peak_day:%a, %d %b %Y}", SEVERITY_COLORS["high"])
    with cards[3]:
        kpi_card("Published Mon\u2013Fri", f"{weekday_share:.1f}%", f"{weekend_total} on weekends", SEVERITY_COLORS["medium"])
    st.write("")

    left, right = st.columns([3, 2], gap="large")

    # ---- Daily chart -----------------------------------------------
    with left:
        section_title("Advisories published per day", "Bars = daily count (grey = weekend). Line = trailing 7-day average.")
        is_weekend = daily.index.day_of_week >= 5
        fig = go.Figure()
        for label, mask, color in (("Weekday", ~is_weekend, COLOR_ACCENT), ("Weekend", is_weekend, COLOR_MIXED)):
            fig.add_trace(go.Bar(
                x=daily.index[mask], y=daily.values[mask], name=label, marker_color=color,
                hovertemplate="%{x|%a, %d %b %Y}<br>Advisories: %{y:,}<extra></extra>",
            ))
        if n_days >= 7:
            rolling = daily.rolling(window=7, min_periods=7).mean()
            fig.add_trace(go.Scatter(
                x=rolling.index, y=rolling.values, mode="lines", name="7-day average",
                line=dict(color=COLOR_ACCENT_2, width=3),
                hovertemplate="%{x|%d %b %Y}<br>7-day average: %{y:.1f}<extra></extra>",
            ))
        fig.add_annotation(x=peak_day, y=daily.max(), text=f"Peak: {daily.max()}", showarrow=True, arrowhead=2,
                           arrowcolor=COLOR_MUTED, font=dict(color=COLOR_TEXT), ax=45, ay=-10)
        style_figure(fig, height=400)
        fig.update_layout(barmode="overlay", legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0))
        fig.update_xaxes(title="Publication date (UTC)")
        fig.update_yaxes(title="Number of advisories", range=[0, daily.max() * 1.15])
        show_chart(fig, "vbars")

    # ---- Weekday chart ---------------------------------------------
    with right:
        section_title("Total by weekday", "Which days of the week advisories are published on.")
        fig = go.Figure(go.Bar(
            x=weekday_names, y=weekday_totals.values,
            marker_color=[color if i < 5 else COLOR_MIXED for i, color in enumerate(gradient_colors(weekday_totals.values))],
            text=[f"{v:,}" for v in weekday_totals.values], textposition="outside",
            hovertemplate="<b>%{x}</b><br>Advisories: %{y:,}<extra></extra>",
        ))
        style_figure(fig, height=400)
        fig.update_xaxes(title="Day of week")
        fig.update_yaxes(title="Number of advisories", range=[0, max(weekday_totals.max() * 1.15, 1)])
        show_chart(fig, "vbars")

    # ---- Monthly summary ---------------------------------------------
    section_title("Monthly view",
                  "The first and last months are only partly covered by the data, so compare advisories per covered day, not totals.")
    month = published_day.dt.to_period("M")
    monthly = published_day.groupby(month).agg(first_day="min", last_day="max")
    monthly["advisories"] = month.value_counts().sort_index()
    monthly["days_covered"] = (monthly["last_day"] - monthly["first_day"]).dt.days + 1
    monthly["per_day"] = (monthly["advisories"] / monthly["days_covered"]).round(1)
    monthly["month_length"] = monthly.index.map(lambda period: period.days_in_month)

    chart_col, table_col = st.columns([2, 3], gap="large")
    with chart_col:
        month_names = [f"{period.strftime('%b %Y')}<br>{covered} of {length} days"
                       for period, covered, length in zip(monthly.index, monthly["days_covered"], monthly["month_length"])]
        fig = go.Figure(go.Bar(
            x=month_names, y=monthly["per_day"], marker_color=[COLOR_ACCENT_2, COLOR_VIOLET, COLOR_ACCENT][: len(month_names)] if len(month_names) <= 3 else COLOR_ACCENT_2,
            text=[f"{v:.1f}" for v in monthly["per_day"]], textposition="outside",
            customdata=monthly[["advisories", "days_covered"]].to_numpy(),
            hovertemplate="<b>%{x}</b><br>Per covered day: %{y:.1f}<br>Advisories: %{customdata[0]:,}<br>Days covered: %{customdata[1]}<extra></extra>",
        ))
        style_figure(fig, height=320)
        fig.update_yaxes(title="Advisories per covered day", range=[0, max(monthly["per_day"].max() * 1.2, 1)])
        fig.update_xaxes(title="Month")
        show_chart(fig, "vbars")
    with table_col:
        table = pd.DataFrame({
            "Month": [period.strftime("%B %Y") for period in monthly.index],
            "Dates in data": [f"{a:%d %b} \u2013 {b:%d %b}" for a, b in zip(monthly["first_day"], monthly["last_day"])],
            "Advisories": monthly["advisories"].values,
            "Days in data": [f"{c} of {n}" for c, n in zip(monthly["days_covered"], monthly["month_length"])],
            "Per covered day": monthly["per_day"].values,
        })
        show_table(table, height=35 * (len(table) + 1) + 3, column_config={
            "Per covered day": st.column_config.NumberColumn(format="%.1f"),
        })

    # ---- Observations --------------------------------------------------
    peak_rows = df[published_day == peak_day]
    peak_eco = peak_rows["ecosystem"].value_counts()
    peak_pkg = peak_rows["package_name"].value_counts()
    zero_days = daily[daily == 0]
    zero_weekend = int((zero_days.index.day_of_week >= 5).sum())
    lines = ["**Key observations**",
             f"- Advisories were published on **{active_days} of {n_days}** calendar days; the average is **{daily.mean():.1f}** per day.",
             f"- **{weekday_share:.1f}%** were published Monday to Friday; **{weekend_total}** appeared on a weekend. "
             f"{weekday_names[int(weekday_totals.idxmax())]} is the busiest weekday.",
             f"- The busiest day is **{peak_day:%d %b %Y}** with **{daily.max():,}** advisories; on that day **{peak_eco.index[0]}** accounts for "
             f"{peak_eco.iloc[0]:,} advisories and the most frequent package is **{peak_pkg.index[0]}** ({peak_pkg.iloc[0]})."]
    if len(zero_days):
        lines.append(f"- Of the {len(zero_days)} days without any advisory, {zero_weekend} were weekend days.")
    st.markdown("\n".join(lines))
    st.caption(f"The data covers only {n_days} days: it is the latest set of reviewed advisories, not a sample of history. "
               "It can show the weekly rhythm and bursts, but it cannot show long-term growth, seasonality or yearly trends.")


# =====================================================================
# PAGE: PACKAGES
# =====================================================================
def package_pairs(df):
    """
    One row per (advisory, package). The ecosystem is only filled in when the advisory affects exactly
    one ecosystem; otherwise the data does not say which package belongs to which ecosystem.
    """
    rows = df[["ghsa_id", "severity", "cvss_score", "package_list", "ecosystem_list"]].copy()
    rows["single_ecosystem"] = rows["ecosystem_list"].map(lambda items: items[0] if len(items) == 1 else None)
    rows = (rows.explode("package_list").rename(columns={"package_list": "package"})
            .dropna(subset=["package"]).drop_duplicates(["ghsa_id", "package"]).reset_index(drop=True))
    return rows[rows["package"] != ""].reset_index(drop=True)


def shorten(text, limit=18):
    """Cut long names for KPI cards."""
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def page_packages(df, full_df):
    page_header("Package Insights", "Which packages are affected most often. Each package is counted once per advisory.")

    pairs = package_pairs(df)
    if pairs.empty:
        st.info("No package information in the current selection.")
        return

    counts = pairs["package"].value_counts()
    n_unique = counts.size
    single = int((counts == 1).sum())
    top10_share = counts.head(10).sum() / len(pairs) * 100

    # Ecosystem of each package: the most common ecosystem among its single-ecosystem advisories
    known = pairs.dropna(subset=["single_ecosystem"])
    package_ecosystem = known.groupby("package")["single_ecosystem"].agg(lambda s: s.value_counts().index[0])
    package_ecosystem = package_ecosystem.reindex(counts.index).fillna("Multiple / unknown")

    # ---- KPI cards -------------------------------------------------
    cards = st.columns(4)
    with cards[0]:
        kpi_card("Distinct packages", f"{n_unique:,}", f"in {len(df):,} advisories", COLOR_ACCENT)
    with cards[1]:
        kpi_card("Most affected package", shorten(counts.index[0]), f"{counts.iloc[0]:,} advisories \u00b7 {counts.index[0]}", COLOR_ACCENT_2)
    with cards[2]:
        kpi_card("Packages with 1 advisory", f"{single / n_unique * 100:.1f}%", f"{single:,} of {n_unique:,} packages", SEVERITY_COLORS["medium"])
    with cards[3]:
        kpi_card("Top 10 share", f"{top10_share:.1f}%", "of all package-advisory pairs", SEVERITY_COLORS["high"])
    st.write("")

    # ---- Top packages -----------------------------------------------
    max_n = int(max(min(25, n_unique), 2))
    st.session_state.setdefault("pkg_top_n", 10)
    st.session_state["pkg_top_n"] = int(min(max(st.session_state["pkg_top_n"], 1), max_n))
    top_n = st.slider("Number of packages to show", min_value=1, max_value=max_n, key="pkg_top_n")
    top = counts.head(top_n)

    left, right = st.columns([3, 2], gap="large")
    with left:
        section_title(f"Top {len(top)} most affected packages", "Number of advisories per package, coloured by ecosystem.")
        ecosystems = [e for e in package_ecosystem.loc[top.index].unique()]
        order = {name: i for i, name in enumerate(known["single_ecosystem"].value_counts().index)}
        fig = go.Figure()
        for ecosystem in ecosystems:
            names = [p for p in top.index if package_ecosystem[p] == ecosystem]
            color = COLOR_MIXED if ecosystem == "Multiple / unknown" else ECOSYSTEM_COLORS[order.get(ecosystem, 0) % len(ECOSYSTEM_COLORS)]
            fig.add_trace(go.Bar(
                y=names, x=[top[p] for p in names], orientation="h", name=ecosystem, marker_color=color,
                text=[f"{top[p]:,}" for p in names], textposition="outside",
                hovertemplate="<b>%{y}</b><br>Advisories: %{x:,}<br>Ecosystem: " + ecosystem + "<extra></extra>",
            ))
        style_figure(fig, height=max(340, 36 * len(top) + 130))
        fig.update_layout(barmode="overlay", legend=dict(title="Ecosystem", orientation="h", yanchor="bottom", y=1.02, x=0))
        fig.update_yaxes(categoryorder="array", categoryarray=list(top.index), autorange="reversed", gridcolor="rgba(0,0,0,0)")
        fig.update_xaxes(title="Number of advisories", range=[0, top.max() * 1.15])
        show_chart(fig, "hbars")

    # ---- Ecosystem / package comparison ------------------------------
    with right:
        section_title("Ecosystem and package comparison", "Advisories compared with distinct packages per ecosystem.")
        per_ecosystem = known.groupby("single_ecosystem").agg(advisories=("ghsa_id", "nunique"), packages=("package", "nunique"))
        per_ecosystem = per_ecosystem.sort_values("advisories", ascending=False)
        fig = go.Figure()
        fig.add_trace(go.Bar(y=per_ecosystem.index, x=per_ecosystem["advisories"], orientation="h", name="Advisories",
                             marker_color=COLOR_ACCENT, hovertemplate="<b>%{y}</b><br>Advisories: %{x:,}<extra></extra>"))
        fig.add_trace(go.Bar(y=per_ecosystem.index, x=per_ecosystem["packages"], orientation="h", name="Distinct packages",
                             marker_color=COLOR_ACCENT_2, hovertemplate="<b>%{y}</b><br>Distinct packages: %{x:,}<extra></extra>"))
        style_figure(fig, height=max(340, 36 * len(top) + 130))
        fig.update_layout(barmode="group", legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0))
        fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)")
        fig.update_xaxes(title="Count")
        show_chart(fig, "hbars")

    excluded = pairs.loc[pairs["single_ecosystem"].isna(), "ghsa_id"].nunique()
    if excluded:
        st.caption(f"{excluded} advisories that affect several ecosystems are left out of the ecosystem comparison, because the data "
                   "does not say which package belongs to which ecosystem.")

    # ---- Ecosystem table -----------------------------------------------
    section_title("Ecosystem summary")
    top_package = known.groupby("single_ecosystem")["package"].agg(lambda s: s.value_counts().index[0])
    summary = per_ecosystem.assign(
        per_package=(per_ecosystem["advisories"] / per_ecosystem["packages"]).round(2),
        top_package=top_package.reindex(per_ecosystem.index),
    ).reset_index()
    summary.columns = ["Ecosystem", "Advisories", "Distinct packages", "Advisories per package", "Most affected package"]
    show_table(summary, height=35 * (len(summary) + 1) + 3, column_config={
        "Advisories per package": st.column_config.NumberColumn(format="%.2f"),
    })

    # ---- All packages (collapsed) ----------------------------------------
    with st.expander(f"Show all {n_unique:,} packages"):
        by_severity = pd.crosstab(pairs["package"], pairs["severity"]).reindex(index=counts.index, columns=SEVERITY_ORDER, fill_value=0)
        table = pd.DataFrame({"Package": counts.index, "Ecosystem": package_ecosystem.values, "Advisories": counts.values})
        for severity in SEVERITY_ORDER:
            table[severity.capitalize()] = by_severity[severity].values
        table["Average CVSS"] = pairs.groupby("package")["cvss_score"].mean().reindex(counts.index).round(2).values
        show_table(table, height=400, column_config={"Average CVSS": st.column_config.NumberColumn(format="%.2f")})

    # ---- Observations -----------------------------------------------------
    repeated = int((counts >= 5).sum())
    top3 = counts.head(3)
    lines = ["**Key observations**",
             f"- **{n_unique:,}** distinct packages appear in the {len(df):,} selected advisories.",
             "- Most affected: " + ", ".join(f"**{name}** ({n})" for name, n in top3.items()) + ".",
             f"- **{single / n_unique * 100:.1f}%** of the packages ({single:,}) have just one advisory; {repeated} packages have five or more.",
             f"- The ten most affected packages account for only **{top10_share:.1f}%** of all package-advisory pairs, "
             "so the advisories are spread over many packages." if top10_share < 30 else
             f"- The ten most affected packages account for **{top10_share:.1f}%** of all package-advisory pairs."]
    st.markdown("\n".join(lines))
    st.caption("A package name is not guaranteed to be unique across ecosystems. Counts say nothing about how popular a package is: "
               "one advisory in a package used by millions can matter more than ten advisories in an unused package.")


# =====================================================================
# PAGE: ADVISORY EXPLORER
# =====================================================================
SEARCH_COLUMNS = ["ghsa_id", "cve_id", "summary", "package_name", "ecosystem", "cwe_ids"]
HELPER_COLUMNS = ["published_date", "ecosystem_list", "package_list", "cwe_list"]    # not part of the exported CSV

SORT_CHOICES = ["Newest first", "Oldest first", "Highest CVSS", "Lowest CVSS", "Severity (critical first)", "Package A\u2013Z"]


def search_advisories(df, query):
    """
    Keep the advisories that contain EVERY word of the query (not case sensitive).
    The words are searched in the advisory id, CVE id, summary, package, ecosystem, CWE id and CWE name.
    """
    terms = query.lower().split()
    if not terms:
        return df
    cwe_names = df["cwe_list"].map(lambda ids: " ".join(CWE_NAMES.get(c, "") for c in ids))
    text = df[SEARCH_COLUMNS].fillna("").astype(str).agg(" ".join, axis=1).str.lower() + " " + cwe_names.str.lower()
    mask = pd.Series(True, index=df.index)
    for term in terms:
        mask &= text.str.contains(term, regex=False)
    return df[mask]


def sort_advisories(df, choice):
    """Sort the advisories; missing values (for example a missing CVSS score) always go last."""
    if choice == "Severity (critical first)":
        rank = df["severity"].map({name: i for i, name in enumerate(SEVERITY_ORDER)})
        return df.assign(_rank=rank).sort_values(["_rank", "published_at"], ascending=[True, False]).drop(columns="_rank")
    column, ascending = {
        "Newest first": ("published_at", False), "Oldest first": ("published_at", True),
        "Highest CVSS": ("cvss_score", False), "Lowest CVSS": ("cvss_score", True),
        "Package A\u2013Z": ("package_name", True),
    }[choice]
    return df.sort_values(column, ascending=ascending, na_position="last")


def explorer_table(df):
    """The columns shown in the explorer table (a clickable link opens the advisory on GitHub)."""
    return pd.DataFrame({
        "Advisory": "https://github.com/advisories/" + df["ghsa_id"].astype(str),
        "CVE": df["cve_id"].fillna("\u2014"),
        "Severity": df["severity"].str.capitalize(),
        "CVSS": df["cvss_score"],
        "Published": df["published_date"],
        "Ecosystem": df["ecosystem"],
        "Package": df["package_name"],
        "CWE": df["cwe_ids"].fillna("\u2014"),
        "Summary": df["summary"],
        "Withdrawn": df["is_withdrawn"],
    })


def export_csv(df):
    """The selected advisories as CSV bytes (UTF-8 with BOM, so Excel shows every character correctly)."""
    return df.drop(columns=HELPER_COLUMNS, errors="ignore").to_csv(index=False).encode("utf-8-sig")


def clear_search():
    st.session_state["ex_search"] = ""


def show_advisory_details(row):
    """A readable card with the most important fields of one advisory."""
    severity = row["severity"]
    color = SEVERITY_COLORS.get(severity, COLOR_MIXED)
    with st.container(border=True):
        st.markdown(
            f'<span class="pill" style="border-color:{color}; color:{color}; font-weight:700">{escape(severity.upper())}</span> '
            f'&nbsp;<b>{escape(row["ghsa_id"])}</b>' + (f' &nbsp;\u00b7&nbsp; {escape(row["cve_id"])}' if pd.notna(row["cve_id"]) else ""),
            unsafe_allow_html=True,
        )
        st.markdown(f"#### {row['summary']}")
        if row["is_withdrawn"]:
            st.warning("GitHub has withdrawn this advisory.")
        left, right = st.columns(2, gap="large")
        with left:
            score = f"{row['cvss_score']:.1f} (CVSS {row['cvss_version']})" if pd.notna(row["cvss_score"]) else "not available"
            st.markdown(f"**CVSS score:** {score}  \n"
                        f"**Published:** {row['published_at']:%d %b %Y, %H:%M} UTC  \n"
                        f"**Last updated:** {row['updated_at']:%d %b %Y, %H:%M} UTC")
        with right:
            cwe_text = ", ".join(f"{c} ({CWE_NAMES[c]})" if c in CWE_NAMES else c for c in row["cwe_list"]) or "not classified"
            st.markdown(f"**Ecosystem:** {', '.join(row['ecosystem_list'])}  \n"
                        f"**Package:** {', '.join(row['package_list'])}  \n"
                        f"**Weakness (CWE):** {cwe_text}")
        st.markdown(f"[Open this advisory on GitHub](https://github.com/advisories/{row['ghsa_id']})")


def page_explorer(df, full_df):
    page_header("Advisory Explorer",
                "Search the advisories that match the sidebar filters, sort them, open one, or download them as CSV.")

    # ---- Search controls ----------------------------------------------
    col_search, col_clear, col_sort = st.columns([4, 1, 2], gap="small", vertical_alignment="bottom")
    with col_search:
        query = st.text_input("Search", key="ex_search", placeholder="Advisory id, CVE id, package, ecosystem, CWE or any word in the summary")
    with col_clear:
        st.button("Clear", on_click=clear_search, width="stretch")
    with col_sort:
        sort_choice = st.selectbox("Sort by", SORT_CHOICES, key="ex_sort")
    include_withdrawn = st.checkbox("Include withdrawn advisories", value=True, key="ex_withdrawn")

    results = df if include_withdrawn else df[~df["is_withdrawn"]]
    results = sort_advisories(search_advisories(results, query), sort_choice)

    # ---- Summary cards ------------------------------------------------------
    if results.empty:
        st.info("No advisory matches your search. Check the spelling, use fewer words, or widen the sidebar filters.")
        return
    urgent = int(results["severity"].isin(["critical", "high"]).sum())
    scores = results["cvss_score"].dropna()
    cards = st.columns(4)
    with cards[0]:
        kpi_card("Matching advisories", f"{len(results):,}", f"{len(results) / len(df) * 100:.0f}% of the filtered advisories", COLOR_ACCENT)
    with cards[1]:
        kpi_card("Critical + high", f"{urgent:,}", f"{urgent / len(results) * 100:.1f}% of the results", SEVERITY_COLORS["critical"])
    with cards[2]:
        kpi_card("Distinct packages", f"{results['package_list'].explode().nunique():,}", "in the results", COLOR_ACCENT_2)
    with cards[3]:
        kpi_card("Average CVSS", f"{scores.mean():.2f}" if len(scores) else "n/a", f"{len(scores):,} scored", SEVERITY_COLORS["high"])
    st.write("")

    # ---- Table + download ---------------------------------------------------
    head_left, head_right = st.columns([4, 1], vertical_alignment="center")
    with head_left:
        section_title("Results", "Click a column header to sort. Click an advisory id to open it on GitHub.")
    with head_right:
        st.download_button(
            "Download CSV", data=export_csv(results), file_name=f"advisorylens_{len(results)}_advisories.csv",
            mime="text/csv", width="stretch", icon=":material/download:",
        )
    show_table(explorer_table(results), height=520, column_config={
        "Advisory": st.column_config.LinkColumn("Advisory", display_text=r"https://github.com/advisories/(.*)", width="medium"),
        "CVSS": st.column_config.NumberColumn(format="%.1f", width="small"),
        "Published": st.column_config.DateColumn(format="YYYY-MM-DD", width="small"),
        "Summary": st.column_config.TextColumn(width="large"),
        "Withdrawn": st.column_config.CheckboxColumn(width="small"),
    })
    st.caption(f"The CSV contains all {len(results):,} results above with every column of the database table.")

    # ---- One advisory in detail -----------------------------------------------
    section_title("Advisory details", "Choose an advisory from the results to read its main facts.")
    lookup = results.set_index("ghsa_id")
    chosen = st.selectbox(
        "Advisory", list(lookup.index), index=None, placeholder="Select or type an advisory id",
        format_func=lambda ghsa: f"{ghsa}  \u00b7  {lookup.loc[ghsa, 'package_name']}  \u00b7  {lookup.loc[ghsa, 'severity']}",
        label_visibility="collapsed",
    )
    if chosen:
        show_advisory_details(lookup.loc[chosen].to_dict() | {"ghsa_id": chosen})


# =====================================================================
# MAIN
# =====================================================================
def main():
    inject_css(animations=st.session_state.get("animations", True))
    full_df, kind, path = get_data()
    page, filtered = render_sidebar(full_df, kind, path)

    # Helpful empty state: no advisory matches the filters
    if filtered.empty:
        page_header(page, "No advisories match the current filters.")
        st.warning("No advisories match the selected filters. Widen the selection or press **Reset filters**.")
        return

    # Pages that only need the filtered data
    page_functions = {
        "Severity": page_severity, "Ecosystem": page_ecosystem, "CVSS": page_cvss,
        "CWE": page_cwe, "Timeline": page_timeline, "Packages": page_packages,
        "Advisory Explorer": page_explorer,
    }

    if page == "Overview":
        page_overview(filtered, full_df, kind, path)
    else:
        page_functions[page](filtered, full_df)


main()