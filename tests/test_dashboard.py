"""
Tests for the Streamlit dashboard (app.py) using Streamlit's built-in AppTest.

The tests run the real dashboard without a browser. They only READ database/advisories.db
(they never change it), and every expected number is calculated from the database itself,
so the tests keep working if the dataset is refreshed.

Run from the project root:
    python -m pytest tests/test_dashboard.py -v
"""

import io
from pathlib import Path
import re
import sqlite3

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent.parent
APP_FILE = ROOT / "app.py"
DB_FILE = ROOT / "database" / "advisories.db"

REQUIRED_COLUMNS = {"ghsa_id", "severity", "cvss_score", "published_at", "updated_at", "is_withdrawn",
                    "cwe_ids", "ecosystem", "package_name", "cve_id", "summary"}


def database_is_ready():
    """True when the database exists and was built by the current pipeline (all required columns exist)."""
    if not DB_FILE.exists():
        return False
    with sqlite3.connect(DB_FILE.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(advisories)")}
    return REQUIRED_COLUMNS <= columns


pytestmark = pytest.mark.skipif(
    not database_is_ready(),
    reason="database/advisories.db is missing or outdated: run  python pipeline.py  first",
)

PAGES = ["Overview", "Severity", "Ecosystem", "CVSS", "CWE", "Timeline", "Packages", "Advisory Explorer"]


def start_app():
    return AppTest.from_file(str(APP_FILE), default_timeout=120).run()


def kpi_values(app):
    """Read the KPI cards (label -> value text) that are drawn as HTML."""
    values = {}
    for element in app.markdown:
        for label, value in re.findall(r'kpi-label">([^<]+)</div><div class="kpi-value">([^<]+)<', element.value):
            values[label] = value
    return values


def database_scalar(sql):
    with sqlite3.connect(DB_FILE.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        return connection.execute(sql).fetchone()[0]


def load_app_functions():
    """Load the helper functions of app.py without starting the dashboard."""
    source = APP_FILE.read_text(encoding="utf-8").rstrip()
    assert source.endswith("main()")
    namespace = {"__name__": "dashboard_under_test", "__file__": str(APP_FILE)}
    exec(compile(source[: -len("main()")], str(APP_FILE), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("page", PAGES)
def test_every_page_loads_without_errors(page):
    app = start_app()
    app.radio[0].set_value(page).run()
    assert not app.exception, f"{page} page raised an exception"


def test_overview_cards_match_database():
    total = database_scalar("SELECT COUNT(*) FROM advisories")
    critical = database_scalar("SELECT COUNT(*) FROM advisories WHERE severity = 'critical'")
    cards = kpi_values(start_app())
    assert cards["Total advisories"] == f"{total:,}"
    assert cards["Critical advisories"] == f"{critical:,}"


def test_severity_filter_changes_the_numbers_and_reset_restores_them():
    total = database_scalar("SELECT COUNT(*) FROM advisories")
    critical = database_scalar("SELECT COUNT(*) FROM advisories WHERE severity='critical'")
    app = start_app()
    app.multiselect(key="f_severity").set_value(["critical"]).run()
    assert kpi_values(app)["Total advisories"] == f"{critical:,}"
    app.button[0].click().run()                       # "Reset filters"
    assert kpi_values(app)["Total advisories"] == f"{total:,}"


def test_ecosystem_filter_counts_every_advisory_that_mentions_the_ecosystem():
    expected = database_scalar("SELECT COUNT(*) FROM advisories WHERE ecosystem LIKE '%npm%'")
    app = start_app()
    app.multiselect(key="f_ecosystem").set_value(["npm"]).run()
    assert kpi_values(app)["Total advisories"] == f"{expected:,}"


def test_empty_filter_shows_a_warning_instead_of_crashing():
    app = start_app()
    app.multiselect(key="f_severity").set_value([]).run()
    assert not app.exception
    assert app.warning, "an empty selection should show a helpful warning"


def test_explorer_search_and_empty_result_message():
    total = database_scalar("SELECT COUNT(*) FROM advisories")
    app = start_app()
    app.radio[0].set_value("Advisory Explorer").run()
    assert len(app.dataframe[0].value) == total       # no search -> every advisory
    app.text_input(key="ex_search").set_value("ghsa").run()
    assert len(app.dataframe[0].value) == total       # every id contains "ghsa" (not case sensitive)
    app.text_input(key="ex_search").set_value("zzzz-no-such-advisory").run()
    assert not app.exception
    assert app.info, "no match should show an information message"


def test_csv_export_contains_exactly_the_search_results():
    functions = load_app_functions()
    with sqlite3.connect(DB_FILE.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        raw = pd.read_sql_query("SELECT * FROM advisories", connection)
    advisories = functions["prepare_data"](raw)
    results = functions["search_advisories"](advisories, "npm")
    exported = pd.read_csv(io.BytesIO(functions["export_csv"](results)), encoding="utf-8-sig")
    assert len(exported) == len(results) > 0
    assert set(exported["ghsa_id"]) == set(results["ghsa_id"])
    assert "ecosystem_list" not in exported.columns   # helper columns are not exported


def test_animation_toggle_switches_the_animation_css_on_and_off():
    app = start_app()
    style_text = lambda: " ".join(element.value for element in app.markdown)
    assert "@keyframes growY" in style_text(), "animations should be on by default"
    app.toggle(key="animations").set_value(False).run()
    assert not app.exception
    assert "@keyframes growY" not in style_text(), "the toggle should remove the animation CSS"