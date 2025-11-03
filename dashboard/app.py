import os
import glob
import time
import subprocess
from pathlib import Path
import re
import shlex
import signal

import streamlit as st
import psycopg2
from psycopg2.extras import RealDictCursor


# ===== Defaults===========================
DEFAULT_DB_DSN = os.getenv("DB_DSN", "postgresql://user:pass@db:5432/scans")
JOBS_DIR = os.getenv("JOBS_DIR", "jobs")
RAW_DIR = os.getenv("RAW_DIR", "data/raw")
CVE_CACHE = os.getenv("CVE_CACHE", "enrich/cve_cache.json")


# ===== Helpery ================================================================
def _run_and_stream(cmd: list[str]) -> int:
    """Run a command and stream stdout/stderr to the UI (returns returncode)."""
    st.write(f"```bash\n$ {' '.join(cmd)}\n```")
    placeholder = st.empty()
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    lines = []
    for line in proc.stdout:
        lines.append(line.rstrip("\n"))
        # zvýšime reaktivitu a nezahlcujeme UI
        if len(lines) % 5 == 0:
            placeholder.text("\n".join(lines[-500:]))
    proc.wait()
    placeholder.text("\n".join(lines[-500:]))
    st.success(f"Process finished with code {proc.returncode}.")
    return proc.returncode


def _db_conn(dsn: str):
    return psycopg2.connect(dsn, cursor_factory=RealDictCursor)


def _ensure_dirs():
    Path(RAW_DIR).mkdir(parents=True, exist_ok=True)


def _safe_delete_globs(base_dir: str, patterns: list[str]) -> dict:
    """
    Deletes files matching patterns inside base_dir (recursively).
    Safety: only deletes files that are inside base_dir (no escape).
    Returns counts per pattern and total.
    """
    base = Path(base_dir).resolve()
    deleted = {p: 0 for p in patterns}
    total = 0
    for pat in patterns:
        for fp in glob.glob(str(base / pat), recursive=True):
            p = Path(fp).resolve()
            try:
                p.relative_to(base)
            except ValueError:
                continue
            if p.is_file():
                try:
                    os.remove(p)
                    deleted[pat] += 1
                    total += 1
                except Exception:
                    pass
    deleted["total"] = total
    return deleted


def _truncate_db(dsn: str):
    with _db_conn(dsn) as conn, conn.cursor() as cur:
        cur.execute("TRUNCATE vulnerabilities RESTART IDENTITY CASCADE;")
        cur.execute("TRUNCATE services RESTART IDENTITY CASCADE;")
        cur.execute("TRUNCATE hosts RESTART IDENTITY CASCADE;")
        conn.commit()


# ===== UI ====================================================================
st.set_page_config(page_title="BIT Orchestrator Dashboard", layout="wide")

st.title("BIT Orchestrator — Dashboard")
st.caption("Scan → Parse → CVE Enrich → Risk Scoring → Prehľad")

# Bočný panel: voľby a nastavenia
with st.sidebar:
    st.header("Settings")
    db_dsn = st.text_input("PostgreSQL DSN", value=DEFAULT_DB_DSN)
    jobs = sorted(glob.glob(f"{JOBS_DIR}/*.yaml")) + sorted(
        glob.glob(f"{JOBS_DIR}/*.yml")
    )
    job_file = st.selectbox("Job file (YAML)", options=jobs, index=0 if jobs else None)
    raw_glob = st.text_input("Raw XML glob for parser", value=f"{RAW_DIR}/**/*.xml")
    cve_cache_path = st.text_input("CVE cache JSON", value=CVE_CACHE)
    st.markdown("---")
    st.header("Maintenance / Reset")

    # Delete RAW XML/LOGs
    st.caption("Delete RAW XML files and logs")
    confirm_rm = st.checkbox(
        "I understand that this will permanently delete RAW files.",
        value=False,
        key="confirm_rm",
    )
    if st.button(
        "Delete RAW XML & logs", use_container_width=True, disabled=not confirm_rm
    ):
        _ensure_dirs()
        patterns = [
            "**/*.xml",
            "**/*.nmap",
            "**/*.gnmap",
            "**/*.log",
        ]
        stats = _safe_delete_globs(RAW_DIR, patterns)
        st.success(f"Deleted {stats.get('total', 0)} files from {RAW_DIR}.")
        with st.expander("Details"):
            st.write(stats)

    st.markdown("")
    # Clear DB
    st.caption("Delete database tables (hosts, services, vulnerabilities).")
    confirm_db = st.checkbox(
        "I understand that this will permanently delete all data from the DB.",
        value=False,
        key="confirm_db",
    )
    if st.button("Delete database", use_container_width=True, disabled=not confirm_db):
        try:
            _truncate_db(db_dsn)
            st.success(
                "Database has been deleted (hosts, services, vulnerabilities) and identities have been reset."
            )
        except Exception as e:
            st.error(f"Deleting DB failed: {e}")
    st.markdown("---")
    st.caption("Tip: In Docker Compose use the service name `db`.")

# Hlavný panel: tlačidlá
_ensure_dirs()
col1, col2, col3, col4 = st.columns(4)
with col1:
    if st.button(
        "▶Run Scan",
        use_container_width=True,
        type="primary",
        disabled=(job_file is None),
    ):
        cmd = ["python", "orchestrator/scan_orchestrator.py", job_file, db_dsn]
        rc = _run_and_stream(cmd)

with col2:
    if st.button("Parse Nmap XML", use_container_width=True):
        # Parser: python -m ingest.parse_nmap data/raw/... --db postgresql://...
        files = glob.glob(raw_glob, recursive=True)
        if not files:
            st.warning(f"No XML files found for pattern: {raw_glob}")
        else:
            cmd = ["python", "-m", "ingest.parse_nmap", raw_glob, db_dsn]
            rc = _run_and_stream(cmd)
with col3:
    if st.button("CVE Enrich", use_container_width=True):
        # --- načítaj stav pred enrichmentom
        try:
            with _db_conn(db_dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM vulnerabilities;")
                pre_total = cur.fetchone()["n"]
                cur.execute("SELECT COUNT(DISTINCT cve_id) AS n FROM vulnerabilities;")
                pre_distinct_cves = cur.fetchone()["n"]
                cur.execute(
                    "SELECT COUNT(DISTINCT service_id) AS n FROM vulnerabilities;"
                )
                pre_services = cur.fetchone()["n"]
        except Exception as e:
            st.error(f"DB pre-check failed: {e}")
            pre_total = pre_distinct_cves = pre_services = None

        # --- spusti enrichment
        cmd = ["python", "-m", "enrich.cve_enricher", db_dsn]
        rc = _run_and_stream(cmd)

        # --- načítaj stav po enrichmentu a zobraz delta
        try:
            with _db_conn(db_dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM vulnerabilities;")
                post_total = cur.fetchone()["n"]
                cur.execute("SELECT COUNT(DISTINCT cve_id) AS n FROM vulnerabilities;")
                post_distinct_cves = cur.fetchone()["n"]
                cur.execute(
                    "SELECT COUNT(DISTINCT service_id) AS n FROM vulnerabilities;"
                )
                post_services = cur.fetchone()["n"]

            if None not in (pre_total, pre_distinct_cves, pre_services):
                colA, colB, colC = st.columns(3)
                colA.metric(
                    "Vulnerabilities (rows)", post_total, post_total - pre_total
                )
                colB.metric(
                    "Distinct CVEs",
                    post_distinct_cves,
                    post_distinct_cves - pre_distinct_cves,
                )
                colC.metric(
                    "Affected services", post_services, post_services - pre_services
                )
            else:
                st.info(
                    "CVE enrichment completed. (Summary metrics unavailable due to pre-check error.)"
                )
        except Exception as e:
            st.error(f"DB post-check failed: {e}")
with col4:
    if st.button("Risk Scoring", use_container_width=True):
        # Scoring: python -m scoring.risk_score --db ...
        cmd = ["python", "-m", "scoring.risk_score", "--db", db_dsn]
        rc = _run_and_stream(cmd)

st.markdown("---")

# ===== Tabuľky a prehľady ====================================================
tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["Hosts", "Services", "Vulnerabilities", "Top Risks", "Scan Jobs"]
)

with tab1:
    try:
        with _db_conn(db_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT h.id, h.ip, COALESCE(MAX(v.risk_score), 0) AS max_risk,
                       COUNT(DISTINCT s.id) AS services
                FROM hosts h
                LEFT JOIN services s ON s.host_id = h.id
                LEFT JOIN vulnerabilities v ON v.service_id = s.id
                GROUP BY h.id, h.ip
                ORDER BY max_risk DESC, h.ip ASC
                LIMIT 200;
            """
            )
            rows = cur.fetchall()
            st.dataframe(rows, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"DB query failed: {e}")

with tab2:
    try:
        with _db_conn(db_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.id, h.ip, s.port, s.proto, s.product, s.version, s.banner,
                       COALESCE(MAX(v.risk_score), 0) AS risk
                FROM services s
                JOIN hosts h ON h.id = s.host_id
                LEFT JOIN vulnerabilities v ON v.service_id = s.id
                GROUP BY s.id, h.ip, s.port, s.proto, s.product, s.version, s.banner
                ORDER BY risk DESC, h.ip, s.port
                LIMIT 500;
            """
            )
            rows = cur.fetchall()
            st.dataframe(rows, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"DB query failed: {e}")

with tab3:
    st.subheader("All vulnerabilities")
    qcol1, qcol2, qcol3, qcol4 = st.columns([2, 1, 1, 1])
    with qcol1:
        q_text = st.text_input("Filter (IP / product / CVE / banner contains)", "")
    with qcol2:
        min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0, 0.1)
    with qcol3:
        min_risk = st.slider("Min RiskScore", 0, 100, 0, 1)
    with qcol4:
        limit = st.number_input(
            "Limit", min_value=10, max_value=5000, value=500, step=10
        )

    conditions = []
    params = []

    if q_text:
        conditions.append(
            """(h.ip ILIKE %s OR COALESCE(s.product,'') ILIKE %s
                              OR COALESCE(v.cve_id,'') ILIKE %s OR COALESCE(s.banner,'') ILIKE %s)"""
        )
        like = f"%{q_text}%"
        params += [like, like, like, like]

    if min_cvss > 0:
        conditions.append("COALESCE(v.cvss,0) >= %s")
        params.append(min_cvss)

    if min_risk > 0:
        conditions.append("COALESCE(v.risk_score,0) >= %s")
        params.append(min_risk)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT v.id, h.ip, s.port, s.proto, s.product, s.version,
            v.cve_id, v.cvss, v.risk_score
        FROM vulnerabilities v
        JOIN services s ON s.id = v.service_id
        JOIN hosts h ON h.id = s.host_id
        {where}
        ORDER BY COALESCE(v.risk_score,0) DESC, COALESCE(v.cvss,0) DESC, v.id DESC
        LIMIT %s;
    """
    params.append(int(limit))

    try:
        import pandas as pd

        with _db_conn(db_dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
            if not df.empty:
                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇️ Download CSV", csv, "vulnerabilities.csv", "text/csv"
                )
    except Exception as e:
        st.error(f"Query failed: {e}")

    st.markdown("---")
    with st.expander("Check duplicates (debug)"):
        try:
            dup_sql = """
                SELECT service_id, cve_id, COUNT(*) AS cnt
                FROM vulnerabilities
                GROUP BY service_id, cve_id
                HAVING COUNT(*) > 1
                ORDER BY cnt DESC, service_id
                LIMIT 100;
            """
            with _db_conn(db_dsn) as conn, conn.cursor() as cur:
                cur.execute(dup_sql)
                dups = cur.fetchall()
                if dups:
                    st.warning("Duplicates found on (service_id, cve_id):")
                    st.dataframe(dups, use_container_width=True, hide_index=True)
                else:
                    st.success("No duplicates detected.")
        except Exception as e:
            st.error(f"Duplicate check failed: {e}")

with tab4:
    try:
        with _db_conn(db_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT h.ip, s.port, s.product, s.version, v.cve_id, v.cvss, v.risk_score
                FROM vulnerabilities v
                JOIN services s ON s.id = v.service_id
                JOIN hosts h ON h.id = s.host_id
                WHERE v.risk_score IS NOT NULL
                ORDER BY v.risk_score DESC
                LIMIT 50;
            """
            )
            rows = cur.fetchall()
            st.dataframe(rows, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"DB query failed: {e}")

with tab5:
    st.subheader("Scan Jobs history")
    try:
        with _db_conn(db_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, job_name,
                       started_at,
                       finished_at,
                       status,
                       config
                FROM scan_jobs
                ORDER BY started_at DESC
                LIMIT 100;
            """
            )
            rows = cur.fetchall()
            if not rows:
                st.info("No scan jobs recorded yet.")
            else:
                import pandas as pd

                df = pd.DataFrame(rows)
                st.dataframe(df, use_container_width=True, hide_index=True)

                # Optional: export as CSV or JSON
                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button("⬇️ Download CSV", csv, "scan_jobs.csv", "text/csv")

    except Exception as e:
        st.error(f"DB query failed: {e}")

st.markdown("—")
st.caption(
    "In the following order: Run Scan → Parse Nmap XML → CVE Enrich → Risk Scoring."
)
