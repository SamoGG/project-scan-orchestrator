# enrich/cve_enricher.py
import argparse
import json
import os
import time
import re
import requests
from typing import Dict, List, Tuple, Iterable


import psycopg2
from psycopg2.extras import execute_values

# ===== Config =================================================================
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100
EPSS_PAUSE_SEC = 0.5


# ===== Helpers =================================================================
def _connect(dsn: str):
    return psycopg2.connect(dsn)


def _clean_version(version: str | None) -> str | None:
    if not version:
        return None
    v = str(version).strip().lower()
    # Keep only the leading numeric dotted core, e.g. "2.2.34" from "2.2.34-1ubuntu1 (Unix)"
    m = re.match(r"(\d+(?:\.\d+)+)", v)
    return m.group(1) if m else v


def _safe_key(product: str | None, version: str | None) -> str | None:
    if not product or not version:
        return None
    p = str(product).strip().lower()
    v = _clean_version(version)
    if not v:
        return None
    return f"{p}:{v}"


def _fetch_services(conn) -> List[Tuple[int, str | None, str | None]]:
    cur = conn.cursor()
    cur.execute("SELECT id, product, version FROM services;")
    rows = cur.fetchall()
    cur.close()
    return rows


def _upsert_cves_for_service(
    cur,
    service_id: int,
    cves: Iterable[Dict],
):
    """
    Insert CVEs (cve_id, cvss, description) for given service.
    Requires a UNIQUE constraint on (service_id, cve_id).
    """
    if not cves:
        return
    execute_values(
        cur,
        """
        INSERT INTO vulnerabilities (service_id, cve_id, cvss, description)
        VALUES %s
        ON CONFLICT (service_id, cve_id) DO NOTHING;
        """,
        [
            (
                service_id,
                cve.get("cve_id"),
                cve.get("cvss"),
                cve.get("description"),
            )
            for cve in cves
            if cve.get("cve_id")
        ],
    )


def _collect_cves_needing_epss(conn, refresh: bool) -> List[str]:
    cur = conn.cursor()
    if refresh:
        cur.execute(
            "SELECT DISTINCT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL;"
        )
    else:
        cur.execute(
            "SELECT DISTINCT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL AND epss IS NULL;"
        )
    cves = [r[0] for r in cur.fetchall()]
    cur.close()
    return cves


def _load_epss_cache(path: str) -> Dict[str, Tuple[float, float]]:
    """
    Load local cache JSON and return {CVE: (epss, percentile)}.
    Accepts either [{"cve": "...", "epss": 0.123, "percentile": 87.3}, ...]
    or {"data": [{"cve": "...", "epss": 0.123, "percentile": 0.873}, ...]} (0..1 percentile).
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    out: Dict[str, Tuple[float, float]] = {}
    if isinstance(raw, list):
        seq = raw
    elif isinstance(raw, dict) and "data" in raw:
        seq = raw["data"]
    else:
        seq = []

    for it in seq:
        cve = it.get("cve")
        if not cve:
            continue
        epss = float(it.get("epss", 0.0) or 0.0)
        perc_raw = float(it.get("percentile", 0.0) or 0.0)
        percentile = perc_raw * 100.0 if perc_raw <= 1.0 else perc_raw
        out[cve] = (epss, percentile)
    return out


def _fetch_epss_online(cves: List[str]) -> Dict[str, Tuple[float, float]]:
    """
    Fetch EPSS from FIRST public API in batches.
    Returns {CVE: (epss, percentile)} with percentile 0..100.
    """

    out: Dict[str, Tuple[float, float]] = {}
    for i in range(0, len(cves), EPSS_BATCH):
        chunk = cves[i : i + EPSS_BATCH]
        resp = requests.get(
            EPSS_API,
            params={"cve": ",".join(chunk)},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        for item in data:
            cve = item.get("cve")
            if not cve:
                continue
            try:
                epss = float(item.get("epss", 0.0) or 0.0)
            except (TypeError, ValueError):
                epss = 0.0
            try:
                perc_raw = float(item.get("percentile", 0.0) or 0.0)
            except (TypeError, ValueError):
                perc_raw = 0.0
            percentile = perc_raw * 100.0 if perc_raw <= 1.0 else perc_raw
            out[cve] = (epss, percentile)
        # be nice to the public API
        time.sleep(EPSS_PAUSE_SEC)
    return out


def _update_epss(conn, epss_map: Dict[str, Tuple[float, float]], refresh: bool) -> int:
    """
    Bulk update EPSS columns in vulnerabilities.
    If refresh=False, only fill rows where epss IS NULL.
    """
    if not epss_map:
        return 0

    rows = [(v[0], v[1], k) for k, v in epss_map.items()]  # (epss, percentile, cve)
    cur = conn.cursor()
    if refresh:
        sql = """
        UPDATE vulnerabilities v
        SET epss = data.epss, epss_percentile = data.epss_percentile
        FROM (VALUES %s) AS data(epss, epss_percentile, cve_id)
        WHERE v.cve_id = data.cve_id;
        """
    else:
        sql = """
        UPDATE vulnerabilities v
        SET epss = data.epss, epss_percentile = data.epss_percentile
        FROM (VALUES %s) AS data(epss, epss_percentile, cve_id)
        WHERE v.cve_id = data.cve_id AND v.epss IS NULL;
        """
    execute_values(cur, sql, rows)
    affected = cur.rowcount
    cur.close()
    conn.commit()
    return affected


# ===== Main enrichment steps ===================================================
def enrich_cve(dsn: str, cve_cache_path: str) -> int:
    """
    CVE enrichment from local cache (product:version -> [{cve_id, cvss, description}, ...]).
    Returns number of (attempted) CVE insert rows (not necessarily unique-new).
    """
    if not os.path.exists(cve_cache_path):
        raise FileNotFoundError(f"CVE cache not found: {cve_cache_path}")

    with open(cve_cache_path, "r", encoding="utf-8") as f:
        cve_cache_raw = json.load(f)

    cve_cache = {str(k).strip().lower(): v for k, v in cve_cache_raw.items()}

    conn = _connect(dsn)
    cur = conn.cursor()

    services = _fetch_services(conn)
    inserted = 0

    for service_id, product, version in services:
        key = _safe_key(product, version)
        if not key:
            continue
        cve_list = cve_cache.get(key, [])
        if not cve_list:
            continue
        _upsert_cves_for_service(cur, service_id, cve_list)
        inserted += len(cve_list)

    conn.commit()
    cur.close()
    conn.close()
    print(f"CVE: processed {len(services)} services, attempted inserts: {inserted}")
    return inserted


def enrich_epss(dsn: str, use_cache: str | None = None, refresh: bool = False) -> int:
    """
    EPSS enrichment for CVEs present in vulnerabilities table.
    - If use_cache is provided, load EPSS from that JSON file.
    - Else, fetch EPSS online from FIRST API in batches.
    Returns number of updated rows.
    """
    conn = _connect(dsn)
    cves = _collect_cves_needing_epss(conn, refresh=refresh)

    if not cves:
        print("EPSS: nothing to enrich.")
        conn.close()
        return 0

    if use_cache:
        print(f"EPSS: loading cache from {use_cache}")
        epss_map = _load_epss_cache(use_cache)
        epss_map = {c: epss_map[c] for c in cves if c in epss_map}
    else:
        print(f"EPSS: fetching online for {len(cves)} CVEs ...")
        epss_map = _fetch_epss_online(cves)

    updated = _update_epss(conn, epss_map, refresh=refresh)
    conn.close()
    print(f"EPSS: updated rows: {updated}")
    return updated


# ===== CLI ====================================================================
def main():
    p = argparse.ArgumentParser(
        description="Enrich CVEs from local cache and (optionally) EPSS from cache or FIRST API."
    )
    p.add_argument(
        "--db",
        required=True,
        help="Postgres DSN, e.g. postgresql://user:pass@db:5432/scans",
    )
    p.add_argument(
        "--cve-cache",
        default="enrich/cve_cache.json",
        help="Local CVE cache JSON path.",
    )
    p.add_argument(
        "--with-epss",
        action="store_true",
        help="Also enrich EPSS after CVE enrichment.",
    )
    p.add_argument(
        "--epss-cache",
        default=None,
        help="Optional local EPSS cache JSON (offline mode).",
    )
    p.add_argument(
        "--refresh-epss", action="store_true", help="Re-fill EPSS even if already set."
    )
    args = p.parse_args()

    # 1) CVE enrichment (always)
    enrich_cve(args.db, args.cve_cache)

    # 2) EPSS enrichment
    if args.with_epss:
        enrich_epss(args.db, use_cache=args.epss_cache, refresh=args.refresh_epss)


if __name__ == "__main__":
    main()
