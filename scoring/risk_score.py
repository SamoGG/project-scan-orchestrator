import argparse
import os
from typing import Optional, Tuple

import psycopg2
from psycopg2.extras import DictCursor


# ====== Helper functions for score computation ====================================

# Mapping of asset criticality and exploit maturity
CRIT_MAP = {"low": 20, "medium": 50, "high": 100}
MATURITY_MAP = {"none": 0, "poc": 50, "public": 100}


def normalize_cvss(cvss: Optional[float]) -> float:
    """Normalizes CVSS value from range 0–10 to 0–100."""
    try:
        v = float(cvss)
    except (TypeError, ValueError):
        return 0.0
    v = max(0.0, min(10.0, v))
    return v * 10.0  # 0–10 -> 0–100


def score_from_criticality(crit: Optional[str]) -> float:
    """Returns score based on asset criticality (low/medium/high)."""
    if not isinstance(crit, str):
        return CRIT_MAP["medium"]
    return CRIT_MAP.get(crit.lower(), CRIT_MAP["medium"])


def score_from_exposure(is_public: Optional[bool]) -> float:
    """If the service is publicly accessible, returns 100, otherwise 0."""
    return 100.0 if bool(is_public) else 0.0


def score_from_maturity(exploitability: Optional[str]) -> float:
    """Translates textual exploit maturity level into a numeric score."""
    if not isinstance(exploitability, str):
        return MATURITY_MAP["none"]
    key = exploitability.strip().lower()
    # accepts multiple variants from common CVE feeds
    if key in ("public", "weaponized", "exploited"):
        return MATURITY_MAP["public"]
    if key in ("poc", "proof_of_concept", "proof-of-concept"):
        return MATURITY_MAP["poc"]
    return MATURITY_MAP["none"]


def compute_risk(
    cvss: Optional[float],
    asset_crit: Optional[str],
    is_public: Optional[bool],
    exploitability: Optional[str],
    epss: Optional[float] = None,
) -> float:
    """Computes the final risk score according to the weighted model."""
    cvss_norm = normalize_cvss(cvss)
    asset_score = score_from_criticality(asset_crit)
    exposure_score = score_from_exposure(is_public)
    maturity_score = score_from_maturity(exploitability)
    epss_norm = float(epss or 0.0) * 100.0

    risk = (
        0.45 * cvss_norm
        + 0.25 * asset_score
        + 0.10 * exposure_score
        + 0.10 * maturity_score
        + 0.10 * epss_norm
    )
    return round(risk, 2)


# ====== Helper functions for working with the DB =======================================


def table_has_column(cur, table: str, column: str) -> bool:
    """Checks whether a given table has a given column (used to verify schema)."""
    cur.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = %s
          AND column_name = %s
        """,
        (table, column),
    )
    return cur.fetchone() is not None


def ensure_schema(cur):
    """Creates missing columns required by this script. If they already exist, does nothing."""
    # vulnerabilities.risk_score – the resulting risk score
    cur.execute(
        "ALTER TABLE IF EXISTS vulnerabilities ADD COLUMN IF NOT EXISTS risk_score NUMERIC"
    )
    # helper aggregated columns for max risk
    cur.execute(
        "ALTER TABLE IF EXISTS services ADD COLUMN IF NOT EXISTS risk_max NUMERIC"
    )
    cur.execute("ALTER TABLE IF EXISTS hosts ADD COLUMN IF NOT EXISTS risk_max NUMERIC")
    # optional meta columns on hosts table:
    # asset_criticality (TEXT) – importance of the asset: low/medium/high
    # is_public (BOOLEAN) – whether the service is publicly accessible
    # not created automatically to avoid altering user's own schema


def load_batch(
    cur,
    recompute: bool,
    where_sql: Optional[str],
    limit: Optional[int],
    have_asset_cols: Tuple[bool, bool],
):
    """Loads a batch of records (vulnerabilities + their host/service relations) for processing."""
    has_crit, has_public = have_asset_cols

    # dynamically adds columns based on available metadata
    crit_col = "h.asset_criticality" if has_crit else "NULL::text AS asset_criticality"
    pub_col = "h.is_public" if has_public else "FALSE::boolean AS is_public"

    base = f"""
        SELECT
            v.id AS vuln_id,
            v.service_id,
            s.host_id,
            v.cvss,
            v.exploitability,
            v.epss,
            {crit_col},
            {pub_col}
        FROM vulnerabilities v
        JOIN services s ON s.id = v.service_id
        JOIN hosts h ON h.id = s.host_id
    """

    filters = []
    if not recompute:
        filters.append("v.risk_score IS NULL")
    if where_sql:
        filters.append(f"({where_sql})")

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    limit_clause = f"LIMIT {int(limit)}" if limit else ""

    sql = f"{base} {where_clause} ORDER BY v.id {limit_clause};"
    cur.execute(sql)
    return cur.fetchall()


def update_vuln_score(cur, vuln_id: int, score: float):
    """Writes the calculated score back into the vulnerabilities table."""
    cur.execute(
        "UPDATE vulnerabilities SET risk_score = %s WHERE id = %s",
        (score, vuln_id),
    )


def aggregate_service_host(cur):
    """Aggregates the highest risk from vulnerabilities up to services and hosts."""
    # services – max score from associated vulnerabilities
    cur.execute(
        """
        UPDATE services s
        SET risk_max = sub.mx
        FROM (
          SELECT service_id, MAX(risk_score) AS mx
          FROM vulnerabilities
          WHERE risk_score IS NOT NULL
          GROUP BY service_id
        ) sub
        WHERE sub.service_id = s.id
        """
    )
    # hosts – max score from services
    cur.execute(
        """
        UPDATE hosts h
        SET risk_max = sub.mx
        FROM (
          SELECT host_id, MAX(risk_max) AS mx
          FROM services
          GROUP BY host_id
        ) sub
        WHERE sub.host_id = h.id
        """
    )


# ====== Main function / CLI interface =======================================


def main():
    ap = argparse.ArgumentParser(
        description="Computes risk scores for vulnerabilities and (optionally) aggregates them into services/hosts."
    )
    ap.add_argument(
        "--db",
        default=os.environ.get("DATABASE_URL"),
        help="PostgreSQL DSN, e.g. postgresql://user:pass@localhost:5432/scans (or use the DATABASE_URL environment variable)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute scores but do not write any changes to the DB",
    )
    ap.add_argument(
        "--recompute",
        action="store_true",
        help="Recalculate all records including those that already have risk_score",
    )
    ap.add_argument(
        "--aggregate",
        action="store_true",
        help="After computation, also compute max risk for services and hosts",
    )
    ap.add_argument("--limit", type=int, default=None, help="Process only N records")
    ap.add_argument(
        "--where",
        type=str,
        default=None,
        help="Additional SQL condition (e.g. \"v.cve_id LIKE 'CVE-2021-%'\")",
    )
    args = ap.parse_args()

    if not args.db:
        raise SystemExit(
            "ERROR: Specify --db or set the DATABASE_URL environment variable"
        )

    with psycopg2.connect(args.db) as conn:
        conn.autocommit = False
        with conn.cursor(cursor_factory=DictCursor) as cur:
            # ensure required columns exist
            ensure_schema(cur)

            # check if meta columns exist on hosts table
            has_crit = table_has_column(cur, "hosts", "asset_criticality")
            has_public = table_has_column(cur, "hosts", "is_public")

            # load a batch of records
            batch = load_batch(
                cur,
                recompute=args.recompute,
                where_sql=args.where,
                limit=args.limit,
                have_asset_cols=(has_crit, has_public),
            )

            processed = 0
            for row in batch:
                risk = compute_risk(
                    cvss=row["cvss"],
                    asset_crit=row["asset_criticality"] if has_crit else "medium",
                    is_public=row["is_public"] if has_public else False,
                    exploitability=row["exploitability"],
                    epss=row.get("epss"),
                )
                if not args.dry_run:
                    update_vuln_score(cur, row["vuln_id"], risk)
                processed += 1

            # If aggregation is enabled, compute max values
            if args.aggregate:
                if not args.dry_run:
                    aggregate_service_host(cur)

            if args.dry_run:
                conn.rollback()
                print(
                    f"[DRY-RUN] Computed {processed} vulnerabilities. No changes written."
                )
            else:
                conn.commit()
                print(f"[OK] Updated {processed} records with risk_score.")
                if args.aggregate:
                    print("[OK] Aggregated into services.risk_max and hosts.risk_max.")


if __name__ == "__main__":
    main()
