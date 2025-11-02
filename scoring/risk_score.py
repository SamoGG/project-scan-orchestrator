import argparse
import os
from typing import Optional, Tuple

import psycopg2
from psycopg2.extras import DictCursor


# ====== Pomocné funkcie pre výpočet skóre ====================================

# mapovanie dôležitosti aktíva a úrovne exploitácie
CRIT_MAP = {"low": 20, "medium": 50, "high": 100}
MATURITY_MAP = {"none": 0, "poc": 50, "public": 100}


def normalize_cvss(cvss: Optional[float]) -> float:
    """Normalizuje CVSS hodnotu z rozsahu 0–10 na rozsah 0–100."""
    try:
        v = float(cvss)
    except (TypeError, ValueError):
        return 0.0
    v = max(0.0, min(10.0, v))
    return v * 10.0  # 0–10 -> 0–100


def score_from_criticality(crit: Optional[str]) -> float:
    """Vráti skóre podľa kritickosti aktíva (low/medium/high)."""
    if not isinstance(crit, str):
        return CRIT_MAP["medium"]
    return CRIT_MAP.get(crit.lower(), CRIT_MAP["medium"])


def score_from_exposure(is_public: Optional[bool]) -> float:
    """Ak je služba verejne dostupná, vráti 100, inak 0."""
    return 100.0 if bool(is_public) else 0.0


def score_from_maturity(exploitability: Optional[str]) -> float:
    """Preloží textovú úroveň exploitovateľnosti na číselné skóre."""
    if not isinstance(exploitability, str):
        return MATURITY_MAP["none"]
    key = exploitability.strip().lower()
    # akceptuje viaceré varianty z bežných CVE feedov
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
) -> float:
    """Spočíta výsledné rizikové skóre podľa váhového modelu."""
    cvss_norm = normalize_cvss(cvss)
    asset_score = score_from_criticality(asset_crit)
    exposure_score = score_from_exposure(is_public)
    maturity_score = score_from_maturity(exploitability)

    risk = (
        0.50 * cvss_norm
        + 0.25 * asset_score
        + 0.15 * exposure_score
        + 0.10 * maturity_score
    )
    # zaokrúhlenie na dve desatinné miesta
    return round(risk, 2)


# ====== Pomocné funkcie pre prácu s DB =======================================


def table_has_column(cur, table: str, column: str) -> bool:
    """Zistí, či má daná tabuľka daný stĺpec (používa sa na kontrolu schémy)."""
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
    """Vytvorí chýbajúce stĺpce, ktoré skript potrebuje. Ak už existujú, nič nerobí."""
    # vulnerabilities.risk_score – výsledné rizikové skóre
    cur.execute(
        "ALTER TABLE IF EXISTS vulnerabilities ADD COLUMN IF NOT EXISTS risk_score NUMERIC"
    )
    # pomocné agregované stĺpce pre max riziko
    cur.execute(
        "ALTER TABLE IF EXISTS services ADD COLUMN IF NOT EXISTS risk_max NUMERIC"
    )
    cur.execute("ALTER TABLE IF EXISTS hosts ADD COLUMN IF NOT EXISTS risk_max NUMERIC")
    # voliteľné meta stĺpce na tabuľke hosts:
    # asset_criticality (TEXT) – dôležitosť aktíva: low/medium/high
    # is_public (BOOLEAN) – či je služba verejne dostupná
    # nevytvárajú sa automaticky, aby sa nenarušila vlastná schéma používateľa


def load_batch(
    cur,
    recompute: bool,
    where_sql: Optional[str],
    limit: Optional[int],
    have_asset_cols: Tuple[bool, bool],
):
    """Načíta dávku záznamov (vulnerabilities + väzby na host/service) pre spracovanie."""
    has_crit, has_public = have_asset_cols

    # dynamicky doplní stĺpce podľa dostupných meta údajov
    crit_col = "h.asset_criticality" if has_crit else "NULL::text AS asset_criticality"
    pub_col = "h.is_public" if has_public else "FALSE::boolean AS is_public"

    base = f"""
        SELECT
            v.id AS vuln_id,
            v.service_id,
            s.host_id,
            v.cvss,
            v.exploitability,
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
    """Zapíše vypočítané skóre späť do tabuľky vulnerabilities."""
    cur.execute(
        "UPDATE vulnerabilities SET risk_score = %s WHERE id = %s",
        (score, vuln_id),
    )


def aggregate_service_host(cur):
    """Agreguje najvyššie riziko z úrovne vulnerabilities do services a hosts."""
    # služby – max skóre z priradených zraniteľností
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
    # hosty – max skóre zo služieb
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


# ====== Hlavná funkcia / CLI rozhranie =======================================


def main():
    ap = argparse.ArgumentParser(
        description="Vypočíta rizikové skóre pre zraniteľnosti a (voliteľne) ho agreguje do services/hosts."
    )
    ap.add_argument(
        "--db",
        default=os.environ.get("DATABASE_URL"),
        help="PostgreSQL DSN, napr. postgresql://user:pass@localhost:5432/scans (alebo použi premennú DATABASE_URL)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Vypočíta skóre, ale nezapíše zmeny do DB",
    )
    ap.add_argument(
        "--recompute",
        action="store_true",
        help="Prepočíta všetky záznamy aj tie, ktoré už majú risk_score",
    )
    ap.add_argument(
        "--aggregate",
        action="store_true",
        help="Po výpočte vypočíta aj max riziko pre služby a hosty",
    )
    ap.add_argument("--limit", type=int, default=None, help="Spracuje len N záznamov")
    ap.add_argument(
        "--where",
        type=str,
        default=None,
        help="Doplnková SQL podmienka (napr. \"v.cve_id LIKE 'CVE-2021-%'\")",
    )
    args = ap.parse_args()

    if not args.db:
        raise SystemExit("CHYBA: Uveď --db alebo nastav premennú DATABASE_URL")

    with psycopg2.connect(args.db) as conn:
        conn.autocommit = False
        with conn.cursor(cursor_factory=DictCursor) as cur:
            # zabezpečí existenciu potrebných stĺpcov
            ensure_schema(cur)

            # zistí, či existujú meta stĺpce na tabuľke hosts
            has_crit = table_has_column(cur, "hosts", "asset_criticality")
            has_public = table_has_column(cur, "hosts", "is_public")

            # načíta dávku záznamov
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
                )
                if not args.dry_run:
                    update_vuln_score(cur, row["vuln_id"], risk)
                processed += 1

            # ak je zapnutá agregácia, spočíta aj max hodnoty
            if args.aggregate:
                if not args.dry_run:
                    aggregate_service_host(cur)

            if args.dry_run:
                conn.rollback()
                print(
                    f"[DRY-RUN] Vypočítaných {processed} zraniteľností. Žiadne zmeny nezapísané."
                )
            else:
                conn.commit()
                print(f"[OK] Aktualizovaných {processed} záznamov s risk_score.")
                if args.aggregate:
                    print("[OK] Agregované do services.risk_max a hosts.risk_max.")


if __name__ == "__main__":
    main()
