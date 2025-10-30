import json
import psycopg2


def enrich_cve(db_url, cache_path="enrich/cve_cache.json"):
    with open(cache_path) as f:
        cache = json.load(f)

    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute("SELECT id, product, version FROM services;")
    services = cur.fetchall()

    for service_id, product, version in services:
        key = f"{product}:{version}"
        if key in cache:
            for cve in cache[key]:
                cur.execute(
                    """
                INSERT INTO vulnerabilities (service_id, cve_id, cvss, description)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (service_id, cve_id) DO NOTHING;
                """,
                    (service_id, cve["cve_id"], cve["cvss"], cve["description"]),
                )

    conn.commit()
    conn.close()
    print("CVE enrichment completed")


if __name__ == "__main__":
    import os

    db_url = os.getenv("DATABASE_URL", "postgresql://user:pass@db:5432/scans")
    enrich_cve(db_url)
