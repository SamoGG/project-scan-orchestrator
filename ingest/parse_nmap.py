import sys
from pathlib import Path
from glob import glob
import xmltodict
import psycopg2
from psycopg2.extras import execute_values


# ---------------------------------------------------------------
# Pomocné interné funkcie
# ---------------------------------------------------------------


def _ensure_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _pick_ip(address_node):
    """
    address_node môže byť dict alebo list(dict).
    Vyber IPv4 ak existuje, inak prvú dostupnú adresu.
    """
    addrs = _ensure_list(address_node)
    if not addrs:
        return None
    # dict s kľúčmi "@addr", "@addrtype"
    for a in addrs:
        if isinstance(a, dict) and a.get("@addrtype", "").lower() in ("ipv4", "ip"):
            return a.get("@addr")
    # fallback: prvá adresa
    first = addrs[0]
    return first.get("@addr") if isinstance(first, dict) else None


def _service_banner(svc):
    if not isinstance(svc, dict):
        return None
    parts = []
    if svc.get("@name"):
        parts.append(svc["@name"])
    if svc.get("@product"):
        parts.append(svc["@product"])
    if svc.get("@version"):
        parts.append(svc["@version"])
    if svc.get("@extrainfo"):
        parts.append(f"({svc['@extrainfo']})")
    return " ".join(parts) if parts else None


# ---------------------------------------------------------------
# Hlavná parsovacia funkcia
# ---------------------------------------------------------------


def parse_nmap_xml(file_path):
    """
    Vráti list dictov: {ip, port, proto, product, version, banner}
    Iba pre porty so stavom 'open'.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        xml = xmltodict.parse(f.read())

    results = []
    nmaprun = xml.get("nmaprun", {})
    hosts = _ensure_list(nmaprun.get("host"))

    for h in hosts:
        if not isinstance(h, dict):
            continue

        # preskoč hosty bez address
        ip = _pick_ip(h.get("address"))
        if not ip:
            continue

        ports_node = h.get("ports", {})
        ports = _ensure_list(ports_node.get("port"))

        for p in ports:
            if not isinstance(p, dict):
                continue

            # filtruj iba open porty
            st = p.get("state") or {}
            if isinstance(st, dict):
                if st.get("@state") != "open":
                    continue

            portid = p.get("@portid")
            proto = p.get("@protocol")

            svc = p.get("service", {}) if isinstance(p.get("service", {}), dict) else {}
            product = svc.get("@product")
            version = svc.get("@version")
            banner = _service_banner(svc)

            results.append(
                {
                    "ip": ip,
                    "port": int(portid) if portid is not None else None,
                    "proto": str(proto) if proto else None,
                    "product": product,
                    "version": version,
                    "banner": banner,
                }
            )

    return [r for r in results if r["port"] is not None and r["proto"]]


# ---------------------------------------------------------------
# Funkcia na uloženie dát do PostgreSQL
# ---------------------------------------------------------------


def upsert_into_db(records, conn_str):
    if not records:
        return

    conn = psycopg2.connect(conn_str)
    cur = conn.cursor()

    # 1) UPSERT hosts and RETURN ids in one go
    ips = sorted({r["ip"] for r in records})
    sql_hosts = """
        INSERT INTO hosts (ip, last_seen)
        VALUES %s
        ON CONFLICT (ip) DO UPDATE
          SET last_seen = EXCLUDED.last_seen
        RETURNING id, ip::text
    """
    execute_values(
        cur,
        sql_hosts,
        [(ip,) for ip in ips],
        template="(%s, now())",
    )
    rows = cur.fetchall()
    id_map = {ip: hid for (hid, ip) in rows}

    # 2) INSERT services with batch de-dupe
    svc_rows, seen = [], set()
    for r in records:
        hid = id_map.get(r["ip"])
        if hid is None:
            # ultra-safe fallback (shouldn't happen with RETURNING):
            cur.execute("SELECT id FROM hosts WHERE ip = %s::inet", (r["ip"],))
            row = cur.fetchone()
            if not row:
                # if still missing, skip this record
                continue
            hid = row[0]
            id_map[r["ip"]] = hid

        key = (hid, r["port"], r["proto"])
        if key in seen:
            continue
        seen.add(key)
        svc_rows.append(
            (hid, r["port"], r["proto"], r["product"], r["version"], r["banner"])
        )

    if svc_rows:
        execute_values(
            cur,
            """
            INSERT INTO services (host_id, port, proto, product, version, banner, first_seen, last_seen)
            VALUES %s
            ON CONFLICT (host_id, port, proto) DO UPDATE
              SET product = EXCLUDED.product,
                  version = EXCLUDED.version,
                  banner  = EXCLUDED.banner,
                  last_seen = now()
            """,
            svc_rows,
            template="(%s,%s,%s,%s,%s,%s, now(), now())",
        )

    conn.commit()
    cur.close()
    conn.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: docker compose run --rm parserp <glob-pattern> <postgres-url>")
        sys.exit(2)

    pattern = sys.argv[1]
    db_url = sys.argv[2]

    files = glob(pattern)
    if not files:
        print(f"[!] No files matched pattern: {pattern}")
        sys.exit(1)

    total = 0
    for xml_file in files:
        print(f"[+] Parsing {xml_file}")
        try:
            recs = parse_nmap_xml(xml_file)
            upsert_into_db(recs, db_url)
            total += len(recs)
            print(f"    -> {len(recs)} services ingested")
        except Exception as e:
            print(f"[!] Failed on {xml_file}: {e}")

    print(f"[✓] Done. Total services ingested: {total}")
