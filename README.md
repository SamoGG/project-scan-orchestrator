# Orchestrator a prioritizačný systém pre autorizované sieťové skenovanie

**Autor:** Samuel Gabriel Galgóci  
**Cieľ:** Vybudovať bezpečný, konfigurovateľný orchestrator, ktorý spúšťa autorizované sieťové skeny, 
normalizuje výsledky, obohacuje ich o CVE a hodnotí podľa rizika.

## Rýchly štart
```bash
git clone https://github.com/SamoGG/project-scan-orchestrator.git
cd project-orchestrator
```

```bash
docker-compose build
```

```bash
pip install -r requirements.txt
```

### Python venv
```bash
python -m venv .venv
source .venv/bin/activate    # on Linux/macOS
.venv\Scripts\activate       # on Windows PowerShell

pip install --upgrade pip
pip install -r requirements.txt
```

### Postup

Start/stop docker
```bash
docker compose up -d

docker compose stop
```

Pre oskenovanie hostov treba spustit orchestrator. Ten nám vytvorí xml a log súbory pre parsovanie.
```bash
docker compose exec orchestrator python orchestrator/scan_orchestrator.py jobs/internal_quickscan.yaml
```

Následne pustíme parser na ulozenie suborov do DB.
```bash
docker compose run --rm parser "/app/data/raw/internal_quickscan/*.xml" "postgresql://user:pass@db:5432/scans"
```

Pre kontrolu súborov v DB:
```bash
docker compose exec db psql -U user -d scans
```

Príklad querry:
```sql
-- akych hostov sme naskenovali
SELECT * FROM hosts ORDER BY id;

-- vypisanie vsetkych servisov pre hostov
SELECT h.ip, s.port, s.proto, s.product, s.version, s.banner,
       s.first_seen, s.last_seen
FROM hosts h
JOIN services s ON s.host_id = h.id
ORDER BY h.ip, s.port;

-- pocet servicov na hosta
SELECT h.ip, COUNT(*) AS svc_count
FROM hosts h
JOIN services s ON s.host_id = h.id
GROUP BY h.ip
ORDER BY svc_count DESC;

-- zaznam z poslednej hodiny
SELECT h.ip, s.port, s.proto, s.last_seen
FROM hosts h
JOIN services s ON s.host_id = h.id
WHERE s.last_seen > now() - interval '1 hour'
ORDER BY s.last_seen DESC;
```

Spustenie service enricheru, ktorý nám k servicom pridám CVE ak nejaké sú v cve_cache, ktoré sa zhodujú.
```bash
docker compose run --rm enricher
```

Kontrola výsledkov.

```bash
docker compose exec db psql -U user -d scans -c "SELECT service_id, cve_id, cvss FROM vulnerabilities ORDER BY service_id, cve_id;"
```

Spustenie risk scoringu pre dáta.
```bash
docker compose run --rm scorer
```


| Parameter     | Popis                                                            |
| ------------- | ---------------------------------------------------------------- |
| `--db`        | DSN na PostgreSQL (ak nie je nastavená premenná `DATABASE_URL`)  |
| `--dry-run`   | Vypočíta skóre, ale nezapíše ho do DB                            |
| `--recompute` | Prepočíta všetky záznamy, aj tie, ktoré už majú `risk_score`     |
| `--aggregate` | Po výpočte aktualizuje aj `services.risk_max` a `hosts.risk_max` |
| `--limit N`   | Spracuje len prvých *N* záznamov                                 |
| `--where`     | Voliteľný SQL filter (napr. `"v.cve_id LIKE 'CVE-2021-%'"`)      |

---

## Architektúra (zjednodušená)
```
[ Job Configs (YAML) ]
→ Orchestrator → Worker Pool → Scanner (nmap/masscan)
↓
Raw XML
↓
Ingest / Parser
↓
Normalized DB ↔ CVE Cache
↓
Risk Scoring
↓
Dashboard
↓
Report / Playbook Generator
```

## Výstupy projektu
- **Kód:**  
  - `orchestrator/scan_orchestrator.py` – spúšťanie skenov podľa YAML konfigurácie  
  - `ingest/parse_nmap.py` – parser a ukladanie do DB  
  - `enrich/cve_enricher.py` – modul pre doplnenie CVE  
  - `scoring/risk_score.py` – výpočet rizikového skóre  
  - `dashboard/` – vizualizácia nálezov   
- **Lab:** `docker-compose.yml` s testovacími hostmi a Postgres DB  
- **Demo:** jednoduchý dashboard + ukážkový report s prioritizovanými nálezmi  

## Testovacie scenáre
1. **Benign host** – server bez známeho CVE → očakávame nízke skóre.  
2. **Vulnerable service** – služba so známym CVE → očakávame vysoké skóre.  
3. **Exposed internal** – databázový port vystavený do verejnej siete → vysoké skóre expozície.  