# Orchestrator and Prioritization System for Authorized Network Scanning

**Author:** Samuel Gabriel Galgóci  
**Goal:** Build a secure, configurable orchestrator that launches authorized network scans,  
normalizes the results, enriches them with CVE data, and evaluates findings by risk.

## Quick Start
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

### Workflow

Start/stop Docker:
```bash
docker compose up -d

docker compose stop
```

### CLI

To scan hosts, start the orchestrator.  
It will create XML and log files for parsing.
Scans are run one per host. XML is used because it is nativly supported not like JSON.
```bash
docker compose exec orchestrator python orchestrator/scan_orchestrator.py jobs/internal_quickscan.yaml
```

Then run the parser to save the files into the database:
```bash
docker compose run --rm parser "/app/data/raw/internal_quickscan/*.xml" "postgresql://user:pass@db:5432/scans"
```

To check the data in the database:
```bash
docker compose exec db psql -U user -d scans
```

Example queries:
```sql
-- list of scanned hosts
SELECT * FROM hosts ORDER BY id;

-- list of all services for each host
SELECT h.ip, s.port, s.proto, s.product, s.version, s.banner,
       s.first_seen, s.last_seen
FROM hosts h
JOIN services s ON s.host_id = h.id
ORDER BY h.ip, s.port;

-- number of services per host
SELECT h.ip, COUNT(*) AS svc_count
FROM hosts h
JOIN services s ON s.host_id = h.id
GROUP BY h.ip
ORDER BY svc_count DESC;

-- records from the last hour
SELECT h.ip, s.port, s.proto, s.last_seen
FROM hosts h
JOIN services s ON s.host_id = h.id
WHERE s.last_seen > now() - interval '1 hour'
ORDER BY s.last_seen DESC;
```

Run the **service enricher**, which adds CVEs to services that match entries in the `cve_cache`.
```bash
docker compose run --rm enricher
```

Check the results:
```bash
docker compose exec db psql -U user -d scans -c "SELECT service_id, cve_id, cvss FROM vulnerabilities ORDER BY service_id, cve_id;"
```

Run **risk scoring** for the stored data:
```bash
docker compose run --rm scorer
```
Risk calculation policy is in **RISK_SCORING.md**

| Parameter     | Description                                                                 |
| -------------- | --------------------------------------------------------------------------- |
| `--db`         | PostgreSQL DSN (if the `DATABASE_URL` environment variable is not set)      |
| `--dry-run`    | Compute the score but do not write it to the DB                             |
| `--recompute`  | Recompute all records, including those that already have `risk_score`       |
| `--aggregate`  | After computation, also update `services.risk_max` and `hosts.risk_max`     |
| `--limit N`    | Process only the first *N* records                                          |
| `--where`      | Optional SQL filter (e.g. `"v.cve_id LIKE 'CVE-2021-%'"`)                   |

---

### Dashboard

```bash
docker compose up -d
#Open http://localhost:8501
```

- **One-click orchestration**
  - `▶ Run Scan` — executes network scan from a selected YAML job  
  - `Parse Nmap XML` — normalizes XML results and inserts into DB  
  - `CVE Enrich` — fetches vulnerability data from CVE feeds  
  - `Risk Scoring` — calculates risk values for each service
- **Live console streaming** for every process (stdout + stderr)
- **Data views**
  - **Hosts** — hosts with service counts and max risk
  - **Services** — ports, banners, product versions, risk scores
  - **Vulnerabilities** — searchable & filterable table with CSV export
  - **Top Risks** — highest-risk entries (top 50)
  - **Scan Jobs** — historical overview with timestamps & configs
- **Maintenance tools**
  - Delete raw XML/logs under `data/raw/**`
  - Truncate database tables (`hosts`, `services`, `vulnerabilities`)

#### Environment variables

| Variable | Default | Description |
|-----------|----------|-------------|
| `DB_DSN` | `postgresql://user:pass@db:5432/scans` | Database connection string |
| `JOBS_DIR` | `jobs` | Directory with scan job YAML files |
| `RAW_DIR` | `data/raw` | Directory for raw Nmap XML outputs |
| `CVE_CACHE` | `enrich/cve_cache.json` | Local CVE cache path |

## Architecture (Simplified)
```
[ Job Configs (YAML) ]
→ Orchestrator → Worker Pool → Scanner (nmap)
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
```

## Project Components
- **Code:**  
  - `orchestrator/scan_orchestrator.py` – executes scans based on YAML configuration  
  - `ingest/parse_nmap.py` – parser and database ingestion  
  - `enrich/cve_enricher.py` – module for CVE enrichment  
  - `scoring/risk_score.py` – risk score computation  
  - `dashboard/` – visualization of findings  
- **Lab:** `docker-compose.yml` with test hosts and Postgres DB   

## Test Scenarios
1. **Benign host** – server without known CVEs → expected low score.  
2. **Vulnerable service** – service with known CVEs → expected high score.  
3. **Exposed internal** – database port exposed to the public network → expected high exposure score.  
