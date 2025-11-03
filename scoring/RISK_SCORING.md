# scoring/risk_score.py

Score model:
  risk = 0.50 * cvss_norm
       + 0.25 * asset_score
       + 0.15 * exposure_score
       + 0.10 * maturity_score

Where:
  - cvss_norm: maximum CVSS value for a vulnerability (0–10) mapped to (0–100)
  - asset_score: from host.asset_criticality ∈ {low, medium, high} → {20, 50, 100}
  - exposure_score: host.is_public → {0, 100}
  - maturity_score: vulnerability.exploitability → {none:0, poc:50, public:100}

CLI:
  python -m scoring.risk_score --db postgresql://user:pass@localhost:5432/scans
  Optional arguments:
  --dry-run            # compute but do not write changes
  --recompute          # recompute even if risk_score is already set
  --aggregate          # also update maximum risk in services/hosts
  --limit 1000         # process only a subset
  --where "v.cve_id LIKE 'CVE-2019-%'"  # server-side filter

Env:
  DATABASE_URL can be used instead of --db
