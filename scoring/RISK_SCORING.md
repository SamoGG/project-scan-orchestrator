# scoring/risk_score.py

Model skóre:
  riziko = 0,50 * cvss_norm
       + 0,25 * asset_score
       + 0,15 * exposure_score
       + 0,10 * maturity_score

Kde:
  - cvss_norm: maximálne CVSS pre zraniteľnosť (0–10) priradené k (0–100)
  - asset_score: z host.asset_criticality ∈ {low, medium, high} → {20,50,100}
  - exposure_score: host.is_public → {0,100}
  - maturity_score: vulnerability.exploitability → {none:0, poc:50, public:100}

CLI:
  python -m scoring.risk_score --db postgresql://user:pass@localhost:5432/scans
  Voliteľné:
  --dry-run            # vypočítať, ale nezapísať
  --recompute          # prepočítať aj v prípade, že risk_score je už nastavené
  --aggregate          # zapísať aj maximálne riziko do služieb/hostiteľov
  --limit 1000         # spracovať podmnožinu
  --where „v.cve_id LIKE ‚CVE-2019-%‘“  # filter na strane servera

Env:
  DATABASE_URL možno použiť namiesto --db
