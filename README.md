# Orchestrator a prioritizačný systém pre autorizované sieťové skenovanie

**Autor:** Samuel Gabriel Galgóci  
**Cieľ:** Vybudovať bezpečný, konfigurovateľný orchestrator, ktorý spúšťa autorizované sieťové skeny, 
normalizuje výsledky, obohacuje ich o CVE a hodnotí podľa rizika.

## Rýchly štart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker-compose -f lab/docker-compose.yml up --build -d

---

## Python prostredie
```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pyyaml xmltodict psycopg2-binary streamlit
pip freeze > requirements.txt
