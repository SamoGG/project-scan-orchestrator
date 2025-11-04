-- lab/db/schema.sql
CREATE TABLE IF NOT EXISTS hosts (
  id SERIAL PRIMARY KEY,
  ip INET UNIQUE,
  last_seen TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS services (
  id SERIAL PRIMARY KEY,
  host_id INT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  port INT NOT NULL,
  proto TEXT NOT NULL,
  product TEXT,
  version TEXT,
  banner TEXT,
  first_seen TIMESTAMP DEFAULT now(),
  last_seen TIMESTAMP DEFAULT now(),
  UNIQUE(host_id, port, proto)
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id SERIAL PRIMARY KEY,
  job_name TEXT,
  started_at TIMESTAMP,
  finished_at TIMESTAMP,
  status TEXT,
  config JSONB
);


CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
    cve_id TEXT,
    cvss NUMERIC(3,1),
    description TEXT,
    exploitability NUMERIC(3,1),
    epss NUMERIC(5,4),           
    epss_percentile NUMERIC(5,2),
    risk_score NUMERIC(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uniq_vuln_service_cve'
  ) THEN
    ALTER TABLE vulnerabilities
      ADD CONSTRAINT uniq_vuln_service_cve UNIQUE (service_id, cve_id);
  END IF;
END $$;


CREATE UNIQUE INDEX IF NOT EXISTS hosts_ip_key ON hosts (ip);
CREATE UNIQUE INDEX IF NOT EXISTS services_host_port_proto_key
  ON services (host_id, port, proto);


