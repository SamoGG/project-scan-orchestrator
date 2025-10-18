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


CREATE TABLE IF NOT EXISTS vulnerabilities (
  id SERIAL PRIMARY KEY,
  service_id INT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  cvss NUMERIC,
  description TEXT,
  exploit_maturity TEXT,
  risk_score NUMERIC
);


CREATE UNIQUE INDEX IF NOT EXISTS hosts_ip_key ON hosts (ip);
CREATE UNIQUE INDEX IF NOT EXISTS services_host_port_proto_key
  ON services (host_id, port, proto);
