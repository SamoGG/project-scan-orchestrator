import yaml
import subprocess
from datetime import datetime
from pathlib import Path
import sys
import json
import psycopg2
from datetime import datetime


def log_job_start(dsn, job_name, config_dict):
    conn = psycopg2.connect(dsn)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scan_jobs (job_name, started_at, status, config)
        VALUES (%s, %s, %s, %s)
        RETURNING id;
    """,
        (job_name, datetime.now(), "running", json.dumps(config_dict)),
    )
    job_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return job_id


def log_job_finish(dsn, job_id, status):
    conn = psycopg2.connect(dsn)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE scan_jobs
        SET finished_at = %s, status = %s
        WHERE id = %s;
    """,
        (datetime.now(), status, job_id),
    )
    conn.commit()
    cur.close()
    conn.close()


# Loads YAML job configuration file (e.g., jobs/internal_quickscan.yaml) into a Python dict using yaml.safe_load.
def load_job_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


# Cleans up the options string for nmap, removing any user-defined '-oX' options.
# The result is a list of safe arguments for subprocess.
def sanitize_options(options_str):
    # removes -oX if it was in options and returns a list
    parts = options_str.split() if options_str else []
    return [p for p in parts if not (p == "-oX" or p.startswith("-oX"))]

    """
    Runs the nmap scan on the target with given arguments.
    - constructs the command as a list: ["nmap", "-sV", "-Pn", "-oX", "output.xml", "172.18.0.3"]
    - writes stdout, stderr and return code to the log file
    - if nmap fails (returncode != 0), prints a warning
    """


def run_nmap(target, options_list, out_file, log_file):
    cmd = ["nmap"] + options_list + ["-oX", str(out_file), target]
    print(f"[orchestrator] Running: {' '.join(cmd)}")

    # subprocess.run run cmd and captures output (stdout, stderr)
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    # Write stderr and returncode to log file
    with open(log_file, "w") as lf:
        lf.write(f"cmd: {' '.join(cmd)}\n")
        lf.write(f"returncode: {proc.returncode}\n\nSTDOUT:\n")
        lf.write(proc.stdout or "")
        lf.write("\n\nSTDERR:\n")
        lf.write(proc.stderr or "")

    # Return code check
    if proc.returncode != 0:
        print(f"[orchestrator] nmap returned {proc.returncode}, see {log_file}")
    else:
        print(f"[orchestrator] Completed {target} -> {out_file}")


def main(config_path: str, dsn: str | None = None):
    job = load_job_config(config_path)
    job_name = job.get("job_name", Path(config_path).stem)
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")

    job_dir = Path(f"/app/data/raw/{job_name}")
    job_dir.mkdir(parents=True, exist_ok=True)

    options_list = sanitize_options(job.get("options", ""))

    job_id = None
    if dsn:
        try:
            job_id = log_job_start(dsn, job_name, job)
            print(f"[orchestrator] Logged job start → id={job_id}")
        except Exception as e:
            print(f"[orchestrator] DB log start failed: {e}")

    try:
        for target in job.get("scope", []):
            out_file = job_dir / f"{target}_{ts}.xml"
            log_file = job_dir / f"{target}_{ts}.log"
            run_nmap(target, options_list, out_file, log_file)

        if job_id and dsn:
            log_job_finish(dsn, job_id, "completed")
            print(f"[orchestrator] Logged job completion → id={job_id}")
    except Exception as e:
        if job_id and dsn:
            log_job_finish(dsn, job_id, f"failed: {e}")
        print(f"[orchestrator] Job failed: {e}")
        raise


if __name__ == "__main__":
    # Allow: 1 arg (job.yaml)  OR  2 args (job.yaml and DSN)
    if not (len(sys.argv) == 2 or len(sys.argv) == 3):
        print(
            "Usage:\n"
            "  python orchestrator/scan_orchestrator.py <job.yaml>\n"
            "  python orchestrator/scan_orchestrator.py <job.yaml> <postgresql://user:pass@db:5432/scans>\n"
            "Hint: You can also set DB_DSN env var."
        )
        sys.exit(1)

    cfg = sys.argv[1]
    dsn = None
    if len(sys.argv) == 3:
        dsn = sys.argv[2]
    else:
        dsn = os.getenv("DB_DSN")

    main(cfg, dsn=dsn)
