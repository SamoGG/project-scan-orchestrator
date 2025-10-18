#!/usr/bin/env python3
import yaml
import subprocess
from datetime import datetime
from pathlib import Path
import sys


def load_job_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def sanitize_options(options_str):
    # odstráni -oX ak by bol v options a vráti list
    parts = options_str.split() if options_str else []
    return [p for p in parts if not (p == "-oX" or p.startswith("-oX"))]


def run_nmap(target, options_list, out_file, log_file):
    cmd = ["nmap"] + options_list + ["-oX", str(out_file), target]
    print(f"[orchestrator] Running: {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    # zapíš stderr a returncode do log file
    with open(log_file, "w") as lf:
        lf.write(f"cmd: {' '.join(cmd)}\n")
        lf.write(f"returncode: {proc.returncode}\n\nSTDOUT:\n")
        lf.write(proc.stdout or "")
        lf.write("\n\nSTDERR:\n")
        lf.write(proc.stderr or "")
    if proc.returncode != 0:
        print(f"[orchestrator] nmap returned {proc.returncode}, see {log_file}")
    else:
        print(f"[orchestrator] Completed {target} -> {out_file}")


def main(config_path):
    job = load_job_config(config_path)
    job_name = job.get("job_name", "job")
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    job_dir = Path(f"/app/data/raw/{job_name}")
    job_dir.mkdir(parents=True, exist_ok=True)

    options_list = sanitize_options(job.get("options", ""))
    for target in job.get("scope", []):
        out_file = job_dir / f"{target}_{ts}.xml"
        log_file = job_dir / f"{target}_{ts}.log"
        run_nmap(target, options_list, out_file, log_file)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python /app/orchestrator/scan_orchestrator.py /app/jobs/internal_quickscan.yaml"
        )
        sys.exit(1)
    cfg = sys.argv[1]
    main(cfg)
