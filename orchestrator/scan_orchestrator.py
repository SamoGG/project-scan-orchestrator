import yaml
import subprocess
from datetime import datetime
from pathlib import Path
import sys


# Načíta YAML konfiguračný súbor jobu (napr. jobs/internal_quickscan.yaml) a prevedie ho na Python dict pomocou yaml.safe_load.
def load_job_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


# Vyčistí reťazec s parametrami pre nmap, ak by obsahoval vlastné '-oX' voľby. -oX sa používa na XML výstup, ale orchestrátor ho nastavuje sám.
# Výsledkom je zoznam (list) bezpečných argumentov pre subprocess.
def sanitize_options(options_str):
    # odstráni -oX ak by bol v options a vráti list
    parts = options_str.split() if options_str else []
    return [p for p in parts if not (p == "-oX" or p.startswith("-oX"))]

    """
    Spustí samotný nmap sken na cieľ (target) s danými argumentmi.
    - vytvorí príkaz ako list: ["nmap", "-sV", "-Pn", "-oX", "vystup.xml", "172.18.0.3"]
    - zapíše stdout, stderr a návratový kód do log súboru
    - ak nmap zlyhá (returncode != 0), vypíše upozornenie
    """


def run_nmap(target, options_list, out_file, log_file):
    cmd = ["nmap"] + options_list + ["-oX", str(out_file), target]
    print(f"[orchestrator] Running: {' '.join(cmd)}")

    # subprocess.run spustí príkaz a zachytí výstup (stdout, stderr)
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

    # kontrola návratového kódu
    if proc.returncode != 0:
        print(f"[orchestrator] nmap returned {proc.returncode}, see {log_file}")
    else:
        print(f"[orchestrator] Completed {target} -> {out_file}")


def main(config_path):
    # načítaj job konfiguráciu
    job = load_job_config(config_path)
    job_name = job.get("job_name", "job")
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    # vytvor adresár pre job
    job_dir = Path(f"/app/data/raw/{job_name}")
    job_dir.mkdir(parents=True, exist_ok=True)

    # priprav parametre nmap
    options_list = sanitize_options(job.get("options", ""))

    # spusti nmap pre každý cieľ v scope
    for target in job.get("scope", []):
        out_file = job_dir / f"{target}_{ts}.xml"
        log_file = job_dir / f"{target}_{ts}.log"
        run_nmap(target, options_list, out_file, log_file)


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(
            "Usage: docker compose exec orchestrator python orchestrator/scan_orchestrator.py jobs/internal_quickscan.yaml"
        )
        sys.exit(1)

    cfg = sys.argv[1]
    main(cfg)
