#!/usr/bin/env python3
"""
ARISE - "Summon Every Hidden Exposure."

Single control script for the ARISE External Attack Surface Monitoring toolkit.

It wraps two things behind one command:
  1. The scan engine (easm-pipeline.sh)  - the actual recon/vuln-scanning pipeline.
  2. The dashboard (dashboard.py)        - the Flask UI that visualizes scan results.

Usage:
    python3 arise.py                          # scan every host in hosts.txt, dashboard first
    python3 arise.py --hosts targets.txt       # use a different input file
    python3 arise.py --no-dashboard            # scan only, don't launch the dashboard
    python3 arise.py --dashboard-only           # just launch the dashboard, skip scanning
    python3 arise.py --skip waf_detection --skip param_fuzzing
    python3 arise.py --env PORT_SCAN_MODE=fast --env NAABU_RATE=5000
    python3 arise.py --dry-run                  # show the plan without running anything

hosts.txt format:
    One target domain per line. Blank lines and lines starting with '#' are ignored.

        # production assets
        example.com
        example.org
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PIPELINE_SCRIPT = SCRIPT_DIR / "easm-pipeline.sh"
DASHBOARD_SCRIPT = SCRIPT_DIR / "dashboard.py"
DEFAULT_HOSTS_FILE = SCRIPT_DIR / "hosts.txt"
LOG_DIR = SCRIPT_DIR / "logs"

BANNER = r"""
 █████╗ ██████╗ ██╗███████╗███████╗
██╔══██╗██╔══██╗██║██╔════╝██╔════╝
███████║██████╔╝██║███████╗█████╗
██╔══██║██╔══██╗██║╚════██║██╔══╝
██║  ██║██║  ██║██║███████║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
        Summon Every Hidden Exposure.
"""


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def read_hosts(hosts_file: Path):
    """Read target hosts one per line, skipping blanks and comments."""
    if not hosts_file.exists():
        log(f"Hosts file not found: {hosts_file}", "ERROR")
        log("Create it with one target domain per line, e.g.:", "ERROR")
        log("    echo 'example.com' >> hosts.txt", "ERROR")
        sys.exit(1)

    hosts = []
    seen = set()
    with hosts_file.open("r") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line in seen:
                log(f"Skipping duplicate host: {line}", "WARN")
                continue
            seen.add(line)
            hosts.append(line)

    if not hosts:
        log(f"No targets found in {hosts_file}", "ERROR")
        sys.exit(1)

    return hosts


def start_dashboard(port: int, env: dict):
    """Launch dashboard.py in the background and return the Popen handle."""
    if not DASHBOARD_SCRIPT.exists():
        log(f"Dashboard script missing: {DASHBOARD_SCRIPT}", "ERROR")
        return None

    dash_env = os.environ.copy()
    dash_env.update(env)
    dash_env["ARISE_DASHBOARD_PORT"] = str(port)

    log(f"Launching dashboard on http://localhost:{port} ...")
    proc = subprocess.Popen(
        [sys.executable, str(DASHBOARD_SCRIPT)],
        cwd=str(SCRIPT_DIR),
        env=dash_env,
    )
    # Give Flask a moment to bind before scans start hammering the filesystem.
    time.sleep(2)
    if proc.poll() is not None:
        log("Dashboard process exited immediately; check logs/dashboard.log", "WARN")
    else:
        log(f"Dashboard is running (pid {proc.pid})")
    return proc


def stop_dashboard(proc):
    if proc is None or proc.poll() is not None:
        return
    log("Stopping dashboard...")
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    log("Dashboard stopped")


def run_pipeline_for_host(host: str, skip_modules, debug: bool, output_dir, env: dict):
    """Invoke the ARISE scan engine (easm-pipeline.sh) for a single host."""
    if not PIPELINE_SCRIPT.exists():
        log(f"Scan engine missing: {PIPELINE_SCRIPT}", "ERROR")
        return 127

    cmd = ["bash", str(PIPELINE_SCRIPT), host]
    for module in skip_modules:
        cmd += ["--skip", module]
    if output_dir:
        cmd += ["--output", output_dir]
    if debug:
        cmd.append("--debug")

    run_env = os.environ.copy()
    run_env.update(env)

    log(f"Starting scan engine for target: {host}")
    log(f"Command: {' '.join(cmd)}")

    start = time.time()
    result = subprocess.run(cmd, cwd=str(SCRIPT_DIR), env=run_env)
    elapsed = int(time.time() - start)

    if result.returncode == 0:
        log(f"Completed {host} in {elapsed}s")
    else:
        log(f"{host} exited with code {result.returncode} after {elapsed}s", "WARN")

    return result.returncode


def parse_env_overrides(pairs):
    env = {}
    for pair in pairs or []:
        if "=" not in pair:
            log(f"Ignoring malformed --env value (expected KEY=VALUE): {pair}", "WARN")
            continue
        key, value = pair.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def main():
    parser = argparse.ArgumentParser(
        description='ARISE - "Summon Every Hidden Exposure." Single control script for the scan engine + dashboard.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--hosts", "-H", default=str(DEFAULT_HOSTS_FILE),
                         help=f"Path to hosts file, one target per line (default: {DEFAULT_HOSTS_FILE.name})")
    parser.add_argument("--skip", "-s", action="append", default=[],
                         help="Skip a pipeline module (repeatable). E.g. --skip waf_detection")
    parser.add_argument("--output", "-o", default=None,
                         help="Output directory override. Only valid when scanning a single host.")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable pipeline debug mode")
    parser.add_argument("--env", "-e", action="append", default=[],
                         help="Environment variable override for the scan engine, KEY=VALUE (repeatable). "
                              "E.g. --env PORT_SCAN_MODE=fast --env NAABU_RATE=5000")
    parser.add_argument("--no-dashboard", action="store_true", help="Do not launch the dashboard")
    parser.add_argument("--dashboard-only", action="store_true", help="Launch only the dashboard, skip scanning")
    parser.add_argument("--dashboard-port", type=int, default=5000, help="Port for the dashboard (default: 5000)")
    parser.add_argument("--continue-on-error", action="store_true", default=True,
                         help="Keep scanning remaining hosts if one fails (default behavior)")
    parser.add_argument("--stop-on-error", action="store_true",
                         help="Abort the queue on the first host that fails")
    parser.add_argument("--dry-run", action="store_true", help="Show the plan without running anything")
    args = parser.parse_args()

    print(BANNER)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    env_overrides = parse_env_overrides(args.env)

    hosts_file = Path(args.hosts).expanduser().resolve()
    dashboard_proc = None

    if args.dashboard_only:
        dashboard_proc = start_dashboard(args.dashboard_port, env_overrides)
        if dashboard_proc is None:
            sys.exit(1)
        log("Dashboard-only mode. Press Ctrl+C to stop.")
        try:
            dashboard_proc.wait()
        except KeyboardInterrupt:
            pass
        finally:
            stop_dashboard(dashboard_proc)
        return

    hosts = read_hosts(hosts_file)
    log(f"Loaded {len(hosts)} target(s) from {hosts_file}")

    if args.output and len(hosts) > 1:
        log("--output is only supported with a single target; ignoring for this multi-host run", "WARN")
        args.output = None

    if args.dry_run:
        log("DRY RUN - the following would execute:")
        if not args.no_dashboard:
            log(f"  1. Launch dashboard at http://localhost:{args.dashboard_port}")
        for i, host in enumerate(hosts, 1):
            skip_str = f" --skip {' --skip '.join(args.skip)}" if args.skip else ""
            log(f"  {i}. bash easm-pipeline.sh {host}{skip_str}")
        return

    try:
        if not args.no_dashboard:
            dashboard_proc = start_dashboard(args.dashboard_port, env_overrides)

        results = {}
        for i, host in enumerate(hosts, 1):
            log(f"[{i}/{len(hosts)}] Feeding target from hosts file: {host}")
            rc = run_pipeline_for_host(host, args.skip, args.debug, args.output, env_overrides)
            results[host] = rc
            if rc != 0 and args.stop_on_error:
                log(f"Stopping queue after failure on {host} (--stop-on-error set)", "ERROR")
                break

        succeeded = [h for h, rc in results.items() if rc == 0]
        failed = [h for h, rc in results.items() if rc != 0]

        log("=" * 60)
        log(f"Run complete: {len(succeeded)} succeeded, {len(failed)} failed, "
            f"{len(hosts) - len(results)} not run")
        if succeeded:
            log(f"  Succeeded: {', '.join(succeeded)}")
        if failed:
            log(f"  Failed:    {', '.join(failed)}", "WARN")

        if dashboard_proc is not None:
            log(f"Dashboard still running at http://localhost:{args.dashboard_port} (Ctrl+C to stop)")
            dashboard_proc.wait()

    except KeyboardInterrupt:
        log("Interrupted by user", "WARN")
    finally:
        stop_dashboard(dashboard_proc)


if __name__ == "__main__":
    main()
