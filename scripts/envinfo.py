#!/usr/bin/env python3
"""Writes <run-dir>/env.json (machine, toolchain, versions, git commit) and aborts if RISC Zero dev mode is on.
A fake proof makes every timing meaningless, so every run directory starts with this check.
usage: envinfo.py RUN_DIR"""
import datetime, json, os, platform, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = os.path.join(ROOT, 'target', 'release', 'host')


def sh(*a):
    try:
        return subprocess.run(a, cwd=ROOT, capture_output=True, text=True).stdout.strip()
    except OSError:
        return ''


def dev_mode_on():
    v = os.environ.get('RISC0_DEV_MODE')
    return v is not None and v.lower() not in ('', '0', 'false')


def collect():
    if dev_mode_on():
        sys.exit('RISC0_DEV_MODE is set: proofs would be fake. Unset it and rerun.')
    env = json.loads(subprocess.run([HOST, 'env'], capture_output=True, text=True, check=True).stdout)
    cores = sh('lscpu', '-p=CORE,SOCKET')
    env['physical_cores'] = len({l for l in cores.splitlines() if not l.startswith('#')}) or None
    env['git_commit'] = sh('git', 'rev-parse', 'HEAD') or None
    env['git_dirty'] = bool(sh('git', 'status', '--porcelain'))
    env['cargo_lock_sha256'] = sh('sha256sum', 'Cargo.lock').split(' ')[0] or None
    env['python'] = platform.python_version()
    env['date_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    env['RISC0_DEV_MODE'] = os.environ.get('RISC0_DEV_MODE')
    env['dev_mode_checked_off'] = True
    return env


def write(run_dir):
    os.makedirs(run_dir, exist_ok=True)
    env = collect()
    with open(os.path.join(run_dir, 'env.json'), 'w') as f:
        json.dump(env, f, indent=1, sort_keys=True)
    return env


if __name__ == '__main__':
    e = write(sys.argv[1])
    print(f"env.json written to {sys.argv[1]} (dev mode off, risc0 {e['risc0_zkvm_crate']}, commit {e['git_commit']})")