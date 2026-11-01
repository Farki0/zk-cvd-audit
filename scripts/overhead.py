#!/usr/bin/env python3
"""The price of zero knowledge: the same guest logic run natively (no proof) against its proof.

  scripts/overhead.py [--bench results/measurements.csv] [--native results/native_baseline.csv]
                      [--bench-env results/bench_env.json] [--out results/zk_overhead.csv]

Reads  the native timings of `scripts/cost_extra.py native` (Algorithm 5.1 of the Rust core, run natively, and the
       Python reference) and the proving times of sweep A (n = 1, Q2, repetitions 1.., the warm-up rep 0 excluded).
Writes results/zk_overhead.csv: per slice length L the native median, the proving median, their ratio, and the CPU of
       each measurement.
The two timings are comparable only on one machine. Run `scripts/cost_extra.py native` on the machine that made the
proofs, then this script; it prints a warning, and writes 'different machines' into the CSV, if the CPU names differ."""
import argparse, csv, json, os, statistics

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rows(path):
    with open(path, newline='') as f:
        lines = [l for l in f if not l.startswith('#') and not l.startswith('"#')]
    return list(csv.DictReader(lines))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bench', default=f'{ROOT}/results/measurements.csv')
    ap.add_argument('--native', default=f'{ROOT}/results/native_baseline.csv')
    ap.add_argument('--bench-env', default=f'{ROOT}/results/bench_env.json')
    ap.add_argument('--out', default=f'{ROOT}/results/zk_overhead.csv')
    a = ap.parse_args()
    native = {int(r['L']): r for r in rows(a.native)}
    prove = {}
    for r in rows(a.bench):
        if r['sweep'] == 'A' and r['statement'] == 'Q2' and r['n'] == '1' and int(r['rep']) >= 1 and r['org'] == 'vendor01':
            prove.setdefault(int(r['L']), []).append(float(r['prove_s']))
    env = json.load(open(a.bench_env)) if os.path.exists(a.bench_env) else {}
    prover_cpu = env.get('cpu_model', '?')
    out = []
    for L in sorted(set(native) & set(prove)):
        n = float(native[L]['native_rust_s_median'])
        p = statistics.median(prove[L])
        same = native[L]['cpu_model'].strip() == str(prover_cpu).strip()
        out.append([L, n, p, round(p / n), len(prove[L]), native[L]['cpu_model'], prover_cpu, 'same machine' if same else 'different machines'])
        if not same:
            print(f'warning: L={L}: native on "{native[L]["cpu_model"]}", proof on "{prover_cpu}": not comparable')
    with open(a.out, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['# overhead.py: native Rust run against the proof of the same guest logic (sweep A, Q2, n = 1)'])
        w.writerow(['L', 'native_s_median', 'prove_s_median', 'ratio', 'prove_runs', 'native_cpu', 'prover_cpu', 'comparison'])
        w.writerows(out)
    for r in out:
        print(f'L={r[0]:5d}  native {r[1] * 1000:9.3f} ms  proof {r[2]:8.1f} s  ratio {r[3]:>9}  ({r[7]})')
    if not out:
        print('no common L: run cost_extra.py native and the sweep A first')


if __name__ == '__main__':
    main()
