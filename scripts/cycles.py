#!/usr/bin/env python3
"""Machine-independent cost: executor-only cycles, segments and journal size (no proving) -> results/cycles.csv.
`cycles` = instructions the guest executed (user cycles); `padded_cycles` = sum of 2^po2 over the segments, i.e. what the
prover has to cover (adds paging and padding). Both are deterministic for a given guest binary."""
import csv, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench

OUT = f'{bench.ROOT}/results/cycles.csv'
FIELDS = ['sweep', 'statement', 'n', 'L', 'org', 'role', 'variant', 'records', 'cycles', 'padded_cycles', 'segments', 'journal_bytes']
Ls = [8, 32, 128, 512, 2048]
rows = []


def ex(sweep, q, n, L, org, variant='full'):
    scn = bench.scenario(n, L)
    sc = json.load(open(scn))
    txt, _, _ = bench.run(['exec', '--stmt', bench.stmt(q), '--scenario', scn, '--org', org, '--variant', variant])
    m = json.loads(txt)
    rows.append([sweep, q, n, L, org, sc['participants'][org], variant, len(sc['slices'][org]), m['cycles'], m['padded_cycles'], m['segments'], m['journal_bytes']])
    print(rows[-1], flush=True)


for q in ('Q2', 'Q4'):
    for L in Ls:
        ex('A', q, 1, L, 'vendor01')
for L in Ls:
    for v in ('chain', 'iface', 'full'):
        ex('C', 'Q2', 1, L, 'vendor01', v)
for n in (1, 2, 4, 8, 16):
    ex('B', 'Q3', n, 32, 'maintainer')
    ex('B', 'Q3', n, 32, 'vendor01')
for n in (2, 8, 16):
    scn = bench.scenario(n, 32)
    txt, _, _ = bench.run(['agg-exec', '--stmt', bench.stmt('Q2'), '--scenario', scn])
    m = json.loads(txt)
    rows.append(['D', 'Q2', n, 32, 'aggregator', 'aggregator', 'agg', n + 1, m['cycles'], m['padded_cycles'], m['segments'], m['journal_bytes']])
    print(rows[-1], flush=True)
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, 'w', newline='') as f:
    w = csv.writer(f); w.writerow(FIELDS); w.writerows(rows)
# the cycle counts hold for these guest binaries only: record their image ids next to the CSV
env, _, _ = bench.run(['env'])
with open(OUT.replace('.csv', '_env.json'), 'w') as f:
    json.dump({'guest_image_ids': json.loads(env)['guest_image_ids'], 'risc0_zkvm_crate': json.loads(env)['risc0_zkvm_crate'],
               'note': 'cycles = user cycles (instructions executed); padded_cycles = sum of 2^po2 over segments'}, f, indent=1)
print('wrote', OUT)