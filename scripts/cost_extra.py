#!/usr/bin/env python3
"""EQ3 additions that need no proving (minutes): what the cycle sweeps of cycles.py leave open.

  native   Algorithm 5.1 of the same Rust core run natively (no zkVM) and the Python reference guest, on the
           sweep A inputs (n = 1, Q2, L = 8..2048) -> results/native_baseline.csv. Together with prove_s from
           runs/bench/measurements.csv this gives the zero-knowledge overhead factor.
  stmt     cycles of one vendor's proof (n = 1, L = 128) against the size of the monitor: random reparation chains of
           the Section 4.4 self-check, compiled by the reference compiler -> results/cycles_statement_size.csv.
           Tests the Chapter 4 claim that the monitor's work per record does not depend on its number of states.
  record   cycles against record size: the internal records carry a filler field of 0..1024 bytes (n = 1, L = 128,
           Q2) -> results/cycles_record_size.csv. The sweeps pad with ~20-byte 'work' records; real records are larger.

  scripts/cost_extra.py [native stmt record]"""
import csv, json, os, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evalkit as K  # noqa: E402
import bench         # noqa: E402

RES = f'{K.ROOT}/results'


def write(path, fields, rows):
    with open(path, 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['# ' + os.path.basename(__file__) + ' (executor/native, no proofs)']); w.writerow(fields); w.writerows(rows)
    print('wrote', path, flush=True)


def native():
    q = f'{K.REF}/vectors/statements/Q2.json'
    st = K.GOLDEN['Q2']
    rows = []
    cpu = K.host('env')['cpu_model']                  # timings are machine-dependent: name the machine in every row
    for L in (8, 32, 128, 512, 2048):
        p = bench.scenario(1, L)
        scn = json.load(open(p))
        nat = K.host('native', '--stmt', q, '--scenario', p, '--org', 'vendor01', '--reps', 21)
        ex = K.host('exec', '--stmt', q, '--scenario', p, '--org', 'vendor01')
        assert nat['journal'] == ex['journal'], 'native and zkVM journals differ'
        ts = []
        for _ in range(5):
            t = time.perf_counter()
            K.V.guest(st, scn['instance'], scn['participants'], 'vendor01', scn['slices']['vendor01'], scn['genesis_salts']['vendor01'])
            ts.append(time.perf_counter() - t)
        ts.sort()
        rows.append([L, nat['records'], nat['native_s_median'], nat['native_s_min'], nat['native_s_max'], ts[2],
                     ex['exec_s'], ex['cycles'], ex['padded_cycles'], cpu])
        print(rows[-1], flush=True)
    write(f'{RES}/native_baseline.csv', ['L', 'records', 'native_rust_s_median', 'native_rust_s_min', 'native_rust_s_max',
                                         'python_reference_s_median', 'zkvm_executor_s', 'user_cycles', 'padded_cycles', 'cpu_model'], rows)


def stmt_size():
    rng = random.Random(44)
    conds = [K.R.PATCH, K.R.MITIG, K.R.ADVIS, K.R.DISC, K.R.GRACE, K.R.Ev('patch'), K.R.COr(K.R.MITIG, K.R.PATCH),
             K.R.CNot(K.R.DISC)]
    seen, chosen = set(), []
    for _ in range(3000):                         # one chain per (states, atoms) pair, as many sizes as the generator gives
        ch = K.R.random_chain(rng, conds)
        norm = K.V.chain_norm('rand', ch)
        key = (len(norm['out']), len(norm['atoms']))
        if key not in seen:
            seen.add(key); chosen.append((norm, len(ch.levels)))
    chosen.sort(key=lambda x: (len(x[0]['out']), len(x[0]['atoms'])))
    p, p32 = bench.scenario(1, 128), bench.scenario(1, 32)
    rows = []
    for name, norm, levels in [('Q2', K.GOLDEN['Q2']['norms'][0], 2), ('Q4', K.GOLDEN['Q4']['norms'][0], 0)] + \
                              [(f'rand{i}', n, lv) for i, (n, lv) in enumerate(chosen)]:
        st = K.statement(name, [norm], 'verdict')
        sp = K.dump(st, f'{K.WORK}/stmt/{name}.json')
        m = K.host('exec', '--stmt', sp, '--scenario', p, '--org', 'vendor01')
        m32 = K.host('exec', '--stmt', sp, '--scenario', p32, '--org', 'vendor01')
        # per internal record: the slope between L = 32 and L = 128 (the 96 extra records are all 'work' records),
        # which removes the fixed cost of reading the statement
        rows.append([name, levels, len(norm['out']), len(norm['atoms']), len(norm['letters']), len(st['canonical']),
                     128, m['cycles'], m['padded_cycles'], m['segments'], round((m['cycles'] - m32['cycles']) / 96, 1),
                     m32['cycles']])
        print(rows[-1], flush=True)
    write(f'{RES}/cycles_statement_size.csv', ['statement', 'levels', 'states', 'atoms', 'letters', 'statement_bytes', 'L',
                                               'user_cycles', 'padded_cycles', 'segments', 'cycles_per_internal_record',
                                               'user_cycles_L32'], rows)


def record_size():
    rows = []
    q = f'{K.REF}/vectors/statements/Q2.json'
    for size in (0, 16, 64, 256, 1024):
        pads = [{'type': 'work', 'i': i, **({'blob': 'x' * size} if size else {})} for i in range(122)]
        sl, parts = K.run_cvd(f'REC-{size}', {'vendor01': {'pre': pads + [{'type': 'patch', 'coverage': 'full'}]}})
        scn = K.scenario_of(f'record size {size}', f'REC-{size}', sl, parts)
        p = K.dump(scn, f'{K.WORK}/recsize/{size}.json')
        rec_bytes = len(json.dumps(pads[0], sort_keys=True, separators=(',', ':')))
        m = K.host('exec', '--stmt', q, '--scenario', p, '--org', 'vendor01')
        assert m['journal']['verdict'] == 'complied'
        rows.append([size, rec_bytes, len(scn['slices']['vendor01']), m['cycles'], m['padded_cycles'], m['segments']])
        print(rows[-1], flush=True)
    write(f'{RES}/cycles_record_size.csv', ['filler_bytes', 'internal_record_bytes', 'records', 'user_cycles',
                                            'padded_cycles', 'segments'], rows)


if __name__ == '__main__':
    which = sys.argv[1:] or ['native', 'stmt', 'record']
    for w in which:
        {'native': native, 'stmt': stmt_size, 'record': record_size}[w]()
