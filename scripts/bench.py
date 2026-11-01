#!/usr/bin/env python3
"""Benchmark runner for the proving-time sweeps of the evaluation.

  scripts/bench.py --dry-run A B C D K     print the planned runs and the time estimate (no proving)
  scripts/bench.py A                       run sweep A (resumable: rows already in the CSV are skipped)
  --plan short (default) | long            preset of points and repetitions (PLANS below; options override it)

Sweeps (long plan; the short plan's subset in brackets):
         A slice length (n=1, Q2 and Q4) [Q2]      B number of vendors (L=32, Q3, every organisation + audit) [1 rep]
         C ablation (n=1, Q2, two variants; L=128, 2048) [128]   D aggregation guest (n=2,8,16, Q2) [2, 8; 1 rep]
         K receipt kinds (n=1, L=128 and 512, Q2) [128]
         E record size (n=1, Q2, internal records with a filler field of 256 and 1024 bytes; L=128, 512) [128]; the
           sweep is named E<filler> in the CSV (E256, E1024); sweep A is the 0-byte point (21-byte records)
  --cold                                   drop the page cache before every proof (needs root or passwordless sudo)
Every proof runs in its own host process (peak memory via wait4 over the process tree). The CSV is appended after
every proof. A run directory (default runs/bench) holds env.json, measurements.csv, measurements_audit.csv and the
receipts of the current repetition; run again with the same directory to resume."""
import argparse, csv, json, os, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import envinfo  # noqa: E402

HOST = f'{ROOT}/target/release/host'
REF = f'{ROOT}/reference'
FIELDS = ['sweep', 'rep', 'statement', 'n', 'L', 'org', 'role', 'records', 'variant', 'requested_kind', 'receipt_kind',
          'cycles', 'user_cycles', 'segments', 'prove_s', 'peak_rss_mb', 'receipt_bytes', 'journal_bytes', 'verify_s', 'wall_s', 'control_id',
          'control_program']
AUDIT_FIELDS = ['sweep', 'rep', 'statement', 'n', 'L', 'mode', 'audit_s', 'receipts']


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def scenario(n, L):
    p = f'{ROOT}/work/scn/n{n}_L{L}.json'
    if not os.path.exists(p):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        subprocess.run([sys.executable, f'{REF}/code/vectors.py', 'scenario', '--vendors', str(n), '--length', str(L), '--out', p],
                       check=True, env=env, stdout=subprocess.DEVNULL)
    return p


def scenario_filler(L, size):
    """Sweep E: one vendor, L records, the internal ('work') records carry a filler field of `size` bytes (as
    cost_extra.py record_size, which measures the cycles of the same inputs). Built with the evaluation kit, not
    with reference/code/vectors.py, which stays as it is."""
    p = f'{ROOT}/work/scn/n1_L{L}_f{size}.json'
    if not os.path.exists(p):
        import evalkit as K
        pads = [{'type': 'work', 'i': i, 'blob': 'x' * size} for i in range(L - 6)]   # the CVD records fill the other 6
        # the instance id 'REC-<size>' is the one of cost_extra.py record_size, so that the L = 128 input is the same
        sl, parts = K.run_cvd(f'REC-{size}', {'vendor01': {'pre': pads + [{'type': 'patch', 'coverage': 'full'}]}})
        scn = K.scenario_of(f'record size {size}, L {L}', f'REC-{size}', sl, parts)
        assert len(scn['slices']['vendor01']) == L, len(scn['slices']['vendor01'])
        K.dump(scn, p)
    return p


COLD = False


def drop_caches():
    """Cold start: flush the page cache before a proof (root, or sudo without a password). Returns False if it cannot."""
    subprocess.run(['sync'])
    for cmd in (['sh', '-c', 'echo 3 > /proc/sys/vm/drop_caches'], ['sudo', '-n', 'sh', '-c', 'echo 3 > /proc/sys/vm/drop_caches']):
        if subprocess.run(cmd, capture_output=True).returncode == 0:
            return True
    return False


def public(scn):
    """The public part of a scenario (instance, participants, published slice commitments): what the auditor gets."""
    p = scn.replace('.json', '.public.json')
    if not os.path.exists(p):
        sc = json.load(open(scn))
        json.dump({k: sc[k] for k in ('instance', 'participants', 'participants_canonical', 'published', 'length')}, open(p, 'w'))
    return p


def stmt(q):
    return f'{REF}/vectors/statements/{q}.json'


def run(args, extra_env=None):
    """Runs the host binary; returns (stdout, wall_s, peak_rss_mb of the whole process tree)."""
    env = dict(os.environ, **(extra_env or {}))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        t = time.time()
        p = subprocess.Popen([HOST] + args, stdout=out, stderr=err, env=env)
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.time() - t
        out.seek(0); err.seek(0)
        txt = out.read().decode()
        etxt = err.read().decode()[-3000:]
    if os.waitstatus_to_exitcode(status) != 0:
        raise RuntimeError(f'host {args} failed: {txt}\n--- stderr ---\n{etxt}')
    return txt, wall, ru.ru_maxrss / 1024


def estimate(q, scn, org, variant, kind, a):
    """Planned proving time of one proof: padded cycles x --sec-per-mcycle, and for a succinct receipt one recursion
    proof (lift or join) per segment and per join, x --recursion-s. The segments are those prove_org proves: a slice
    that fits one segment is executed again with half the segment limit, as prove_org does (control id)."""
    args = ['exec', '--stmt', stmt(q), '--scenario', scn, '--org', org, '--variant', variant]
    m = json.loads(run(args)[0])
    if kind == 'succinct' and m['segments'] == 1:
        m = json.loads(run(args, {'PROTO_PO2': str(m['po2'][0] - 1)})[0])
    rec = 2 * m['segments'] - 1 if kind == 'succinct' else 0
    return m['padded_cycles'] * a.sec_per_mcycle / 1e6 + rec * a.recursion_s


class Store:
    def __init__(self, d):
        self.path, self.apath = f'{d}/measurements.csv', f'{d}/measurements_audit.csv'
        self.done, self.arows = set(), set()
        for p, fields, keyf, dst in ((self.path, FIELDS, lambda r: (r['sweep'], r['rep'], r['statement'], r['n'], r['L'], r['org'], r['variant'], r['requested_kind']), self.done),
                                     (self.apath, AUDIT_FIELDS, lambda r: (r['sweep'], r['rep'], r['statement'], r['n'], r['L'], r['mode']), self.arows)):
            if os.path.exists(p):
                with open(p, newline='') as f:
                    header = next(csv.reader(f), None)
                if header != fields:      # appending rows under another header would shift the columns
                    sys.exit(f'{p} has the columns {header}, this bench.py writes {fields}: use another --run-dir')
                dst.update(keyf(r) for r in csv.DictReader(open(p)))
            else:
                with open(p, 'w', newline='') as f:
                    csv.writer(f).writerow(fields)

    @staticmethod
    def jkey(j):
        return tuple(map(str, (j['sweep'], j['rep'], j['q'], j['n'], j['L'], j['org'], j['variant'], j['kind'])))

    def add(self, j, m):
        row = {**m, 'sweep': j['sweep'], 'rep': j['rep'], 'n': j['n'], 'L': j['L']}
        with open(self.path, 'a', newline='') as f:                       # written after every proof
            csv.DictWriter(f, FIELDS, extrasaction='ignore').writerow(row)
            f.flush(); os.fsync(f.fileno())
        self.done.add(self.jkey(j))

    def add_audit(self, g, mode, audit_s, receipts):
        with open(self.apath, 'a', newline='') as f:
            csv.writer(f).writerow([g['sweep'], g['rep'], g['q'], g['n'], g['L'], mode, audit_s, receipts])
            f.flush(); os.fsync(f.fileno())
        self.arows.add(tuple(map(str, (g['sweep'], g['rep'], g['q'], g['n'], g['L'], mode))))

    def has_audit(self, g, mode):
        return tuple(map(str, (g['sweep'], g['rep'], g['q'], g['n'], g['L'], mode))) in self.arows


def reps_for(est_s, a):
    """(warm-up, repetitions) of a point from the estimate of one proof. Long plan: warm-up + 5
    repetitions, no warm-up and 3 repetitions over 10 minutes. Short plan: warm-up + 3 repetitions up to 10 minutes,
    3 repetitions without warm-up up to 30 minutes, one run above."""
    warm = 1 if est_s <= (a.large_secs if a.warmup_secs is None else a.warmup_secs) else 0
    return warm, (a.reps if est_s <= a.large_secs else a.reps_large)


def plan(sweeps, a):
    """Returns a list of groups; a group is the list of proofs of one repetition of one point (plus its audit)."""
    rate = a.sec_per_mcycle / 1e6
    groups = []

    def point(sweep, q, n, L, orgs, variant='full', kind='succinct', audit=None, force=None, warm_orgs=None, scn=None):
        """warm_orgs: the organisations proved in the warm-up (default all; sweep B: one vendor, no audit).
        scn: a scenario file made by the caller (sweep E); by default the one of (n, L)."""
        scn = scn or scenario(n, L)
        ests = {o: estimate(q, scn, o, variant, kind, a) for o in orgs}          # succinct = the protocol's kind
        warm, reps = reps_for(max(ests.values()), a)
        if force:                         # (warm-up, repetitions); None keeps the value from the estimate
            warm, reps = (warm if force[0] is None else force[0]), (reps if force[1] is None else force[1])
        extra = 0.0
        if audit == 'aggregate':          # the aggregation guest's own cycles, its lifts and joins, one resolve per assumption
            m = json.loads(run(['agg-exec', '--stmt', stmt(q), '--scenario', scn])[0])
            extra = m['padded_cycles'] * rate + (2 * m['segments'] - 1 + m['n_inputs']) * a.recursion_s
        for rep in range(0 if warm else 1, reps + 1):
            these = orgs if rep or warm_orgs is None else warm_orgs
            jobs = [dict(sweep=sweep, rep=rep, q=q, n=n, L=L, org=o, variant=variant, kind=kind, scn=scn, est_s=ests[o],
                         out=f'{a.run_dir}/receipts/{sweep}_n{n}_L{L}_{q}_{kind}/rep{rep}/{o}.receipt') for o in these]
            groups.append(dict(sweep=sweep, rep=rep, q=q, n=n, L=L, jobs=jobs, scn=scn,
                               audit=audit if these == orgs else None, extra_est=extra if these == orgs else 0.0))

    def vendors_of(n, L):
        return [o for o in json.load(open(scenario(n, L)))['participants']]

    for s in sweeps:
        if s == 'A':
            for L in a.A_lengths:
                for q in a.A_stmts:
                    point('A', q, 1, L, ['vendor01'])
        elif s == 'B':
            for i, n in enumerate(a.B_vendors):
                orgs = vendors_of(n, a.B_L)
                # the warm-up proves one vendor only (the proofs of a point are alike); 'once': only at the first point
                warm = None if a.B_warmup == 'each' else int(a.B_warmup == 'once' and i == 0)
                force = (warm, a.B_reps)
                point('B', 'Q3', n, a.B_L, orgs, audit='per-org', force=force, warm_orgs=[o for o in orgs if o != 'maintainer'][:1])
        elif s == 'C':
            for L in a.C_lengths:
                for variant in ('chain', 'iface'):   # the 'full' variant is the point of sweep A (same input)
                    point('C', 'Q2', 1, L, ['vendor01'], variant=variant)
        elif s == 'D':
            for n in a.D_vendors:
                point('D', 'Q2', n, a.B_L, vendors_of(n, a.B_L), audit='aggregate', force=(0, a.D_reps))
        elif s == 'K':
            for L in a.K_lengths:
                for kind in ('composite', 'succinct'):
                    point('K', 'Q2', 1, L, ['vendor01'], kind=kind)
        elif s == 'E':
            for L in a.E_lengths:
                for size in a.E_sizes:       # the sweep name carries the filler size, so every point has its own rows
                    point(f'E{size}', 'Q2', 1, L, ['vendor01'], scn=scenario_filler(L, size))
    return groups


def prove(j):
    args = ['prove', '--stmt', stmt(j['q']), '--scenario', j['scn'], '--org', j['org'], '--variant', j['variant'], '--kind', j['kind']]
    os.makedirs(os.path.dirname(j['out']), exist_ok=True)
    args += ['--out', j['out']]
    if COLD and not drop_caches():
        raise RuntimeError('--cold: the page cache cannot be dropped (run as root or allow passwordless sudo)')
    txt, wall, rss = run(args)
    m = json.loads(txt.strip().splitlines()[-1])
    m.update(peak_rss_mb=round(rss, 1), wall_s=round(wall, 2))
    # the protocol's receipt: succinct and finished by join.zkr (prove_org splits a one-segment slice); a row of
    # another kind or recursion program would not measure the protocol, so stop before it is recorded
    if m['receipt_kind'] != j['kind'] or (j['kind'] == 'succinct' and m['control_program'] != 'join.zkr'):
        raise RuntimeError(f'{j["sweep"]} {j["q"]} n={j["n"]} L={j["L"]} {j["org"]}: requested {j["kind"]}, got '
                           f'{m["receipt_kind"]} finished by {m["control_program"]} (expected join.zkr): not recorded')
    return m


def dry_run(groups, a):
    tot = {}
    log(f'{"sweep":<5}{"stmt":<5}{"n":>3}{"L":>6} {"variant":<6}{"kind":<10}{"rep":>4}{"proofs":>7}{"est/proof [s]":>15}{"est group [min]":>17}')
    last = None
    for g in groups:
        est = sum(j['est_s'] for j in g['jobs']) + g.get('extra_est', 0)
        j0 = g['jobs'][0]
        tot[g['sweep']] = tot.get(g['sweep'], 0) + est
        extra = ' (warm-up, discarded)' if g['rep'] == 0 else ''
        log(f'{g["sweep"]:<5}{g["q"]:<5}{g["n"]:>3}{g["L"]:>6} {j0["variant"]:<6}{j0["kind"]:<10}{g["rep"]:>4}{len(g["jobs"]):>7}'
            f'{est / len(g["jobs"]):>15.0f}{est / 60:>17.1f}{extra}')
    log(f'estimates use {a.sec_per_mcycle} s per million padded cycles and {a.recursion_s} s per recursion proof of a '
        f'succinct receipt (measured on the author\'s WSL machine; calibrate for yours, MEASURE.md section 2)')
    for s, t in tot.items():
        log(f'sweep {s}: about {t / 3600:.1f} h')
    log(f'total: about {sum(tot.values()) / 3600:.1f} h (plan {a.plan}; {sum(len(g["jobs"]) for g in groups)} proofs '
        f'+ {sum(g["audit"] == "aggregate" for g in groups)} aggregates)')


def execute(groups, st, a):
    secs = {}                                   # wall time per sweep of this invocation -> wall_times.csv
    for g in groups:
        t_group = time.time()
        for j in g['jobs']:
            if st.jkey(j) in st.done and os.path.exists(j['out']):
                continue
            m = prove(j)
            st.add(j, m)
            log(f'{j["sweep"]} {j["q"]} n={j["n"]} L={j["L"]} {j["variant"]}/{j["kind"]} rep {j["rep"]} {j["org"]}: cycles {m["cycles"]} '
                f'segments {m["segments"]} prove {m["prove_s"]:.1f} s rss {m["peak_rss_mb"]} MB receipt {m["receipt_bytes"]} B')
        files = [j['out'] for j in g['jobs']]
        if g['audit'] == 'per-org' and not st.has_audit(g, 'per-org'):
            txt, _, _ = run(['audit', '--stmt', stmt(g['q']), '--scenario', public(g['scn']), '--receipts'] + files)
            r = json.loads(txt)
            assert r['ok'], r
            st.add_audit(g, 'per-org', r['audit_s'], r['receipts'])
            log(f'   audit rep {g["rep"]}: {r["audit_s"] * 1000:.0f} ms for {r["receipts"]} receipts -> {r["output"]}')
        if g['audit'] == 'aggregate':
            out = f'{os.path.dirname(files[0])}/aggregate.receipt'
            agg_job = dict(sweep='D', rep=g['rep'], q=g['q'], n=g['n'], L=g['L'], org='aggregator', variant='agg', kind='succinct')
            if not (st.jkey(agg_job) in st.done and os.path.exists(out)):     # resume: an aggregate is proved once
                txt, wall, rss = run(['agg', '--stmt', stmt(g['q']), '--scenario', g['scn'], '--receipts'] + files + ['--out', out])
                m = json.loads(txt.strip().splitlines()[-1])
                m.update(peak_rss_mb=round(rss, 1), wall_s=round(wall, 2), requested_kind='succinct')
                assert not m['leak']['leaks'], m['leak']          # EQ2: the aggregate must not carry organisation journals
                st.add(agg_job, m)
                log(f'   aggregation rep {g["rep"]}: cycles {m["cycles"]} prove {m["prove_s"]:.1f} s rss {m["peak_rss_mb"]} MB '
                    f'{m["receipt_kind"]}/{m["control_program"]}')
            if not st.has_audit(g, 'aggregate'):
                txt, _, _ = run(['audit-agg', '--stmt', stmt(g['q']), '--scenario', public(g['scn']), '--agg', out])
                r = json.loads(txt)
                assert r['ok'], r                             # check 1 includes succinct + resolve.zkr
                st.add_audit(g, 'aggregate', r['audit_s'], 1)
            if not st.has_audit(g, 'per-org'):
                txt, _, _ = run(['audit', '--stmt', stmt(g['q']), '--scenario', public(g['scn']), '--receipts'] + files)
                r = json.loads(txt)
                assert r['ok'], r
                st.add_audit(g, 'per-org', r['audit_s'], r['receipts'])
        secs[g['sweep']] = secs.get(g['sweep'], 0.0) + time.time() - t_group
    path = f'{a.run_dir}/wall_times.csv'          # one row per sweep and invocation; a resumed sweep adds its own time
    new = not os.path.exists(path)
    with open(path, 'a', newline='') as f:
        w = csv.writer(f)
        if new:
            w.writerow(['utc', 'sweep', 'wall_s', 'cold'])
        for s, t in secs.items():
            w.writerow([time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), s, round(t, 1), int(COLD)])


# Presets (--plan); an option given on the command line overrides the preset. 'short' is the default
# (MEASURE.md: about 9 h on the author's machine), 'long' the full plan (about 46 h).
PLANS = {
    'short': dict(reps=3, reps_large=1, large_secs=1800, warmup_secs=600, A_lengths=[8, 32, 128, 512, 2048],
                  A_stmts=['Q2'], B_reps=1, B_warmup='once', C_lengths=[128], K_lengths=[128], D_reps=1, D_vendors=[2, 8],
                  E_lengths=[128], E_sizes=[256, 1024]),
    'long': dict(reps=5, reps_large=3, large_secs=600, warmup_secs=None, A_lengths=[8, 32, 128, 512, 2048],
                 A_stmts=['Q2', 'Q4'], B_reps=None, B_warmup='each', C_lengths=[128, 2048], K_lengths=[128, 512],
                 D_reps=3, D_vendors=[2, 8, 16], E_lengths=[128, 512], E_sizes=[256, 1024]),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('sweeps', nargs='+', choices=['A', 'B', 'C', 'D', 'K', 'E'])
    ap.add_argument('--plan', choices=list(PLANS), default='short',
                    help='preset of repetitions and points (short: about 9 h, long: about 46 h on the author\'s machine)')
    ap.add_argument('--run-dir', default=f'{ROOT}/runs/bench')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--sec-per-mcycle', type=float, default=265.0, help='planning rate, seconds per million padded cycles')
    ap.add_argument('--recursion-s', type=float, default=37.0,
                    help='planning rate, seconds per recursion proof (lift, join, resolve) of a succinct receipt; 37 s on '
                         "the author's machine: L=8, 3 segments, succinct 291 s against composite 104 s, 5 recursion proofs")
    ap.add_argument('--reps', type=int, help='repetitions of a point')
    ap.add_argument('--reps-large', type=int, help='repetitions when one run is estimated over --large-secs')
    ap.add_argument('--large-secs', type=float)
    ap.add_argument('--warmup-secs', type=float, help='warm-up only when one run is estimated at most this (default: --large-secs)')
    ap.add_argument('--A-lengths', type=int, nargs='+')
    ap.add_argument('--A-stmts', nargs='+')
    ap.add_argument('--B-vendors', type=int, nargs='+', default=[1, 2, 4, 8, 16])
    ap.add_argument('--B-L', type=int, default=32)
    ap.add_argument('--B-reps', type=int, help='repetitions of every B point (default: from the estimate)')
    ap.add_argument('--B-warmup', choices=['each', 'once', 'none'], help='warm-up of one vendor at each point, at the first only, or none')
    ap.add_argument('--C-lengths', type=int, nargs='+')
    ap.add_argument('--K-lengths', type=int, nargs='+')
    ap.add_argument('--D-reps', type=int)
    ap.add_argument('--D-vendors', type=int, nargs='+')
    ap.add_argument('--E-lengths', type=int, nargs='+', help='slice lengths of sweep E (record size)')
    ap.add_argument('--E-sizes', type=int, nargs='+', help='filler bytes of the internal records in sweep E (record = 31 + this)')
    ap.add_argument('--cold', action='store_true',
                    help='drop the page cache before every proof, and record it (wall_times.csv, commands.log)')
    a = ap.parse_args()
    global COLD
    COLD = a.cold
    for k, v in PLANS[a.plan].items():
        if getattr(a, k) is None:
            setattr(a, k, v)
    a.run_dir = os.path.abspath(a.run_dir)
    groups = plan(a.sweeps, a)
    if a.dry_run:
        dry_run(groups, a)
        return
    prev = f'{a.run_dir}/env.json'
    if os.path.exists(prev):                                  # resuming: rows of two guest binaries must not mix
        try:
            old = json.load(open(prev)).get('guest_image_ids')
            new = json.loads(subprocess.run([HOST, 'env'], capture_output=True, text=True).stdout).get('guest_image_ids')
        except (OSError, ValueError):
            old = new = None
        if old and new and old != new:
            sys.exit(f'{a.run_dir} was measured with other guest binaries (image ids differ from this build): use another --run-dir')
    if a.cold and not drop_caches():
        sys.exit('--cold needs root or passwordless sudo to drop the page cache (echo 3 > /proc/sys/vm/drop_caches)')
    envinfo.write(a.run_dir)                                  # aborts if dev mode is on
    with open(f'{a.run_dir}/commands.log', 'a') as f:          # which plan and options produced the rows
        f.write(json.dumps({'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'argv': sys.argv[1:],
                            'resolved': {k: (os.path.relpath(v, ROOT) if k == 'run_dir' else v)   # no machine paths
                                         for k, v in vars(a).items() if k != 'dry_run'}}) + '\n')
    log(f'run directory {a.run_dir} (plan {a.plan})')
    execute(groups, Store(a.run_dir), a)
    log('done')


if __name__ == '__main__':
    main()