#!/usr/bin/env python3
"""EQ1 beyond the fixed vectors: differential test of the zkVM guest and the auditor against the reference evaluator.

The acceptance test (acceptance.sh) compares the prototype with 15 fixed scenario x statement pairs. This script
compares it, in the zkVM executor, with the semantics of Chapter 3 computed directly (audit_ref.rank / settled /
ltlf_holds, no automaton) on many more inputs:

  R  random CVD runs: 1-4 vendors with random internal records before, between and after the deadlines, random
     serving order, some without ack, some not closed; statements Q1-Q5
  G  random reparation chains (audit_ref.random_chain, as in the Section 4.4 self-check) compiled with the
     reference compiler into monitor tables the guest has never seen, on random CVD runs
  S  the scaled scenarios of the cost sweeps (n = 1..16 vendors, L = 8..2048), Q1-Q5

For every run three things are compared: (1) each journal with the Python table-driven guest of vectors.py,
field by field; (2) each vendor's verdict (open if not settled) with the semantics; (3) the auditor's output
(checks 2-7 on the journals) with the declared output computed from the semantics.

  scripts/eq1_diff.py [--runs 120] [--chains 30] [--per-chain 15] [--seed 2026] [--out results/eq1_diff.json]
Exit status 0 iff nothing differs."""
import argparse, json, os, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evalkit as K  # noqa: E402
import bench         # noqa: E402

POOL = [{'type': 'patch', 'coverage': 'full'}, {'type': 'patch', 'coverage': 'partial'}, {'type': 'mitigation'},
        {'type': 'advisory'}, {'type': 'work', 'i': 0}, {'type': 'triage', 'affected_products': 1}]


def random_plan(rng):
    pick = lambda k: [rng.choice(POOL) for _ in range(rng.randint(0, k))]
    # the reparation of N_patch needs a mitigation or patch right after the disclosure; seed it often enough that
    # repaired slices are not rare
    head = rng.choice([[], [], [POOL[2]], [POOL[2], POOL[0]], [POOL[0]]])
    p = {'pre': pick(3), 'mid': head + pick(2), 'post': pick(2), 'ack': rng.random() > 0.1}
    if rng.random() < 0.2: p['first'] = pick(2)                      # internal records before the first message
    if rng.random() < 0.07: p['disclose'] = False                    # no deadline ever arrives (rank-0 open)
    if rng.random() < 0.07: p['repeat'] = rng.choice(['disclosure', 'grace_end'])   # a deadline twice
    return p


def random_run(rng, tag, secret=False):
    n = rng.randint(1, 4)
    plans = {f'vendor{chr(65 + i)}': random_plan(rng) for i in range(n)}
    order = list(plans); rng.shuffle(order)
    close = rng.random() > 0.15
    serve = rng.choice(['phased', 'per-vendor'])
    inst = f'EQ1-{tag}'
    slices, parts = K.run_cvd(inst, plans, order, close, serve, secret)
    return K.scenario_of(inst, inst, slices, parts)


def multi_norm_statements():
    """Statements with two norms (Def. 3.9: the organisation's verdict is the minimum, open if any norm is open)."""
    n = {q: K.GOLDEN[q]['norms'][0] for q in ('Q1', 'Q2', 'Q4', 'Q5')}
    return {'M1': K.statement('M1 embargo+patch', [n['Q1'], n['Q2']], 'verdict+responsible'),
            'M2': K.statement('M2 patch+ack', [n['Q2'], n['Q4']], 'verdict'),
            'M3': K.statement('M3 embargo+patch+cover', [n['Q1'], n['Q2'], n['Q5']], 'verdict+responsible')}


class Diff:
    def __init__(self):
        self.runs = self.journals = self.verdicts = self.audits = 0
        self.mismatches = []
        self.by_part = {}

    def check(self, part, stmt, scn, stmt_path, scn_path, expected_audit=None):
        got = K.host('exec-all', '--stmt', stmt_path, '--scenario', scn_path)
        self.runs += 1
        c = self.by_part.setdefault(part, {'runs': 0, 'journals': 0, 'vendor_verdicts': 0, 'audits': 0,
                                           'verdicts_seen': {}})
        c['runs'] += 1
        bad = []
        for org, entries in scn['slices'].items():
            g = got['orgs'][org]
            try:
                want = K.canonical_journal(K.V.guest(stmt, scn['instance'], scn['participants'], org, entries, scn['genesis_salts'][org]))
            except K.P.GuestAbort as e:
                want = {'aborted': str(e)}
            if 'aborted' in want or 'aborted' in g:
                if ('aborted' in want) != ('aborted' in g):
                    bad.append(f'{org}: abort differs: zkVM {g.get("aborted")} / reference {want.get("aborted")}')
                continue
            self.journals += 1; c['journals'] += 1
            if g['journal'] != want:
                bad.append(f'{org}: journal differs from the reference guest')
            if scn['participants'][org] == 'vendor':
                recs = K.records(scn, org)
                sem = K.reference_org_verdict(stmt, recs)
                mon = g['journal']['verdict'] if g['journal']['settled'] else 'open'
                self.verdicts += 1; c['vendor_verdicts'] += 1
                c['verdicts_seen'][sem] = c['verdicts_seen'].get(sem, 0) + 1
                if mon != sem:
                    bad.append(f'{org}: verdict {mon}, semantics {sem}')
                # Theorem 4.1 on every slice, settled or not: the settled flag, and the verdict when settled (an
                # organisation that is not settled outputs no verdict)
                cur, done = K.reference_org_state(stmt, recs)
                state = (cur if done else None, done)
                if (g['journal']['verdict'], g['journal']['settled']) != state:
                    bad.append(f'{org}: state {(g["journal"]["verdict"], g["journal"]["settled"])}, semantics {state}')
        if got['audit'] is not None:
            want = expected_audit or K.reference_audit(stmt, scn)
            self.audits += 1; c['audits'] += 1
            if got['audit'] != want:
                bad.append(f'audit {got["audit"]}, expected {want}')
        if bad:
            self.mismatches.append({'part': part, 'statement': stmt['name'], 'scenario': scn['name'], 'problems': bad,
                                    'scenario_file': scn_path})
            print('MISMATCH', part, stmt['name'], scn['name'], bad[:3], flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', type=int, default=120)
    ap.add_argument('--chains', type=int, default=30)
    ap.add_argument('--per-chain', type=int, default=15)
    ap.add_argument('--seed', type=int, default=2026)
    ap.add_argument('--skip-scaled', action='store_true')
    ap.add_argument('--out', default=f'{K.ROOT}/results/eq1_diff.json')
    a = ap.parse_args()
    rng = random.Random(a.seed)
    d = Diff()
    t0 = time.time()
    gpath = {q: f'{K.REF}/vectors/statements/{q}.json' for q in K.GOLDEN}

    print('== V: the fixed vectors S1-S3 x Q1-Q5 against the semantics', flush=True)
    for s in ('S1', 'S2', 'S3'):
        p = f'{K.REF}/vectors/scenarios/{s}.json'
        scn = json.load(open(p))
        for q, st in K.GOLDEN.items():
            exp = scn['expected'][q]['audit']
            if exp != K.reference_audit(st, scn):
                d.mismatches.append({'part': 'V', 'statement': q, 'scenario': s,
                                     'problems': ['vectors.py expected output differs from the semantics']})
            d.check('V', st, scn, gpath[q], p, expected_audit=exp)

    multi = multi_norm_statements()
    mpath = {k: K.dump(st, f'{K.WORK}/eq1/{k}.stmt.json') for k, st in multi.items()}
    print(f'== R: {a.runs} random CVD runs x Q1-Q5 and three two- or three-norm statements', flush=True)
    for i in range(a.runs):
        scn = random_run(rng, f'R{i}')
        p = K.dump(scn, f'{K.WORK}/eq1/R{i}.json')
        for q, st in K.GOLDEN.items():
            d.check('R', st, scn, gpath[q], p)
        for k, st in multi.items():
            d.check('R', st, scn, mpath[k], p)

    print(f'== G: {a.chains} random reparation chains x {a.per_chain} random runs', flush=True)
    # as the Section 4.4 self-check, plus two well-typed data atoms (a number and a string comparison)
    conds = [K.R.PATCH, K.R.MITIG, K.R.ADVIS, K.R.DISC, K.R.GRACE, K.R.Ev('patch'), K.R.COr(K.R.MITIG, K.R.PATCH),
             K.R.CNot(K.R.DISC), K.R.Ev('triage', (('affected_products', '>=', 2),)),
             K.R.Ev('patch', (('coverage', '!=', 'full'),))]
    states = []
    for c in range(a.chains):
        ch = K.R.random_chain(rng, conds)
        name = f'rand{c}'
        K.CHAINS[name] = ch
        norm = K.V.chain_norm(name, ch)
        states.append(len(norm['out']))
        st = K.statement(f'G{c}', [norm])
        sp = K.dump(st, f'{K.WORK}/eq1/G{c}.stmt.json')
        for i in range(a.per_chain):
            scn = random_run(rng, f'G{c}-{i}')
            d.check('G', st, scn, sp, K.dump(scn, f'{K.WORK}/eq1/G{c}-{i}.json'))

    if not a.skip_scaled:
        points = [(n, 32) for n in (1, 2, 4, 8, 16)] + [(4, L) for L in (8, 128, 512)] + [(1, 2048)]
        print(f'== S: scaled scenarios {points} x Q1-Q5', flush=True)
        for n, L in points:
            p = bench.scenario(n, L)
            scn = json.load(open(p))
            for q, st in K.GOLDEN.items():
                if L == 2048 and q not in ('Q2', 'Q4'):
                    continue
                exp = scn['expected'][q]['audit']
                if exp != K.reference_audit(st, scn):         # the vectors themselves agree with the semantics
                    d.mismatches.append({'part': 'S', 'statement': q, 'scenario': scn['name'],
                                         'problems': ['vectors.py expected output differs from the semantics']})
                d.check('S', st, scn, gpath[q], p, expected_audit=exp)

    hist = {'V': 3, 'R': a.runs, 'G': a.chains * a.per_chain, 'S': 0 if a.skip_scaled else 9}
    for part, c in d.by_part.items():
        c['histories'] = hist[part]
        c['mismatches'] = sum(1 for m in d.mismatches if m['part'] == part)
    res = {'seed': a.seed, 'runs': d.runs, 'journals_compared': d.journals, 'vendor_verdicts_compared': d.verdicts,
           'audits_compared': d.audits, 'mismatches': len(d.mismatches), 'by_part': d.by_part,
           'random_chain_monitor_states': {'min': min(states, default=0), 'max': max(states, default=0)},
           'seconds': round(time.time() - t0, 1), 'details': d.mismatches, 'mode': 'zkVM executor (no proofs)'}
    K.dump(res, a.out)
    print(json.dumps({k: v for k, v in res.items() if k != 'details'}, indent=1))
    print('EQ1 differential test', 'PASSED' if not d.mismatches else 'FAILED', '->', a.out)
    sys.exit(1 if d.mismatches else 0)


if __name__ == '__main__':
    main()
