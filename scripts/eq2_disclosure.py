#!/usr/bin/env python3
"""EQ2: does the auditor obtain exactly what the declaration allows? (executor; --prove adds the receipt check)

Definition 3.11 asks for a simulator that computes the auditor's view from the public layer pub(I) and the declared
output out(S, I) alone. The zero-knowledge property covers the proofs themselves (assumption A4); what this script
checks is the part the protocol designs, the public outputs the auditor receives:

  * view: under 'verdict, responsible' (Q3, Q5) the n+1 journals; under 'verdict' (Q1, Q2, Q4) the journal of the
    aggregation guest (agg-exec, executor);
  * simulator: rebuilds that view from pub(I) = (instance, participants, statement id, program id, published slice
    commitments, each organisation's messages with partner and direction, D8) and out(S, I) (computed from the
    semantics), with a placeholder for every hash value;
  * the view must equal the simulation field by field, the hash values must be 64 hex digits, and the hash values
    may be equal only where check 5 makes them equal (the two ends of one hand-off). Every other difference is
    reported as a finding: something the auditor sees that the declaration does not allow.

Further:
  * pairs: two runs with the same public layer and the same declared output but different private data (vendors
    swap behaviours) must give the same view up to the public slice commitments;
  * size: a vendor's journal size against slice length (n = 1, L = 8..2048), less the instance identifier;
  * --prove: real proofs of S1 under Q2 and the aggregate in both receipt kinds; reports whether the receipt the
    auditor receives carries the organisations' journals (tens of minutes on the development machine).

  scripts/eq2_disclosure.py [--random 30] [--prove] [--out results/eq2_disclosure.json]"""
import argparse, json, os, random, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evalkit as K  # noqa: E402
import bench         # noqa: E402
import eq1_diff      # noqa: E402

HASH = re.compile(r'^[0-9a-f]{64}$')
STAR = '<hash>'


def public_layer(st, scn, image_id):
    """pub(I), built without the slices: the messages come from the log recorded at the hand-offs
    (evalkit.run_cvd) or, for the scenarios of vectors.py, from its fixed choreography. Only the partner and the
    direction of each message are public, not the order in which an organisation interleaved its partners, so the
    simulator gets them sorted (the guest's output order, core::sort_iface, with the commitments hidden)."""
    order = scn.get('public_order') or K.choreography_order(scn)
    order = {o: sorted(ms, key=lambda m: (m['peer'], m['dir'])) for o, ms in order.items()}
    return {'sid': st['id'], 'instance': scn['instance'], 'participants': scn['participants'],
            'pdigest': K.P.pdigest(scn['participants']), 'guest_id': image_id,
            'heads': {o: p['head'] for o, p in scn['published'].items()}, 'order': order}


def public_hashes(pub):
    """Hash values anyone can compute from pub(I): the unsalted genesis head H('slice', instance, org) of each
    organisation (the genesis head before it was salted; a regression check), the published slice commitments, the
    participant digest and the statement id."""
    out = {K.P.H('slice', pub['instance'], o): f'unsalted genesis of {o}' for o in pub['participants']}
    out.update({h: f'published head of {o}' for o, h in pub['heads'].items()})
    out[pub['pdigest']] = 'participant digest'
    out[pub['sid']] = 'statement id'
    return out


def simulate(st, pub, out):
    """Sim(pub(I), out(S, I)) for the auditor's view."""
    if st['disclosure'] == 'verdict':
        return {'sid': pub['sid'], 'instance': pub['instance'], 'guest_id': pub['guest_id'],
                'pdigest': pub['pdigest'], 'heads': pub['heads'], 'verdict': out['verdict']}
    view = {}
    for o, role in pub['participants'].items():
        v = out['per_org'].get(o) if role == 'vendor' else None
        view[o] = {'sid': pub['sid'], 'instance': pub['instance'], 'org': o, 'pdigest': pub['pdigest'],
                   'head': pub['heads'][o],
                   'iface': [{**m, 'msg': STAR, 'own_pre': STAR, 'peer_pre': STAR} for m in pub['order'][o]],
                   # an open vendor: the declared output says only 'open', i.e. no verdict and settled = false
                   'verdict': v if v != 'open' else None, 'settled': v != 'open'}
    return view


def masked(view):
    """The view with every hash value inside interface entries replaced by the placeholder."""
    if 'heads' in view:
        return view
    return {o: {**j, 'iface': [{k: (STAR if k in ('msg', 'own_pre', 'peer_pre') else x) for k, x in e.items()}
                               for e in j['iface']]} for o, j in view.items()}


def diff(a, b, path=''):
    if isinstance(a, dict) and isinstance(b, dict):
        out = [f'{path}.{k}: field not in the simulation' for k in a if k not in b]
        out += [f'{path}.{k}: missing' for k in b if k not in a]
        for k in a:
            if k in b: out += diff(a[k], b[k], f'{path}.{k}')
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b): return [f'{path}: {len(a)} entries, simulation {len(b)}']
        return [x for i, (p, q) in enumerate(zip(a, b)) for x in diff(p, q, f'{path}[{i}]')]
    return [] if a == b else [f'{path}: auditor sees {a!r}, simulation from pub(I) and out(S, I) gives {b!r}']


def hash_equalities(view, pub):
    """Equal hash values in the interface entries beyond those check 5 pairs up, and hash values equal to one that
    can be computed from pub(I) (the simulator, drawing random values, would not reproduce either)."""
    if 'heads' in view:
        return []
    known = public_hashes(pub)
    pos, bad = {}, []
    for o, j in view.items():
        for i, e in enumerate(j['iface']):
            for k in ('msg', 'own_pre', 'peer_pre'):
                if not HASH.match(e[k]): return [f'{o}.iface[{i}].{k} is not a hash']
                if e[k] in known:
                    bad.append(f'{o}.iface[{i}].{k}: equals the {known[e[k]]}, computable from pub(I)')
                if k != 'msg':
                    pos.setdefault(e[k], []).append((o, e['msg'], e['dir'], k))
    for h, ps in pos.items():
        if len(ps) == 1: continue
        ok = len(ps) == 2 and ps[0][1] == ps[1][1] and {ps[0][2], ps[1][2]} == {'send', 'recv'} and {ps[0][3], ps[1][3]} == {'own_pre', 'peer_pre'}
        if not ok: bad.append(f'hash {h[:12]}.. occurs at {ps}')
    return bad


def view_of(st, scn_path, scn):
    if st['disclosure'] == 'verdict':
        m = K.host('agg-exec', '--stmt', st['_path'], '--scenario', scn_path)
        return m['journal']
    r = K.host('exec-all', '--stmt', st['_path'], '--scenario', scn_path)
    return {o: x['journal'] for o, x in r['orgs'].items()}


# Findings accepted as known (reported every run, failing it only if new ones appear). Empty since 2026-10-28: the
# two earlier classes are fixed (docs/EVALUATION.md, EQ2): an open vendor's journal carried its current verdict, and
# the unsalted genesis head showed whether an internal record precedes an organisation's first message.
KNOWN = {}


def check(st, scn, scn_path, image_id, rows, findings):
    pub = public_layer(st, scn, image_id)
    out = K.reference_audit(st, scn)
    view = view_of(st, scn_path, scn)
    sim = simulate(st, pub, out)
    probs = diff(masked(view), sim) + hash_equalities(view, pub)
    classes = ({'public': ['sid', 'instance', 'guest_id', 'pdigest', 'heads'], 'declared': ['verdict'], 'hash': []}
               if st['disclosure'] == 'verdict' else
               {'public': ['sid', 'instance', 'org', 'pdigest', 'head', 'iface.dir', 'iface.peer'],
                'declared': ['verdict', 'settled'], 'hash': ['iface.msg', 'iface.own_pre', 'iface.peer_pre']})
    rows.append({'statement': st['name'], 'scenario': scn['name'], 'declaration': st['disclosure'],
                 'view': 'aggregate journal' if st['disclosure'] == 'verdict' else f'{len(view)} journals',
                 'fields': classes, 'declared_output': out, 'equal_to_simulation': not probs, 'problems': probs})
    for p in probs:
        findings.append({'statement': st['name'], 'scenario': scn['name'], 'problem': p})
    return view


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--random', type=int, default=30)
    ap.add_argument('--seed', type=int, default=7)
    ap.add_argument('--prove', action='store_true')
    ap.add_argument('--out', default=f'{K.ROOT}/results/eq2_disclosure.json')
    a = ap.parse_args()
    t0 = time.time()
    image_id = K.host('env')['guest_image_ids']['full']
    stmts = {}
    for q, st in K.GOLDEN.items():
        stmts[q] = {**st, '_path': f'{K.REF}/vectors/statements/{q}.json'}
    rows, findings = [], []

    scns = [(f'{K.REF}/vectors/scenarios/{s}.json') for s in ('S1', 'S2', 'S3')]
    rng = random.Random(a.seed)
    for i in range(a.random):
        # salts and nonces from a CSPRNG: with the reference model's fixed salts the hashes could be recomputed
        scns.append(K.dump(eq1_diff.random_run(rng, f'EQ2-{i}', secret=True), f'{K.WORK}/eq2/R{i}.json'))
    for p in (bench.scenario(2, 32), bench.scenario(8, 32)):
        scns.append(p)
    print(f'== simulation check: {len(scns)} instances x Q1-Q5', flush=True)
    for p in scns:
        scn = json.load(open(p))
        for st in stmts.values():
            check(st, scn, p, image_id, rows, findings)

    print('== same public layer, same declared output, different private data', flush=True)
    pairs = []
    for q in ('Q2', 'Q3'):
        st = stmts[q]
        v = []
        for k, beh in enumerate(({'vendorA': 'violated', 'vendorB': 'complied'}, {'vendorA': 'complied', 'vendorB': 'violated'})):
            plans = {o: ({'pre': [{'type': 'patch', 'coverage': 'full'}]} if b == 'complied' else {}) for o, b in beh.items()}
            sl, parts = K.run_cvd('EQ2-PAIR', plans, secret=True)
            scn = K.scenario_of(f'pair{k}', 'EQ2-PAIR', sl, parts)
            path = K.dump(scn, f'{K.WORK}/eq2/pair{k}.json')
            pub = public_layer(st, scn, image_id)
            vw = view_of(st, path, scn)
            # replace what pub(I) gives anyway (the published slice commitments) before comparing the two views
            if 'heads' in vw: vw = {**vw, 'heads': {o: 'published' for o in vw['heads']}}
            else: vw = {o: {**j, 'head': 'published'} for o, j in masked(vw).items()}
            v.append((vw, K.reference_audit(st, scn)))
        same_out = v[0][1] == v[1][1]
        pairs.append({'statement': q, 'declared_outputs_equal': same_out, 'views_equal_up_to_public': v[0][0] == v[1][0],
                      'expected': 'equal views' if same_out else 'views differ exactly in the declared output'})
    for p in pairs:
        ok = p['views_equal_up_to_public'] == p['declared_outputs_equal']
        p['as_expected'] = ok
        if not ok: findings.append({'statement': p['statement'], 'scenario': 'pair', 'problem': 'pair test: ' + json.dumps(p)})

    print('== journal size against slice length', flush=True)
    size = []
    for L in (8, 32, 128, 512, 2048):
        p = bench.scenario(1, L)
        scn = json.load(open(p))
        m = K.host('exec', '--stmt', stmts['Q2']['_path'], '--scenario', p, '--org', 'vendor01')
        size.append({'L': L, 'journal_bytes': m['journal_bytes'], 'instance_id_bytes': len(scn['instance']),
                     'journal_bytes_less_instance_id': m['journal_bytes'] - len(scn['instance'])})
    const = len({s['journal_bytes_less_instance_id'] for s in size}) == 1
    if not const: findings.append({'statement': 'Q2', 'scenario': 'size', 'problem': 'journal size depends on L'})

    agg = None
    if a.prove:
        agg = prove_leak(stmts['Q2'])
        for kind, r in agg.items():
            if kind == 'succinct' and r['leak']['leaks']:
                findings.append({'statement': 'Q2', 'scenario': 'S1', 'problem': f'succinct aggregate leaks: {r["leak"]}'})

    for f in findings:
        f['class'] = next((c for c, test in KNOWN.items() if test(f['problem'])), 'unexpected')
    kinds = {}
    for f in findings:
        key = re.sub(r'\[\d+\]', '[i]', re.sub(r"'[^']*'", "'..'", f['problem'].split(':')[0]))
        kinds.setdefault(f'{f["statement"]} {key}', []).append(f['scenario'])
    res = {'mode': 'zkVM executor' + (' + real proofs of S1/Q2' if a.prove else ''), 'instances': len(scns),
           'views_checked': len(rows), 'views_equal_to_simulation': sum(r['equal_to_simulation'] for r in rows),
           'pairs': pairs, 'journal_size_vs_L': size, 'journal_size_constant_less_instance_id': const,
           'aggregate_receipt': agg, 'findings': len(findings),
           'findings_by_class': {c: sum(f['class'] == c for f in findings) for c in [*KNOWN, 'unexpected']},
           'views_by_class': {c: len({(f['statement'], f['scenario']) for f in findings if f['class'] == c}) for c in [*KNOWN, 'unexpected']},
           'findings_grouped': {k: {'count': len(v), 'scenarios': sorted(set(v))[:10]} for k, v in kinds.items()},
           'rows': rows, 'seconds': round(time.time() - t0, 1)}
    K.dump(res, a.out)
    print(json.dumps({k: v for k, v in res.items() if k != 'rows'}, indent=1))
    unexpected = [f for f in findings if f['class'] == 'unexpected']
    print('EQ2 disclosure check:', f'{len(findings) - len(unexpected)} known findings ({res["findings_by_class"]}),',
          f'{len(unexpected)} unexpected', '->', a.out)
    sys.exit(1 if unexpected else 0)


def prove_leak(st, org_kind='succinct'):
    """Real proofs of S1 under Q2 (organisation receipts of the protocol's kind), then the aggregate as a composite
    and as a succinct receipt."""
    d = f'{K.ROOT}/runs/eq2-prove'
    os.makedirs(d, exist_ok=True)
    scn_path = f'{K.REF}/vectors/scenarios/S1.json'
    scn = json.load(open(scn_path))
    files = []
    for org in scn['participants']:
        f = f'{d}/{org}.{org_kind}.receipt'
        if not os.path.exists(f):
            m = K.host('prove', '--stmt', st['_path'], '--scenario', scn_path, '--org', org, '--kind', org_kind, '--out', f)
            print('   proved', org, f'{m["prove_s"]:.0f} s', flush=True)
        files.append(f)
    out = {}
    for kind in ('composite', 'succinct'):
        f = f'{d}/aggregate_{kind}_over_{org_kind}.receipt'
        m = K.host('agg', '--stmt', st['_path'], '--scenario', scn_path, '--receipts', *files, '--out', f, '--kind', kind)
        aud = K.host('audit-agg', '--stmt', st['_path'], '--scenario', scn_path, '--agg', f)
        out[kind] = {k: m[k] for k in ('receipt_kind', 'receipt_bytes', 'prove_s', 'cycles', 'verify_s', 'leak')}
        out[kind]['auditor_output'] = aud.get('output')
        print(f'   aggregate {kind}: {m["receipt_bytes"]} B, {m["prove_s"]:.0f} s, leak {m["leak"]}', flush=True)
    return out


if __name__ == '__main__':
    main()
