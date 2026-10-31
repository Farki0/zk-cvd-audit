#!/usr/bin/env python3
"""The stated coalition limit (threat model of the thesis), tested in both directions (executor + Rust auditor).

The limit: a rewrite by the maintainer and a vendor goes through whenever the maintainer exchanged no message with an
honest party after that vendor's hand-off being rewritten; since the maintainer chooses the serving order, this is
not restricted to a single vendor or to the time after the disclosure. The fixed vectors contain one case of each
side (the single-vendor limit case, and the rewrite exposed by an honest vendor). This script enumerates:

  n = 1, 2, 3 vendors; the colluding vendor in every serving position; two serving schedules (phased: all
  disclosures, then all grace_ends, as in vectors.py; per-vendor: disclosure and grace_end of one vendor before the
  next); two rewrites:
    disclosure  the colluder (violated, no patch) gets a full patch inserted before its disclosure -> fulfilled
    grace_end   the colluder (mitigated, never patched) gets a full patch inserted before its grace_end -> repaired

The honest vendors patch in time. The maintainer and the colluder recompute their chains and the heads they stored
for each other (as audit_protocol.collude, generalised to any insertion point and any number of vendors); the
honest vendors' slices stay as recorded. The prediction is computed from the limit's condition on record positions only,
without any hash: accepted iff no maintainer record with an honest peer follows the first maintainer record that
stores a rewritten head of the colluder. The prototype's outcome (Q3, checks 1-7) must match the prediction, and
an accepted rewrite must report the false verdict.

  scripts/collusion.py [--out results/collusion.json]"""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evalkit as K  # noqa: E402

P = K.P
PATCH = {'type': 'patch', 'coverage': 'full'}


def rewrite(instance, slices, vendor, before):
    """Insert a full patch into the vendor's slice right before its `before` message record; re-chain the vendor and
    the maintainer and update the heads each stored for the other, to a fixed point."""
    v_recs = [dict(r) for r, _ in slices[vendor].entries]
    i = next(i for i, r in enumerate(v_recs) if r['type'] == before)
    v_recs = v_recs[:i] + [dict(PATCH)] + v_recs[i:]
    m_recs = [dict(r) for r, _ in slices['maintainer'].entries]

    def chain(org, recs):
        s = P.Slice(instance, org)
        for r in recs: s.append(r)
        return s
    for _ in range(len(v_recs) + len(m_recs)):
        nv, nm = chain(vendor, v_recs), chain('maintainer', m_recs)
        hv = {r['msg']: h for (r, _), h in zip(nv.entries, P.pre_heads(nv)) if 'msg' in r}
        hm = {r['msg']: h for (r, _), h in zip(nm.entries, P.pre_heads(nm)) if 'msg' in r}
        for r in v_recs:
            if 'msg' in r: r['peer_head'] = hm[r['msg']]
        for r in m_recs:
            if 'msg' in r and r['peer'] == vendor: r['peer_head'] = hv[r['msg']]
    return {**slices, vendor: chain(vendor, v_recs), 'maintainer': chain('maintainer', m_recs)}, i


def predict(slices, vendor, inserted_at):
    """The limit on positions: the first colluder message at or after the insertion point is the rewritten hand-off; the
    maintainer's record of it is the first maintainer record that changes."""
    v_msgs = [r['msg'] for r, _ in slices[vendor].entries[inserted_at:] if 'msg' in r]
    m = [r for r, _ in slices['maintainer'].entries]
    first = next(i for i, r in enumerate(m) if r.get('msg') == v_msgs[0])
    later_honest = [r['type'] + '->' + r['peer'] for r in m[first + 1:] if 'msg' in r and r['peer'] != vendor]
    return not later_honest, later_honest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=f'{K.ROOT}/results/collusion.json')
    a = ap.parse_args()
    t0 = time.time()
    st = {**K.GOLDEN['Q3'], '_path': f'{K.REF}/vectors/statements/Q3.json'}
    rows, bad = [], 0
    for n in (1, 2, 3):
        vendors = [f'vendor{chr(65 + i)}' for i in range(n)]
        for pos in range(n):
            colluder = vendors[pos]
            for serve in ('phased', 'per-vendor'):
                if n == 1 and serve == 'per-vendor':
                    continue                          # identical to phased with one vendor
                for target in ('disclosure', 'grace_end'):
                    honest = {v: {'pre': [dict(PATCH)]} for v in vendors if v != colluder}
                    col = {} if target == 'disclosure' else {'mid': [{'type': 'mitigation'}]}
                    plans = {**honest, colluder: col}
                    inst = f'COAL-n{n}-p{pos}-{serve}-{target}'
                    sl, parts = K.run_cvd(inst, plans, order=vendors, serve=serve)
                    honest_scn = K.scenario_of(inst + ' honest', inst, sl, parts)
                    before = K.host('exec-all', '--stmt', st['_path'], '--scenario', K.dump(honest_scn, f'{K.WORK}/coalition/{inst}-0.json'))['audit']
                    new, at = rewrite(inst, sl, colluder, target)
                    accepted_pred, why = predict(sl, colluder, at)
                    scn = K.scenario_of(inst, inst, new, parts)
                    got = K.host('exec-all', '--stmt', st['_path'], '--scenario', K.dump(scn, f'{K.WORK}/coalition/{inst}-1.json'))
                    aborted = [o for o, x in got['orgs'].items() if 'aborted' in x]
                    aud = got['audit']
                    accepted = aud is not None and 'rejected' not in aud
                    false_verdict = {'disclosure': 'complied', 'grace_end': 'repaired'}[target]
                    ok = accepted == accepted_pred and not aborted
                    if accepted:
                        ok &= aud['per_org'][colluder] == false_verdict      # the audit reports the false verdict
                    else:
                        ok &= aud is not None and aud['rejected'] == 5         # exposed by an honest vendor at check 5
                    ok &= before['per_org'][colluder] == 'violated'
                    bad += not ok
                    rows.append({'n': n, 'colluder_position': pos + 1, 'serve': serve, 'rewrite_before': target,
                                 'true_verdict': before['per_org'][colluder], 'predicted': 'accepted' if accepted_pred else 'rejected',
                                 'later_honest_messages': why, 'obtained': aud, 'as_predicted': ok})
                    print(f'{"ok  " if ok else "FAIL"} n={n} pos={pos + 1} {serve:<10} before {target:<10} '
                          f'predicted {"accepted" if accepted_pred else "rejected":<8} got '
                          f'{("accepted " + aud["per_org"][colluder]) if accepted else ("check " + str(aud and aud.get("rejected")))}', flush=True)
    acc = [r for r in rows if r['predicted'] == 'accepted']
    res = {'cases': len(rows), 'as_predicted': len(rows) - bad, 'accepted_cases': len(acc),
           'accepted_cases_detail': [{k: r[k] for k in ('n', 'colluder_position', 'serve', 'rewrite_before')} for r in acc],
           'mode': 'zkVM executor + Rust auditor (checks 2-7)', 'rows': rows, 'seconds': round(time.time() - t0, 1)}
    K.dump(res, a.out)
    print(f'{len(rows) - bad} of {len(rows)} collusion cases as the limit predicts; {len(acc)} accepted with a false verdict -> {a.out}')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
