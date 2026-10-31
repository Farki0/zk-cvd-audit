#!/usr/bin/env python3
"""Shared helpers of the evaluation scripts (eq1_diff.py, eq2_disclosure.py, collusion.py, cost_extra.py).

The reference code in reference/code is only imported, never changed. Scenarios built here use the same record
encoding, hash chains, hand-offs and Ed25519 publication as reference/code/vectors.py, but let the caller choose the
vendors' records and the maintainer's serving order, which the fixed vectors do not."""
import json, os, secrets, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = f'{ROOT}/reference'
HOST = f'{ROOT}/target/release/host'
WORK = f'{ROOT}/work/eval'
sys.path.insert(0, f'{REF}/code')
sys.dont_write_bytecode = True
import audit_protocol as P  # noqa: E402
import audit_ref as R       # noqa: E402
import vectors as V         # noqa: E402

GOLDEN = {q: json.load(open(f'{REF}/vectors/statements/{q}.json')) for q in ('Q1', 'Q2', 'Q3', 'Q4', 'Q5')}
CHAINS = {'embargo': R.N_EMBARGO, 'patch_duty': R.N_PATCH}
FORMULAS = {'ack': R.PHI_ACK, 'cover': R.PHI_COVER}


def host(*args, check=True):
    """Runs the host binary; returns its stdout parsed as JSON (last line)."""
    p = subprocess.run([HOST, *map(str, args)], capture_output=True, text=True)
    if check and p.returncode not in (0, 3, 4):
        raise RuntimeError(f'host {args[0]} failed ({p.returncode}): {p.stderr[-2000:]}')
    return json.loads(p.stdout.strip().splitlines()[-1])


def dump(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(obj, f, sort_keys=True)
    return path


def statement(name, norms, disclosure='verdict+responsible'):
    """A statement file in the format of reference/vectors/statements (norms from V.chain_norm / V.formula_norm)."""
    s = {'name': name, 'role': 'vendor', 'disclosure': disclosure, 'norms': norms}
    s['canonical'] = P.enc(s)
    s['id'] = P.H('statement', s['canonical'])
    return s


def scenario_of(name, instance, slices, participants):
    """Scenario file (without expected outputs) from P.Slice objects: encoded slices plus signed commitments."""
    sc = {'format': 'cvd-audit-scenario/1', 'name': name, 'instance': instance, 'participants': participants,
          'participants_canonical': P.enc(participants), 'length': None,
          'slices': V.encode(slices), 'genesis_salts': V.gsalts(slices), 'published': {o: V.publish(instance, o, s.head) for o, s in slices.items()}}
    if instance in LOG:
        sc['public_order'] = LOG[instance]          # recorded at the hand-offs (run_cvd), not read from the slices
    return sc


class SecretSlice(P.Slice):
    """A slice whose salts come from a CSPRNG, as in a deployment, not from the reference model's fixed formula
    H('salt', org, i, key), which anyone with the reference code can recompute; the genesis salt too."""
    def __post_init__(self):
        self.salt0 = secrets.token_hex(32)
        super().__post_init__()

    def append(self, rec):
        salt = secrets.token_hex(32)
        self.entries.append((rec, salt))
        self.head = P.link(self.head, P.commit(rec, salt))


LOG = {}


def run_cvd(instance, plans, order=None, close=True, serve='phased', secret=False):
    """A CVD run with free vendor behaviour. plans: vendor -> dict with lists of internal records
    'first' (before the notify), 'pre' (after triage, before the disclosure), 'mid' (between disclosure and
    grace_end), 'post' (after grace_end); 'ack' (bool, default True); 'disclose' (bool, default True; False = the
    maintainer never sends this vendor a disclosure or grace_end); 'repeat' (a deadline kind sent a second time after
    'mid'). order: the maintainer's serving order (default: the order of plans). serve='phased' sends every
    disclosure, then every grace_end (as vectors.py); serve='per-vendor' sends a vendor its disclosure and grace_end
    before serving the next one. secret=True draws salts and nonces from a CSPRNG.
    The public message log of D8 (each organisation's messages in order, with partner and direction) is recorded at
    every hand-off in LOG[instance], independently of the slices."""
    order = list(order or plans)
    S = SecretSlice if secret else P.Slice
    m = S(instance, 'maintainer')
    vs = {v: S(instance, v) for v in plans}
    log = LOG[instance] = {o: [] for o in ['maintainer', *plans]}

    def xch(a, b, kind, body=''):
        if secret:
            nonce = secrets.token_hex(32)
            k = P.iface_commit(a.instance, a.org, b.org, kind, nonce, body)
            s_pre, r_pre = a.head, b.head
            base = {'type': kind, 'msg': k, 'nonce': nonce, 'body': body}
            b.append({**base, 'dir': 'recv', 'peer': a.org, 'peer_head': s_pre})
            a.append({**base, 'dir': 'send', 'peer': b.org, 'peer_head': r_pre})
        else:
            P.exchange(a, b, kind, body)
        log[b.org].append({'dir': 'recv', 'peer': a.org})
        log[a.org].append({'dir': 'send', 'peer': b.org})

    m.append({'type': 'report'})
    for v in order:
        s = vs[v]
        for r in plans[v].get('first', []): s.append(dict(r))
        xch(m, s, 'notify', 'CVE details')
        if plans[v].get('ack', True):
            xch(s, m, 'ack')
        s.append({'type': 'triage', 'affected_products': 3})
        for r in plans[v].get('pre', []): s.append(dict(r))

    def disclose(v):
        if not plans[v].get('disclose', True): return
        xch(m, vs[v], 'disclosure')
        for r in plans[v].get('mid', []): vs[v].append(dict(r))
        if plans[v].get('repeat'): xch(m, vs[v], plans[v]['repeat'])

    def end(v):
        if not plans[v].get('disclose', True): return
        xch(m, vs[v], 'grace_end')
        for r in plans[v].get('post', []): vs[v].append(dict(r))

    if serve == 'phased':
        for v in order: disclose(v)
        if close:
            for v in order: end(v)
    else:
        for v in order:
            disclose(v)
            if close: end(v)
    return {'maintainer': m, **vs}, {'maintainer': 'maintainer', **{v: 'vendor' for v in vs}}


def records(scn, org):
    return [json.loads(e) for e, _ in scn['slices'][org]]


def canonical_journal(j):
    """A reference journal with its interface entries in the guest's output order (core::sort_iface: partner,
    direction, commitment); the reference model lists them in record order."""
    if 'iface' not in j:
        return j
    return {**j, 'iface': sorted(j['iface'], key=lambda e: (e['peer'], e['dir'], e['msg']))}


def norm_semantics(norm, recs):
    """(verdict, settled) of one norm by the semantics of Chapter 3 directly (no monitor): chains by
    Definitions 3.5-3.7 (audit_ref.rank/settled), formulas by LTLf trace semantics (audit_ref.ltlf_holds)."""
    if 'source' in norm:
        ch = norm['source']
    elif norm['name'] in CHAINS:
        ch = CHAINS[norm['name']]
    else:
        return ('complied' if R.ltlf_holds(FORMULAS[norm['name']], recs) else 'violated'), True
    return R.verdict(ch, recs), R.settled(ch, recs)


def reference_org_verdict(stmt, recs):
    out = [norm_semantics(n, recs) for n in stmt['norms']]
    if not all(s for _, s in out):
        return 'open'
    return R.aggregate([v for v, _ in out])


def reference_org_state(stmt, recs):
    """(minimum of the norms' current verdicts, all settled): what Theorem 4.1 says the monitors output on any
    slice, settled or not; compared with the journal's (verdict, settled), whose verdict is None unless settled."""
    out = [norm_semantics(n, recs) for n in stmt['norms']]
    return R.aggregate([v for v, _ in out]), all(s for _, s in out)


def choreography_order(scn):
    """Each organisation's message order for the scenarios of vectors.py, from public data only (participants and
    whether the run was closed): its build() serves the vendors in name order, notify and ack each, then every
    disclosure, then every grace_end."""
    vendors = [o for o, r in scn['participants'].items() if r == 'vendor']
    out = {'maintainer': [], **{v: [] for v in vendors}}

    def msg(a, b):
        out[a].append({'dir': 'send', 'peer': b}); out[b].append({'dir': 'recv', 'peer': a})
    for v in vendors: msg('maintainer', v); msg(v, 'maintainer')
    for v in vendors: msg('maintainer', v)
    if scn.get('closed', True):
        for v in vendors: msg('maintainer', v)
    return out


def reference_audit(stmt, scn):
    """Declared output from the semantics: statement verdict = open if any vendor is open, else the minimum."""
    per = {o: reference_org_verdict(stmt, records(scn, o)) for o, r in scn['participants'].items() if r == 'vendor'}
    vs = list(per.values())
    verdict = 'open' if 'open' in vs else R.aggregate(vs)
    return {'verdict': verdict, 'per_org': per} if stmt['disclosure'] == 'verdict+responsible' else {'verdict': verdict}


# Thesis terminology (WRITING_CONTEXT E): the prototype and the vectors print 'complied'; a chain's rank 0 is
# 'fulfilled', a formula's is 'satisfied'.
def thesis_word(v, formula=False):
    if v == 'complied':
        return 'satisfied' if formula else 'fulfilled'
    return v
