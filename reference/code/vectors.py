"""
Test vectors and scenario generator for the zkVM prototype (thesis ch. 6).

Everything here is derived from the reference model (audit_ref.py, audit_protocol.py) and is meant to be
reproduced bit for bit by the prototype: the same hash encoding, the same record encoding, the same monitor
tables, the same public outputs (journals), the same auditor decisions.

    python3 vectors.py golden  OUTDIR                      # statements, 3 scenarios, attack cases, hash examples
    python3 vectors.py scenario --vendors N --length L --out FILE [--no-close]

The formats are those of the prototype (core/src/lib.rs).
"""
from __future__ import annotations
import argparse, copy, json, os, sys
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import audit_protocol as P
import audit_ref as R

BEHAVIOURS = ["complied", "repaired", "violated", "leak"]

# ----------------------------------------------------------------------------- monitor tables

def atom_json(ev):
    return {"type": ev.type, "pred": [list(p) for p in ev.pred]}


def table_of(mach, kind, m):
    letters = sorted(mach.letters, key=lambda l: sorted(map(str, l)))
    idx = {l: i for i, l in enumerate(letters)}
    A = len(mach.atoms)
    lom = [idx.get(frozenset(a for i, a in enumerate(mach.atoms) if mask >> i & 1), -1) for mask in range(2 ** A)]
    states = mach.states
    assert states == list(range(len(states)))
    if kind == "chain":
        out = [[mach.out[q][0], mach.out[q][1]] for q in states]
    else:                                   # formula: complied = rank 0, violated = rank 1 (m = 0), always settled
        out = [[0 if mach.out[q] else 1, True] for q in states]
    return {"kind": kind, "m": m, "atoms": [atom_json(a) for a in mach.atoms],
            "letters": [sorted(map(str, l)) or ["other"] for l in letters],
            "letter_of_mask": lom, "init": mach.init,
            "delta": [[mach.delta[(q, l)] for l in letters] for q in states],
            "out": out}


def chain_norm(name, chain):
    return {"name": name, **table_of(R.compile_chain(chain).minimise(), "chain", len(chain.levels) - 1)}


def formula_norm(name, phi):
    return {"name": name, **table_of(R.ltlf_to_dfa(phi).minimise(), "formula", 0)}


# Recording vocabulary of each role: the message kinds it sends or receives (P.SCHEMA) and its internal record types.
INTERNAL_TYPES = {"maintainer": {"report"}, "vendor": {"triage", "work", "patch", "advisory", "mitigation"}}


def vocabulary(role):
    return INTERNAL_TYPES.get(role, set()) | {k for k, (s, r) in P.SCHEMA.items() if role in (s, r)}


def check_local(stmt):
    """Locality: every atom of every norm has an event type that the bearer role records. Otherwise no record of the
    bearer's slice can satisfy the atom, and the verdict is not that of the norm on the run. Raises ValueError."""
    voc = vocabulary(stmt["role"])
    for n in stmt["norms"]:
        foreign = sorted({a["type"] for a in n["atoms"]} - voc)
        if foreign:
            raise ValueError(f"norm {n.get('name', '?')} is not local to role {stmt['role']}: {foreign}")


def statements():
    emb, pat = chain_norm("embargo", R.N_EMBARGO), chain_norm("patch_duty", R.N_PATCH)
    ack, cov = formula_norm("ack", R.PHI_ACK), formula_norm("cover", R.PHI_COVER)
    st = {
        "Q1": {"name": "Q1", "role": "vendor", "disclosure": "verdict", "norms": [emb]},
        "Q2": {"name": "Q2", "role": "vendor", "disclosure": "verdict", "norms": [pat]},
        "Q3": {"name": "Q3", "role": "vendor", "disclosure": "verdict+responsible", "norms": [pat]},
        "Q4": {"name": "Q4", "role": "vendor", "disclosure": "verdict", "norms": [ack]},
        "Q5": {"name": "Q5", "role": "vendor", "disclosure": "verdict+responsible", "norms": [cov]},
    }
    for s in st.values():
        check_local(s)
        s["canonical"] = P.enc(s)                 # the exact bytes the guest receives, hashes and parses
        s["id"] = P.H("statement", s["canonical"])
    return st

# ----------------------------------------------------------------------------- table-driven guest (what the zkVM guest does)

def holds(atom, rec):
    if rec.get("type") != atom["type"]:
        return False
    for f, op, c in atom["pred"]:
        if f not in rec or type(rec[f]) is not type(c):
            return False
        if isinstance(c, str) and op not in ("=", "!="):
            return False
        if not R.OPS[op](rec[f], c):
            return False
    return True


def guest(stmt, instance, participants, org, entries, salt0):
    """entries: list of [encoded_record, salt]; salt0: the genesis salt. Returns the journal (public output) or
    raises P.GuestAbort."""
    role = participants[org]
    h = P.genesis(instance, org, salt0)
    norms = stmt["norms"] if role == stmt["role"] else []
    q = [n["init"] for n in norms]
    iface = []
    for e, salt in entries:
        rec = json.loads(e)
        if rec["type"] in P.SCHEMA and "msg" not in rec:
            raise P.GuestAbort("a shared event was recorded without a hand-off")
        if "msg" in rec:
            s, t = (org, rec["peer"]) if rec["dir"] == "send" else (rec["peer"], org)
            if P.SCHEMA.get(rec["type"]) != (participants.get(s), participants.get(t)):
                raise P.GuestAbort("message kind not allowed between these roles")
            if rec["msg"] != P.iface_commit(instance, s, t, rec["type"], rec["nonce"], rec["body"]):
                raise P.GuestAbort("record type or peer does not match the interface commitment")
            iface.append({"msg": rec["msg"], "dir": rec["dir"], "peer": rec["peer"],
                          "own_pre": h, "peer_pre": rec["peer_head"]})
        h = P.link(h, P.H("rec", salt, e))
        for i, n in enumerate(norms):
            mask = sum(1 << j for j, a in enumerate(n["atoms"]) if holds(a, rec))
            letter = n["letter_of_mask"][mask]
            if letter < 0:
                raise P.GuestAbort("inconsistent letter")
            q[i] = n["delta"][q[i]][letter]
    verdicts = [P.label(n["out"][qi][0], n["m"]) for n, qi in zip(norms, q)]
    settled = all(n["out"][qi][1] for n, qi in zip(norms, q))
    return {"sid": stmt["id"], "instance": instance, "org": org, "pdigest": P.pdigest(participants),
            "head": h, "iface": iface, "verdict": R.aggregate(verdicts) if verdicts and settled else None,
            "settled": settled}

# ----------------------------------------------------------------------------- signatures and the auditor

def keypair(org):
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(P.H("ed25519-seed", org))[:32])
    return sk, sk.public_key().public_bytes_raw().hex()


def publish(instance, org, head):
    sk, pk = keypair(org)
    return {"head": head, "pubkey": pk, "sig": sk.sign((instance + head).encode()).hex()}


def check_heads(instance, heads, published):
    for org, head in heads.items():
        p = published.get(org)
        if p is None or p["head"] != head:
            raise P.Reject(f"check 4: {org}: proof is not about the slice it committed to at closure")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(p["pubkey"])).verify(
                bytes.fromhex(p["sig"]), (instance + head).encode())
        except Exception:
            raise P.Reject(f"check 4: {org}: bad signature on the slice commitment")


def audit(stmt, instance, participants, published, journals):
    """Checks 1-7 of Section 5.3 on a list of journals. Returns the declared output."""
    receipts = [P.Receipt(P.GUEST_ID, P.enc(j)) for j in journals]
    res = P.check(SimpleNamespace(sid=stmt["id"]), instance, participants, receipts)
    check_heads(instance, res["heads"], published)
    if stmt["disclosure"] == "verdict+responsible":
        return {"verdict": res["verdict"], "per_org": res["per_org"]}
    return {"verdict": res["verdict"]}


def aggregate_journal(stmt, instance, participants, journals):
    """Public output of the aggregation guest program (mode 'verdict')."""
    receipts = [P.Receipt(P.GUEST_ID, P.enc(j)) for j in journals]
    res = P.check(SimpleNamespace(sid=stmt["id"]), instance, participants, receipts)
    return {"sid": stmt["id"], "instance": instance, "heads": res["heads"], "verdict": res["verdict"]}

# ----------------------------------------------------------------------------- scenarios

def build(instance, behaviour, length=None, close=True):
    """CVD run. behaviour: vendor -> complied|repaired|violated|leak. length: pad every vendor slice to this
    many records with internal 'work' records placed after the triage."""
    base = {"complied": 6, "repaired": 7, "violated": 5, "leak": 7}
    m = P.Slice(instance, "maintainer")
    vs = {v: P.Slice(instance, v) for v in behaviour}
    m.append({"type": "report"})
    for v, s in vs.items():
        P.exchange(m, s, "notify", "CVE details"); P.exchange(s, m, "ack")
        s.append({"type": "triage", "affected_products": 3})
        if length is not None:
            pad = length - base[behaviour[v]] + (0 if close else 1)
            if pad < 0:
                raise ValueError(f"length must be at least {base[behaviour[v]]}")
            for i in range(pad):
                s.append({"type": "work", "i": i})
    for v, s in vs.items():
        if behaviour[v] == "complied": s.append({"type": "patch", "coverage": "full"})
        if behaviour[v] == "leak": s.append({"type": "advisory"}); s.append({"type": "patch", "coverage": "full"})
    for v, s in vs.items():
        P.exchange(m, s, "disclosure")
    for v, s in vs.items():
        if behaviour[v] == "repaired":
            s.append({"type": "mitigation"}); s.append({"type": "patch", "coverage": "full"})
    if close:
        for v, s in vs.items():
            P.exchange(m, s, "grace_end")
    participants = {"maintainer": "maintainer", **{v: "vendor" for v in vs}}
    return {"maintainer": m, **vs}, participants


def encode(slices):
    return {o: [[P.enc(r), salt] for r, salt in s.entries] for o, s in slices.items()}


def gsalts(slices):
    """The genesis salts (private, part of each slice's private input)."""
    return {o: s.salt0 for o, s in slices.items()}


def reference_verdict(stmt, records):
    """Verdict from the semantics of Ch. 3 directly, without monitors (the 'reference evaluator')."""
    out = []
    for n in stmt["norms"]:
        if n["name"] == "embargo":
            ch = R.N_EMBARGO
        elif n["name"] == "patch_duty":
            ch = R.N_PATCH
        else:
            phi = {"ack": R.PHI_ACK, "cover": R.PHI_COVER}[n["name"]]
            out.append(("complied" if R.ltlf_holds(phi, records) else "violated", True))
            continue
        out.append((R.verdict(ch, records), R.settled(ch, records)))
    if not all(s for _, s in out):
        return "open"
    return R.aggregate([v for v, _ in out])


def scenario(name, instance, behaviour, stmts, length=None, close=True):
    slices, parts = build(instance, behaviour, length, close)
    enc = encode(slices)
    published = {o: publish(instance, o, s.head) for o, s in slices.items()}
    sc = {"format": "cvd-audit-scenario/1", "name": name, "instance": instance, "participants": parts,
          "participants_canonical": P.enc(parts),
          "kinds": {k: list(v) for k, v in P.SCHEMA.items()}, "behaviour": behaviour,
          "length": length, "closed": close, "slices": enc, "genesis_salts": gsalts(slices), "published": published,
          "expected": {}}
    for sname, st in stmts.items():
        journals = {o: guest(st, instance, parts, o, enc[o], slices[o].salt0) for o in slices}
        for o, j in journals.items():                  # EQ1 reference: monitor output == semantics
            if parts[o] == "vendor":
                want = reference_verdict(st, [r for r, _ in slices[o].entries])
                got = j["verdict"] if j["settled"] else "open"
                assert got == want, (name, sname, o, got, want)
        exp = {"journals": journals, "audit": audit(st, instance, parts, published, list(journals.values()))}
        if st["disclosure"] == "verdict":
            exp["aggregate_journal"] = aggregate_journal(st, instance, parts, list(journals.values()))
        sc["expected"][sname] = exp
    return sc, slices

# ----------------------------------------------------------------------------- attack cases

def outcome(fn):
    try:
        return {"accepted": fn()}
    except P.GuestAbort as e:
        return {"rejected_by": "guest", "reason": str(e)}
    except P.Reject as e:
        return {"rejected_by": "auditor", "reason": str(e)}


def reslice(instance, org, records):
    s = P.Slice(instance, org)
    for r in records: s.append(r)
    return s


def attacks(stmts, base_sc, base_slices):
    Q3 = stmts["Q3"]
    inst, parts = base_sc["instance"], base_sc["participants"]
    enc0, pub0, gs = base_sc["slices"], base_sc["published"], base_sc["genesis_salts"]   # a rewritten slice keeps its salt0
    C = [r for r, _ in base_slices["vendorC"].entries]
    i_disc = next(i for i, r in enumerate(C) if r["type"] == "disclosure")
    cases = []

    def run(enc, pub, st=Q3, journals_override=None):
        js = journals_override or [guest(st, inst, parts, o, enc[o], gs[o]) for o in parts]
        return audit(Q3, inst, parts, pub, js)

    def add(name, check, fn, slices=None, published=None, note=""):
        cases.append({"name": name, "statement": "Q3", "expected_check": check, "note": note,
                      "slices_changed": slices or {}, "published_changed": published or {},
                      "expected": outcome(fn)})

    forged = reslice(inst, "vendorC", C[:i_disc] + [{"type": "patch", "coverage": "full"}] + C[i_disc:])
    fe = [[P.enc(r), s] for r, s in forged.entries]
    add("patch back-dated after closure", "5 (and 4)",
        lambda: run({**enc0, "vendorC": fe}, pub0), {"vendorC": fe})
    fp = publish(inst, "vendorC", forged.head)
    add("patch back-dated before closure, rewritten head published", "5",
        lambda: run({**enc0, "vendorC": fe}, {**pub0, "vendorC": fp}), {"vendorC": fe}, {"vendorC": fp})

    col = P.collude(inst, copy.deepcopy(base_slices), "vendorC")
    ce = encode({o: col[o] for o in ("maintainer", "vendorC")})
    cp = {o: publish(inst, o, col[o].head) for o in ("maintainer", "vendorC")}
    add("maintainer and vendor rewrite together", "5, through an honest vendor",
        lambda: run({**enc0, **ce}, {**pub0, **cp}), ce, cp)

    dropped = reslice(inst, "vendorC", [r for r in C if r["type"] != "disclosure"])
    de = [[P.enc(r), s] for r, s in dropped.entries]
    dp = publish(inst, "vendorC", dropped.head)
    add("received message dropped", "5",
        lambda: run({**enc0, "vendorC": de}, {**pub0, "vendorC": dp}), {"vendorC": de}, {"vendorC": dp})

    rel = copy.deepcopy(base_slices["vendorC"].entries)
    for r, _ in rel:
        if r["type"] == "disclosure": r["type"] = "notify"
    re_ = [[P.enc(r), s] for r, s in rel]
    add("disclosure relabelled as another message kind", "guest: interface commitment",
        lambda: run({**enc0, "vendorC": re_}, pub0), {"vendorC": re_})

    add("proof over another vendor's records", "guest: interface commitment",
        lambda: run({**enc0, "vendorC": enc0["vendorA"]}, pub0), {"vendorC": enc0["vendorA"]})

    A = copy.deepcopy(base_slices["vendorA"]); A.append({"type": "advisory"})
    ae = [[P.enc(r), s] for r, s in A.entries]
    add("record appended after closure", "4",
        lambda: run({**enc0, "vendorA": ae}, pub0), {"vendorA": ae})

    def easier():
        js = [guest(Q3, inst, parts, o, enc0[o], gs[o]) for o in parts if o != "vendorC"]
        js.append(guest(stmts["Q1"], inst, parts, "vendorC", enc0["vendorC"], gs["vendorC"]))
        return run(enc0, pub0, journals_override=js)
    add("proof for an easier statement", "2", easier, note="vendorC proves Q1 instead of Q3")

    def withheld():
        js = [guest(Q3, inst, parts, o, enc0[o], gs[o]) for o in parts if o != "vendorC"]
        return run(enc0, pub0, journals_override=js)
    add("one participant withholds its proof", "3", withheld, note="vendorC submits nothing")

    # embargo cases use statement Q1 on a separate small run
    sl, pa = build("K", {"vendorA": "leak"})
    recs = [r for r, _ in sl["vendorA"].entries]
    i_adv = next(i for i, r in enumerate(recs) if r["type"] == "advisory")
    fake = reslice("K", "vendorA", recs[:i_adv] + [{"type": "disclosure"}] + recs[i_adv:])
    fke = [[P.enc(r), s] for r, s in fake.entries]
    cases.append({"name": "local disclosure inserted before an early advisory", "statement": "Q1",
                  "instance": "K", "participants": pa, "expected_check": "guest: no link",
                  "slices_changed": {"vendorA": fke}, "genesis_salts": {"vendorA": fake.salt0},
                  "expected": outcome(lambda: guest(stmts["Q1"], "K", pa, "vendorA", fke, fake.salt0))})

    a, b = P.Slice("L", "vendorA"), P.Slice("L", "vendorB")
    P.exchange(a, b, "disclosure")
    pl = {"maintainer": "maintainer", "vendorA": "vendor", "vendorB": "vendor"}
    be = [[P.enc(r), s] for r, s in b.entries]
    cases.append({"name": "disclosure sent by a vendor", "statement": "Q1", "instance": "L", "participants": pl,
                  "expected_check": "guest: roles", "slices_changed": {"vendorB": be}, "genesis_salts": {"vendorB": b.salt0},
                  "expected": outcome(lambda: guest(stmts["Q1"], "L", pl, "vendorB", be, b.salt0))})

    for c in cases:
        assert "rejected_by" in c["expected"], c["name"]
    return cases


def limit_cases(stmts):
    out = []
    sl, pa = build("M", {"vendorC": "violated"})
    col = P.collude("M", sl, "vendorC")
    enc = encode(col)
    pub = {o: publish("M", o, s.head) for o, s in col.items()}
    js = [guest(stmts["Q3"], "M", pa, o, enc[o], col[o].salt0) for o in pa]
    out.append({"name": "single vendor colludes with the maintainer (known limit: accepted)", "statement": "Q3",
                "instance": "M", "participants": pa, "slices": enc, "genesis_salts": gsalts(col), "published": pub,
                "expected": outcome(lambda: audit(stmts["Q3"], "M", pa, pub, js))})
    assert out[-1]["expected"]["accepted"]["verdict"] == "complied"
    return out

# ----------------------------------------------------------------------------- hash examples

def hash_examples():
    rec = {"type": "patch", "coverage": "full"}
    salt = P.H("salt", "example")
    salt0 = P.H("salt0", "example")
    h0 = P.genesis("CVD-2026-0001", "vendorA", salt0)
    return {
        "H('a')": P.H("a"),
        "H('a','bc')": P.H("a", "bc"),
        "H('ab','c')": P.H("ab", "c"),
        "enc(record)": P.enc(rec),
        "salt": salt,
        "commit = H('rec', salt, enc(record))": P.H("rec", salt, P.enc(rec)),
        "salt0 = H('salt0', 'example')": salt0,
        "genesis = H('slice', 'CVD-2026-0001', 'vendorA', salt0)": h0,
        "link = H('link', genesis, commit)": P.link(h0, P.H("rec", salt, P.enc(rec))),
        "iface = H('iface','I','maintainer','vendorA','disclosure', nonce='n', H('body',''))":
            P.iface_commit("I", "maintainer", "vendorA", "disclosure", "n", ""),
        "pdigest({'maintainer':'maintainer','vendorA':'vendor'})":
            P.pdigest({"maintainer": "maintainer", "vendorA": "vendor"}),
    }

# ----------------------------------------------------------------------------- CLI

def dump(obj, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)


def golden(outdir):
    st = statements()
    for k, s in st.items():
        dump(s, f"{outdir}/statements/{k}.json")
    dump(hash_examples(), f"{outdir}/hash_examples.json")
    s1, sl1 = scenario("S1 running example", "CVD-2026-0001",
                       {"vendorA": "complied", "vendorB": "repaired", "vendorC": "violated"}, st)
    s2, _ = scenario("S2 embargo broken", "CVD-2026-0002", {"vendorA": "leak", "vendorB": "complied"}, st)
    s3, _ = scenario("S3 not closed", "CVD-2026-0003",
                     {"vendorA": "complied", "vendorB": "repaired", "vendorC": "violated"}, st, close=False)
    for name, sc in (("S1", s1), ("S2", s2), ("S3", s3)):
        dump(sc, f"{outdir}/scenarios/{name}.json")
    dump({"base_scenario": "S1", "cases": attacks(st, s1, sl1) + limit_cases(st)}, f"{outdir}/attacks.json")
    summary = {n: {q: s["expected"][q]["audit"] for q in st} for n, s in (("S1", s1), ("S2", s2), ("S3", s3))}
    dump(summary, f"{outdir}/expected_summary.json")
    print(json.dumps(summary, indent=1))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("golden"); g.add_argument("outdir")
    s = sub.add_parser("scenario")
    s.add_argument("--vendors", type=int, required=True)
    s.add_argument("--length", type=int, required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--no-close", action="store_true")
    sub.add_parser("locality")
    a = ap.parse_args()
    if a.cmd == "golden":
        golden(a.outdir)
    elif a.cmd == "locality":
        st = statements()                       # raises if a golden statement is not local
        bad = {"name": "X", "role": "vendor", "norms": [formula_norm("vendor_reports", R.F(R.At(R.Ev("report"))))]}
        try:
            check_local(bad)
            sys.exit("FAIL: a vendor norm on the maintainer's report event was accepted")
        except ValueError as e:
            print(f"ok: {', '.join(st)} are local; rejected: {e}")
    else:
        beh = {f"vendor{i + 1:02d}": BEHAVIOURS[i % 4] for i in range(a.vendors)}
        sc, _ = scenario(f"n={a.vendors} L={a.length}", f"CVD-n{a.vendors}-L{a.length}", beh, statements(),
                         a.length, not a.no_close)
        dump(sc, a.out)
        print(a.out, {q: sc["expected"][q]["audit"]["verdict"] for q in sc["expected"]})


if __name__ == "__main__":
    main()
