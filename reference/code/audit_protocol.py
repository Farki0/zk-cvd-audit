"""
Executable model of the audit protocol (thesis ch. 5). NOT zero-knowledge: the "guest" is an ordinary
function and a "receipt" stands for a zkVM proof of its execution. The model fixes WHAT the guest checks
and outputs and WHAT the auditor checks, so the logic can be tested before it is ported to the zkVM.

Stand-ins (replace in the prototype):  prove() -> zkVM proof;  sign()/verify() -> digital signature.

Run:  python3 audit_protocol.py
"""
from __future__ import annotations
import hashlib, hmac, json, copy
from dataclasses import dataclass, field
from audit_ref import (compile_chain, letter_of, aggregate, N_PATCH, N_EMBARGO, ORDER)

# ----------------------------------------------------------------------------- primitives

def H(*parts) -> str:
    h = hashlib.sha256()
    for p in parts:
        b = p.encode() if isinstance(p, str) else p
        h.update(len(b).to_bytes(4, "big")); h.update(b)
    return h.hexdigest()

def enc(rec) -> str: return json.dumps(rec, sort_keys=True, separators=(",", ":"))
def commit(rec, salt) -> str: return H("rec", salt, enc(rec))
def genesis(instance, org, salt0) -> str: return H("slice", instance, org, salt0)   # salt0: private, fresh per slice
def link(head, c) -> str: return H("link", head, c)
def iface_commit(instance, sender, receiver, kind, nonce, body) -> str:
    return H("iface", instance, sender, receiver, kind, nonce, H("body", body))

KEYS = {}                                             # org -> secret (signature stand-in)
def sign(org, msg): return hmac.new(KEYS[org].encode(), msg.encode(), "sha256").hexdigest()
def verify(org, msg, sig): return org in KEYS and hmac.compare_digest(sign(org, msg), sig)

# ----------------------------------------------------------------------------- execution phase

@dataclass
class Slice:
    """One organisation's recorder: a salted commitment per record, hash-chained."""
    instance: str
    org: str
    entries: list = field(default_factory=list)      # [(record, salt)]  -- private
    head: str = ""
    salt0: str = ""                                  # salt of the genesis head -- private, kept with the slice
    def __post_init__(self):
        KEYS.setdefault(self.org, H("key", self.org))
        # without a salt the genesis head H('slice', instance, org) is public, and a first message's pre-head would
        # tell the auditor whether an internal record precedes it; derived like the record salts (a deployment
        # draws it at random)
        self.salt0 = self.salt0 or H("salt0", self.instance, self.org, KEYS[self.org])
        self.head = genesis(self.instance, self.org, self.salt0)
    def append(self, rec):
        salt = H("salt", self.org, str(len(self.entries)), KEYS[self.org])
        self.entries.append((rec, salt))
        self.head = link(self.head, commit(rec, salt))
    def publish(self):                                # at closure: the signed slice commitment
        return {"org": self.org, "head": self.head, "sig": sign(self.org, self.instance + self.head)}

_ctr = [0]
def exchange(sender: Slice, receiver: Slice, kind: str, body: str = ""):
    """Anchored hand-off: the message carries the sender's head, the acknowledgement the receiver's."""
    _ctr[0] += 1
    nonce = H("nonce", str(_ctr[0]))
    k = iface_commit(sender.instance, sender.org, receiver.org, kind, nonce, body)
    s_pre, r_pre = sender.head, receiver.head
    base = {"type": kind, "msg": k, "nonce": nonce, "body": body}
    receiver.append({**base, "dir": "recv", "peer": sender.org, "peer_head": s_pre})
    sender.append({**base, "dir": "send", "peer": receiver.org, "peer_head": r_pre})

# ----------------------------------------------------------------------------- statement

# Message kinds of the choreography: kind -> (sender role, receiver role). Records of these types are shared
# events; they count only if they carry the interface commitment of a real hand-off.
SCHEMA = {"notify": ("maintainer", "vendor"), "ack": ("vendor", "maintainer"),
          "disclosure": ("maintainer", "vendor"), "grace_end": ("maintainer", "vendor")}

def pdigest(participants: dict) -> str: return H("participants", enc(participants))

@dataclass(frozen=True)
class Statement:
    sid: str
    norms: tuple          # ((name, chain), ...) addressed to every organisation with role "vendor"
    disclosure: str       # "verdict" | "verdict+responsible"

MONITORS = {}
def monitors(st: Statement):
    if st.sid not in MONITORS:
        MONITORS[st.sid] = [(n, compile_chain(c).minimise(), len(c.levels) - 1) for n, c in st.norms]
    return MONITORS[st.sid]

def label(rank, m): return "complied" if rank == 0 else ("repaired" if rank <= m else "violated")

# ----------------------------------------------------------------------------- the guest program (Algorithm 5.1)

GUEST_ID = "guest-v1"

class GuestAbort(Exception): pass

def guest(st: Statement, instance: str, participants: dict, org: str, entries: list, salt0: str) -> dict:
    """Private input: entries and the genesis salt. Public output: the returned journal."""
    role = participants[org]
    h = genesis(instance, org, salt0)
    mons = monitors(st) if role == "vendor" else []
    states = [m.init for _, m, _ in mons]
    iface = []
    for rec, salt in entries:
        if rec["type"] in SCHEMA and "msg" not in rec:
            raise GuestAbort("a shared event was recorded without a hand-off")
        if "msg" in rec:                                             # interface record
            s, r = (org, rec["peer"]) if rec["dir"] == "send" else (rec["peer"], org)
            if SCHEMA.get(rec["type"]) != (participants.get(s), participants.get(r)):
                raise GuestAbort("message kind not allowed between these roles")
            if rec["msg"] != iface_commit(instance, s, r, rec["type"], rec["nonce"], rec["body"]):
                raise GuestAbort("record type or peer does not match the interface commitment")
            iface.append({"msg": rec["msg"], "dir": rec["dir"], "peer": rec["peer"],
                          "own_pre": h, "peer_pre": rec["peer_head"]})
        h = link(h, commit(rec, salt))                               # rebuild the slice commitment
        states = [m.delta[(q, letter_of(rec, m.atoms))] for q, (_, m, _) in zip(states, mons)]
    verdicts, is_settled = [], True
    for q, (_, m, lv) in zip(states, mons):
        rank, done = m.out[q]
        verdicts.append(label(rank, lv)); is_settled &= done
    return {"sid": st.sid, "instance": instance, "org": org, "pdigest": pdigest(participants),
            "head": h, "iface": iface,
            # an organisation that is not settled outputs no verdict, only settled = False (Def. 3.10: 'open')
            "verdict": aggregate(verdicts) if verdicts and is_settled else None, "settled": is_settled}

@dataclass(frozen=True)
class Receipt:
    program: str
    journal: str          # canonical JSON; a real receipt is bound to it by the proof
def prove(program, fn, *args) -> Receipt: return Receipt(program, enc(fn(*args)))

# ----------------------------------------------------------------------------- checks on a set of receipts

class Reject(Exception): pass

def check(st, instance, participants: dict, receipts: list) -> dict:
    """Run by the auditor (mode verdict+responsible) or inside the aggregation guest (mode verdict)."""
    js = []
    for r in receipts:
        if r.program != GUEST_ID: raise Reject("wrong guest program")
        j = json.loads(r.journal)
        if j["sid"] != st.sid or j["instance"] != instance: raise Reject("wrong statement or instance")
        if j["pdigest"] != pdigest(participants): raise Reject("proof assumes another participant set")
        js.append(j)
    if sorted(j["org"] for j in js) != sorted(participants):
        raise Reject("full participation fails: the provers are not exactly the participant set")
    send, recv = {}, {}
    for j in js:
        for e in j["iface"]:
            side = send if e["dir"] == "send" else recv
            if e["msg"] in side: raise Reject("interface commitment used twice")
            side[e["msg"]] = (j["org"], e)
    if set(send) != set(recv): raise Reject("interface: a message is missing on one side")
    for k, (s_org, s) in send.items():
        r_org, r = recv[k]
        if s["peer"] != r_org or r["peer"] != s_org: raise Reject("interface: wrong peer")
        if s["own_pre"] != r["peer_pre"] or r["own_pre"] != s["peer_pre"]:
            raise Reject("interface: heads at the hand-off do not match (history rewritten around a message)")
    per_org = {j["org"]: (j["verdict"] if j["settled"] else "open") for j in js if participants[j["org"]] == "vendor"}
    overall = "open" if "open" in per_org.values() else aggregate(per_org.values())
    return {"heads": {j["org"]: j["head"] for j in js}, "per_org": per_org, "verdict": overall}

AGG_ID = "aggregator-v1"
def aggregation_guest(st, instance, participants, receipts) -> dict:
    """Private input: the receipts. Public output: heads and the aggregate verdict only."""
    res = check(st, instance, participants, receipts)
    return {"sid": st.sid, "instance": instance, "heads": res["heads"], "verdict": res["verdict"]}

def check_heads(instance, heads, published):
    for org, head in heads.items():
        p = published.get(org)
        if p is None or p["head"] != head or not verify(org, instance + head, p["sig"]):
            raise Reject(f"{org}: proof is not about the slice it committed to at closure")

def audit(st, instance, participants, published, receipts=None, agg: Receipt = None):
    """Returns (declared output, auditor's view)."""
    if st.disclosure == "verdict+responsible":
        res = check(st, instance, participants, receipts)
        check_heads(instance, res["heads"], published)
        return {"verdict": res["verdict"], "per_org": res["per_org"]}, [json.loads(r.journal) for r in receipts]
    if agg.program != AGG_ID: raise Reject("wrong aggregation program")
    j = json.loads(agg.journal)
    if j["sid"] != st.sid or j["instance"] != instance or sorted(j["heads"]) != sorted(participants):
        raise Reject("aggregate is about another statement, instance or participant set")
    check_heads(instance, j["heads"], published)
    return {"verdict": j["verdict"]}, [j]

# ----------------------------------------------------------------------------- CVD scenarios

def run_cvd(instance, behaviour: dict, close=True):
    """behaviour: vendor -> 'complied' | 'repaired' | 'violated' | 'leak'. Returns (slices, participants)."""
    m = Slice(instance, "maintainer")
    vs = {v: Slice(instance, v) for v in behaviour}
    m.append({"type": "report"})
    for v, s in vs.items():
        exchange(m, s, "notify", "CVE details"); exchange(s, m, "ack")
        s.append({"type": "triage", "affected_products": 3})
    for v, s in vs.items():
        if behaviour[v] == "complied": s.append({"type": "patch", "coverage": "full"})
        if behaviour[v] == "leak": s.append({"type": "advisory"}); s.append({"type": "patch", "coverage": "full"})
    for v, s in vs.items(): exchange(m, s, "disclosure")
    for v, s in vs.items():
        if behaviour[v] == "repaired":
            s.append({"type": "mitigation"}); s.append({"type": "patch", "coverage": "full"})
    if close:
        for v, s in vs.items(): exchange(m, s, "grace_end")
    return {"maintainer": m, **vs}, {"maintainer": "maintainer", **{v: "vendor" for v in vs}}

def pre_heads(sl: Slice):
    """Head before each record of a slice."""
    out, h = [], genesis(sl.instance, sl.org, sl.salt0)
    for rec, salt in sl.entries:
        out.append(h); h = link(h, commit(rec, salt))
    return out

def collude(instance, slices, vendor):
    """The maintainer and one vendor jointly rewrite history: the vendor gets a patch record before the
    disclosure, and both recompute their chains and the heads they stored for each other."""
    V, M = slices[vendor], slices["maintainer"]
    v_recs = [dict(r) for r, _ in V.entries]
    i = next(i for i, r in enumerate(v_recs) if r["type"] == "disclosure")
    v_recs = v_recs[:i] + [{"type": "patch", "coverage": "full"}] + v_recs[i:]
    m_recs = [dict(r) for r, _ in M.entries]
    for _ in range(len(v_recs) + len(m_recs)):                 # iterate to a fixed point of the stored heads
        nv, nm = Slice(instance, vendor), Slice(instance, "maintainer")
        for r in v_recs: nv.append(r)
        for r in m_recs: nm.append(r)
        hv = {r["msg"]: h for (r, _), h in zip(nv.entries, pre_heads(nv)) if "msg" in r}
        hm = {r["msg"]: h for (r, _), h in zip(nm.entries, pre_heads(nm)) if "msg" in r}
        for r in v_recs:
            if "msg" in r: r["peer_head"] = hm[r["msg"]]
        for r in m_recs:
            if "msg" in r and r["peer"] == vendor: r["peer_head"] = hv[r["msg"]]
    nv, nm = Slice(instance, vendor), Slice(instance, "maintainer")
    for r in v_recs: nv.append(r)
    for r in m_recs: nm.append(r)
    return {**slices, vendor: nv, "maintainer": nm}

def receipts_for(st, instance, slices, participants):
    return [prove(GUEST_ID, guest, st, instance, participants, o, s.entries, s.salt0) for o, s in slices.items()]

def expect_reject(name, fn):
    try: fn()
    except (Reject, GuestAbort) as e: print(f"  {name:<46} rejected: {e}"); return
    raise AssertionError(f"{name}: should have been rejected")

def main():
    Q1 = Statement("Q1", (("embargo", N_EMBARGO),), "verdict")
    Q_only = Statement("Q2", (("patch", N_PATCH),), "verdict")
    Q_who = Statement("Q3", (("patch", N_PATCH),), "verdict+responsible")
    Q_all = Statement("Q1+Q3", (("patch", N_PATCH), ("embargo", N_EMBARGO)), "verdict+responsible")
    inst = "CVD-2026-0001"
    beh = {"vendorA": "complied", "vendorB": "repaired", "vendorC": "violated"}
    slices, parts = run_cvd(inst, beh)
    pub = {o: s.publish() for o, s in slices.items()}

    print("1. honest run, declaration 'verdict+responsible'")
    rs = receipts_for(Q_who, inst, slices, parts)
    out, view = audit(Q_who, inst, parts, pub, receipts=rs)
    print("  declared output:", out)
    assert out == {"verdict": "violated", "per_org": beh}
    print("  auditor's view, vendorC journal keys:", sorted(view[3]), "| interface entries:", len(view[3]["iface"]))

    print("2. honest run, declaration 'verdict'")
    rs2 = receipts_for(Q_only, inst, slices, parts)
    agg = prove(AGG_ID, aggregation_guest, Q_only, inst, parts, rs2)
    out2, view2 = audit(Q_only, inst, parts, pub, agg=agg)
    print("  declared output:", out2, "| auditor's view keys:", sorted(view2[0]))
    assert out2 == {"verdict": "violated"}
    # same public layer and same declared output, different culprit: the views have the same shape
    s_alt, _ = run_cvd(inst, {"vendorA": "violated", "vendorB": "complied", "vendorC": "repaired"})
    agg_alt = prove(AGG_ID, aggregation_guest, Q_only, inst, parts, receipts_for(Q_only, inst, s_alt, parts))
    a, b = json.loads(agg.journal), json.loads(agg_alt.journal)
    assert a["verdict"] == b["verdict"] and sorted(a["heads"]) == sorted(b["heads"]) and sorted(a) == sorted(b)
    print("  a run with a different culprit gives a view of the same shape and the same verdict")

    slL, paL = run_cvd("E", {"vendorA": "leak"}); pbL = {o: x.publish() for o, x in slL.items()}
    aggL = prove(AGG_ID, aggregation_guest, Q1, "E", paL, receipts_for(Q1, "E", slL, paL))
    assert audit(Q1, "E", paL, pbL, agg=aggL)[0] == {"verdict": "violated"}
    aggL2 = prove(AGG_ID, aggregation_guest, Q_only, "E", paL, receipts_for(Q_only, "E", slL, paL))
    assert audit(Q_only, "E", paL, pbL, agg=aggL2)[0] == {"verdict": "complied"}
    print("  embargo-breaking slice: Q1 violated, Q2 complied")

    print("3. all verdict combinations for three vendors (statement with both norms)")
    kinds = ["complied", "repaired", "violated", "leak"]
    n = 0
    for x in kinds:
        for y in kinds:
            for z in kinds:
                b3 = {"vendorA": x, "vendorB": y, "vendorC": z}
                sl, pa = run_cvd("I", b3); pb = {o: s.publish() for o, s in sl.items()}
                o3, _ = audit(Q_all, "I", pa, pb, receipts=receipts_for(Q_all, "I", sl, pa))
                want = {v: ("violated" if k == "leak" else k) for v, k in b3.items()}
                assert o3["per_org"] == want and o3["verdict"] == min(want.values(), key=ORDER.get); n += 1
    print(f"  {n} runs, protocol verdict == expected verdict in all")

    print("4. negative tests")
    C = slices["vendorC"]

    def rewrite(pos):                       # vendorC inserts a patch record at position pos and re-chains
        s = Slice(inst, "vendorC")
        ent = [e[0] for e in C.entries]
        for rec in ent[:pos] + [{"type": "patch", "coverage": "full"}] + ent[pos:]: s.append(rec)
        return s
    pos = next(i for i, (r, _) in enumerate(C.entries) if r["type"] == "disclosure")
    forged = rewrite(pos)
    def t_after_closure():
        sl = {**slices, "vendorC": forged}
        audit(Q_who, inst, parts, pub, receipts=receipts_for(Q_who, inst, sl, parts))
    expect_reject("patch back-dated after closure", t_after_closure)
    def t_before_closure():                 # same rewrite, but vendorC publishes the rewritten head
        sl = {**slices, "vendorC": forged}; pb = {**pub, "vendorC": forged.publish()}
        audit(Q_who, inst, parts, pb, receipts=receipts_for(Q_who, inst, sl, parts))
    expect_reject("patch back-dated before closure", t_before_closure)
    def t_drop_message():                   # vendorC pretends it never received the disclosure
        s = Slice(inst, "vendorC")
        for r, _ in C.entries:
            if r["type"] != "disclosure": s.append(r)
        sl = {**slices, "vendorC": s}; pb = {**pub, "vendorC": s.publish()}
        audit(Q_who, inst, parts, pb, receipts=receipts_for(Q_who, inst, sl, parts))
    expect_reject("received message dropped", t_drop_message)
    def t_relabel():                        # vendorC relabels the disclosure record as another message kind
        ent = copy.deepcopy(C.entries)
        for r, _ in ent:
            if r["type"] == "disclosure": r["type"] = "notify"
        guest(Q_who, inst, parts, "vendorC", ent, C.salt0)
    expect_reject("interface record relabelled", t_relabel)
    def t_missing():
        audit(Q_who, inst, parts, pub, receipts=rs[:-1])
    expect_reject("one participant withholds its proof", t_missing)
    def t_wrong_statement():
        easy = Statement("Q1r", (("embargo", N_EMBARGO),), "verdict+responsible")
        mixed = rs[:-1] + [prove(GUEST_ID, guest, easy, inst, parts, "vendorC", C.entries, C.salt0)]
        audit(Q_who, inst, parts, pub, receipts=mixed)
    expect_reject("proof for an easier statement", t_wrong_statement)
    def t_foreign_slice():                  # vendorC proves over vendorA's (compliant) records
        r = prove(GUEST_ID, guest, Q_who, inst, parts, "vendorC", slices["vendorA"].entries, C.salt0)
        audit(Q_who, inst, parts, pub, receipts=rs[:-1] + [r])
    expect_reject("proof over another vendor's records", t_foreign_slice)

    def t_tail():                           # vendorA appends a record after the last hand-off, after closure
        s = copy.deepcopy(slices["vendorA"]); s.append({"type": "advisory"})
        audit(Q_who, inst, parts, pub, receipts=receipts_for(Q_who, inst, {**slices, "vendorA": s}, parts))
    expect_reject("record appended after closure", t_tail)
    def t_fake_deadline():                  # a vendor fakes an early local "disclosure" to legalise a leak
        sl, pa = run_cvd("K", {"vendorA": "leak"})
        ent = [e[0] for e in sl["vendorA"].entries]
        i = next(i for i, r in enumerate(ent) if r["type"] == "advisory")
        s = Slice("K", "vendorA")
        for r in ent[:i] + [{"type": "disclosure"}] + ent[i:]: s.append(r)
        guest(Q_all, "K", pa, "vendorA", s.entries, s.salt0)
    expect_reject("deadline event without a hand-off", t_fake_deadline)
    def t_peer_deadline():                  # two vendors exchange a "disclosure" between themselves
        a, b = Slice("L", "vendorA"), Slice("L", "vendorB")
        exchange(a, b, "disclosure")
        guest(Q_who, "L", {"maintainer": "maintainer", "vendorA": "vendor", "vendorB": "vendor"}, "vendorB", b.entries, b.salt0)
    expect_reject("deadline sent by a non-maintainer", t_peer_deadline)

    def t_collude():                        # maintainer + vendorC rewrite together, before closure
        sl = collude(inst, slices, "vendorC"); pb = {o: x.publish() for o, x in sl.items()}
        audit(Q_who, inst, parts, pb, receipts=receipts_for(Q_who, inst, sl, parts))
    expect_reject("maintainer and vendor rewrite together", t_collude)

    print("   limit: the same collusion when no honest organisation exchanged a later message")
    sl1, pa1 = run_cvd("M", {"vendorC": "violated"})
    sl1 = collude("M", sl1, "vendorC"); pb1 = {o: x.publish() for o, x in sl1.items()}
    o_lim, _ = audit(Q_who, "M", pa1, pb1, receipts=receipts_for(Q_who, "M", sl1, pa1))
    print("   accepted with output:", o_lim)
    assert o_lim["per_org"] == {"vendorC": "complied"}

    print("5. instance not closed (no grace_end): verdict stays open")
    sl, pa = run_cvd("J", beh, close=False); pb = {o: s.publish() for o, s in sl.items()}
    o5, _ = audit(Q_who, "J", pa, pb, receipts=receipts_for(Q_who, "J", sl, pa))
    print("  declared output:", o5)
    assert o5["per_org"] == {"vendorA": "complied", "vendorB": "repaired", "vendorC": "open"} and o5["verdict"] == "open"
    print("all protocol checks passed")

if __name__ == "__main__":
    main()
