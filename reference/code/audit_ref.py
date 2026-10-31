"""
Reference implementation for the deontic audit-statement language (thesis ch. 3-4).

Contents
  1. Event conditions over single records
  2. LTLf: semantics over finite traces, and LTLf -> DFA by progression
  3. Norms: outcome / rank / settled semantics (Definitions 3.3-3.7)
  4. Norms -> Moore machine (Section 4.2), minimisation, transition table
  5. The CVD statements and the three example traces
  6. Self-check: monitor output == semantics on all short traces, plus random norms

Run:  python3 audit_ref.py
"""
from __future__ import annotations
from dataclasses import dataclass
from itertools import product
from functools import lru_cache
import random

# ---------------------------------------------------------------------------
# 1. Event conditions (evaluated on ONE record; a record is a dict with "type")
# ---------------------------------------------------------------------------

OPS = {
    "=": lambda a, b: a == b, "!=": lambda a, b: a != b,
    "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
}


@dataclass(frozen=True)
class Ev:
    """Atom e[c]: record has event type `type` and satisfies the comparisons in `pred`."""
    type: str
    pred: tuple = ()          # tuple of (field, op, constant), read as a conjunction

    def holds(self, rec):
        return rec["type"] == self.type and all(
            f in rec and OPS[op](rec[f], c) for f, op, c in self.pred)

    def __str__(self):
        if not self.pred:
            return self.type
        return f"{self.type}[{' & '.join(f'{f}{op}{c}' for f, op, c in self.pred)}]"


@dataclass(frozen=True)
class CTrue:
    def holds(self, rec): return True
    def __str__(self): return "true"


@dataclass(frozen=True)
class CNot:
    c: object
    def holds(self, rec): return not self.c.holds(rec)
    def __str__(self): return f"!{self.c}"


@dataclass(frozen=True)
class CAnd:
    l: object
    r: object
    def holds(self, rec): return self.l.holds(rec) and self.r.holds(rec)
    def __str__(self): return f"({self.l} & {self.r})"


@dataclass(frozen=True)
class COr:
    l: object
    r: object
    def holds(self, rec): return self.l.holds(rec) or self.r.holds(rec)
    def __str__(self): return f"({self.l} | {self.r})"


TOP = CTrue()


def cond_atoms(c):
    if isinstance(c, Ev): return {c}
    if isinstance(c, CTrue): return set()
    if isinstance(c, CNot): return cond_atoms(c.c)
    return cond_atoms(c.l) | cond_atoms(c.r)


def cond_on_letter(c, letter):
    """Evaluate a condition on a letter (= frozenset of the atoms that are true)."""
    if isinstance(c, Ev): return c in letter
    if isinstance(c, CTrue): return True
    if isinstance(c, CNot): return not cond_on_letter(c.c, letter)
    if isinstance(c, CAnd): return cond_on_letter(c.l, letter) and cond_on_letter(c.r, letter)
    return cond_on_letter(c.l, letter) or cond_on_letter(c.r, letter)


def letter_of(rec, atoms):
    """Alphabet abstraction: a record is mapped to the set of statement atoms it satisfies."""
    return frozenset(a for a in atoms if a.holds(rec))


def consistent_letters(atoms):
    """All letters a record can produce: true atoms share one event type, and e[c] implies e."""
    atoms = sorted(atoms, key=str)
    out = []
    for bits in product([False, True], repeat=len(atoms)):
        true = [a for a, b in zip(atoms, bits) if b]
        if len({a.type for a in true}) > 1:
            continue
        if any(a.pred and Ev(a.type) in atoms and Ev(a.type) not in true for a in true):
            continue
        out.append(frozenset(true))
    return out


# ---------------------------------------------------------------------------
# 2. LTLf
# ---------------------------------------------------------------------------
# Formulas are tuples: ("c", cond) | ("not", f) | ("and", f, g) | ("or", f, g)
#                      | ("X", f) | ("WX", f) | ("U", f, g) | ("R", f, g)

def At(c): return ("c", c)
def Not(f): return ("not", f)
def And(*fs):
    out = fs[0]
    for f in fs[1:]: out = ("and", out, f)
    return out
def Or(*fs):
    out = fs[0]
    for f in fs[1:]: out = ("or", out, f)
    return out
def X(f): return ("X", f)            # strong next: a next position exists and satisfies f
def WX(f): return ("WX", f)          # weak next: no next position, or it satisfies f
def U(f, g): return ("U", f, g)
def R(f, g): return ("R", f, g)
def F(f): return U(At(TOP), f)
def G(f): return R(At(CNot(TOP)), f)
def W(f, g): return R(g, Or(f, g))   # weak until


def ltlf_holds(f, trace, i=0):
    """trace, i |= f   (0-based position i, 0 <= i < len(trace)). Bottom-up over positions, so it is not
    limited by recursion depth in the length of the trace."""
    n = len(trace)
    memo = {}

    def table(f):
        if f in memo:
            return memo[f]
        k = f[0]
        if k == "c":
            t = [f[1].holds(r) for r in trace]
        elif k == "not":
            t = [not x for x in table(f[1])]
        elif k in ("and", "or"):
            a, b = table(f[1]), table(f[2])
            t = [x and y for x, y in zip(a, b)] if k == "and" else [x or y for x, y in zip(a, b)]
        elif k in ("X", "WX"):
            a = table(f[1])
            t = [a[j + 1] if j + 1 < n else (k == "WX") for j in range(n)]
        elif k in ("U", "R"):
            a, b = table(f[1]), table(f[2])
            t = [False] * n
            for j in range(n - 1, -1, -1):
                later = t[j + 1] if j + 1 < n else None
                if k == "U":
                    t[j] = b[j] or (a[j] and later is True)
                else:
                    t[j] = b[j] and (a[j] or later is None or later)
        else:
            raise ValueError(k)
        memo[f] = t
        return t
    return table(f)[i]


def nnf(f, neg=False):
    k = f[0]
    if k == "c": return ("c", CNot(f[1])) if neg else f
    if k == "not": return nnf(f[1], not neg)
    if k in ("and", "or"):
        kk = k if not neg else ("or" if k == "and" else "and")
        return (kk, nnf(f[1], neg), nnf(f[2], neg))
    if k in ("X", "WX"):
        kk = k if not neg else ("WX" if k == "X" else "X")
        return (kk, nnf(f[1], neg))
    if k in ("U", "R"):
        kk = k if not neg else ("R" if k == "U" else "U")
        return (kk, nnf(f[1], neg), nnf(f[2], neg))
    raise ValueError(k)


def ltlf_atoms(f):
    if f[0] == "c": return cond_atoms(f[1])
    return set().union(*(ltlf_atoms(g) for g in f[1:]))


# DNF over "remainder items": ("S", f) = rest non-empty and satisfies f; ("W", f) = rest empty or satisfies f
D_TRUE = frozenset([frozenset()])
D_FALSE = frozenset()
def d_or(a, b): return _absorb(a | b)
def d_and(a, b): return _absorb(frozenset(x | y for x in a for y in b))
def _absorb(d): return frozenset(x for x in d if not any(y < x for y in d))


def _prog(f, letter):
    k = f[0]
    if k == "c": return D_TRUE if cond_on_letter(f[1], letter) else D_FALSE
    if k == "and": return d_and(_prog(f[1], letter), _prog(f[2], letter))
    if k == "or": return d_or(_prog(f[1], letter), _prog(f[2], letter))
    if k == "X": return frozenset([frozenset([("S", f[1])])])
    if k == "WX": return frozenset([frozenset([("W", f[1])])])
    if k == "U":
        return d_or(_prog(f[2], letter),
                    d_and(_prog(f[1], letter), frozenset([frozenset([("S", f)])])))
    if k == "R":
        return d_and(_prog(f[2], letter),
                     d_or(_prog(f[1], letter), frozenset([frozenset([("W", f)])])))
    raise ValueError(k)


@dataclass
class Moore:
    """Deterministic Moore machine: output is read off the state reached at the end of the trace."""
    atoms: list
    letters: list
    init: int
    delta: dict          # (state, letter) -> state
    out: dict            # state -> output
    names: dict          # state -> readable description

    def run(self, trace):
        s = self.init
        path = [s]
        for rec in trace:
            s = self.delta[(s, letter_of(rec, self.atoms))]
            path.append(s)
        return self.out[s], path

    @property
    def states(self): return sorted(self.out)

    def minimise(self):
        block = {s: self.out[s] for s in self.states}
        while True:
            sig = {s: (block[s], tuple(block[self.delta[(s, l)]] for l in self.letters))
                   for s in self.states}
            ids = {}
            new = {s: ids.setdefault(sig[s], len(ids)) for s in self.states}
            if len(set(new.values())) == len(set(block.values())):
                break
            block = new
        # renumber in BFS order from the initial state
        order, seen, todo = {}, set(), [self.init]
        while todo:
            s = todo.pop(0)
            if block[s] in seen: continue
            seen.add(block[s]); order[block[s]] = len(order)
            todo += [self.delta[(s, l)] for l in self.letters]
        rep = {}
        for s in self.states:
            if block[s] in order: rep.setdefault(order[block[s]], s)
        delta = {(q, l): order[block[self.delta[(s, l)]]] for q, s in rep.items() for l in self.letters}
        return Moore(self.atoms, self.letters, order[block[self.init]], delta,
                     {q: self.out[s] for q, s in rep.items()},
                     {q: self.names[s] for q, s in rep.items()})

    def is_partially_ordered(self):
        """True iff the only cycles are self-loops (then every output class is star-free)."""
        succ = {s: {self.delta[(s, l)] for l in self.letters} - {s} for s in self.states}
        state = {}
        def dfs(s):
            state[s] = 1
            for t in succ[s]:
                if state.get(t) == 1: return False
                if t not in state and not dfs(t): return False
            state[s] = 2
            return True
        return all(dfs(s) for s in self.states if s not in state)


def ltlf_to_dfa(f):
    """LTLf -> DFA by formula progression. Output True = formula satisfied by the trace read."""
    f = nnf(f)
    atoms = sorted(ltlf_atoms(f), key=str)
    letters = consistent_letters(atoms)
    init = frozenset([frozenset([("S", f)])])
    ids, delta, todo = {init: 0}, {}, [init]
    while todo:
        st = todo.pop()
        for l in letters:
            nxt = D_FALSE
            for clause in st:
                acc = D_TRUE
                for _, g in clause:
                    acc = d_and(acc, _prog(g, l))
                nxt = d_or(nxt, acc)
            if nxt not in ids:
                ids[nxt] = len(ids); todo.append(nxt)
            delta[(ids[st], l)] = ids[nxt]
    out = {i: any(all(kind == "W" for kind, _ in clause) for clause in st) for st, i in ids.items()}
    out[0] = False  # the empty trace is not a trace
    names = {i: f"q{i}" for i in ids.values()}
    return Moore(atoms, letters, 0, delta, out, names)


# ---------------------------------------------------------------------------
# 3. Norms: outcome and rank semantics
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Obl:
    """O(act <= deadline): an `act` record must occur no later than the first `deadline` record."""
    act: object
    deadline: object
    def races(self): return frozenset([(self.act, self.deadline)])
    def __str__(self): return f"O({self.act} <= {self.deadline})"


@dataclass(frozen=True)
class Forb:
    """F(act <= deadline): no `act` record before the first `deadline` record. Equals O(deadline <= act)."""
    act: object
    deadline: object
    def races(self): return frozenset([(self.deadline, self.act)])
    def __str__(self): return f"F({self.act} <= {self.deadline})"


@dataclass(frozen=True)
class Both:
    """Conjunction of basic norms."""
    parts: tuple
    def races(self): return frozenset().union(*(p.races() for p in self.parts))
    def __str__(self): return "(" + " and ".join(map(str, self.parts)) + ")"


@dataclass(frozen=True)
class Chain:
    """B0 (x) B1 (x) ... (x) Bm : B(j+1) enters into force right after the violation of Bj."""
    levels: tuple
    def __str__(self): return "  (x)  ".join(map(str, self.levels))


def race_outcome(win, lose, trace, i):
    """Outcome of one race from position i: None = complied, k = violated at position k (0-based)."""
    for k in range(i, len(trace)):
        if win.holds(trace[k]): return None       # includes the tie: both hold at k
        if lose.holds(trace[k]): return k
    return None                                   # neither occurred: never due


def outcome(basic, trace, i):
    """Definition 3.5: complied (None) or the earliest violation position."""
    viols = [k for w, l in basic.races() if (k := race_outcome(w, l, trace, i)) is not None]
    return min(viols) if viols else None


def rank(chain, trace):
    """Definition 3.6: index of the first level that is complied with; m+1 if none is."""
    i = 0
    for j, level in enumerate(chain.levels):
        k = outcome(level, trace, i)
        if k is None: return j
        i = k + 1
    return len(chain.levels)


def settled(chain, trace):
    """Definition 3.7: the verdict is final, i.e. no race of the level in force is still undecided."""
    i = 0
    for level in chain.levels:
        k = outcome(level, trace, i)
        if k is None:
            return all(any(w.holds(r) for r in trace[i:]) for w, _ in level.races())
        i = k + 1
    return True


def verdict(chain, trace):
    r, m = rank(chain, trace), len(chain.levels) - 1
    return "complied" if r == 0 else ("repaired" if r <= m else "violated")


ORDER = {"violated": 0, "repaired": 1, "complied": 2}
def aggregate(verdicts):
    """Meet in the verdict order complied > repaired > violated."""
    return min(verdicts, key=ORDER.get)


# ---------------------------------------------------------------------------
# 4. Norms -> Moore machine
# ---------------------------------------------------------------------------

def chain_atoms(chain):
    s = set()
    for level in chain.levels:
        for w, l in level.races():
            s |= cond_atoms(w) | cond_atoms(l)
    return sorted(s, key=str)


def compile_chain(chain):
    """State = (level j, set of still-pending races) or 'V'. Output = rank."""
    atoms = chain_atoms(chain)
    letters = consistent_letters(atoms)
    m = len(chain.levels) - 1
    init = (0, chain.levels[0].races())
    ids, delta, todo = {init: 0}, {}, [init]

    def step(st, letter):
        if st == "V": return "V"
        j, pending = st
        keep, violated = set(), False
        for w, l in pending:
            if cond_on_letter(w, letter): continue          # this race is won: drop it
            if cond_on_letter(l, letter): violated = True
            else: keep.add((w, l))
        if violated:
            return "V" if j == m else (j + 1, chain.levels[j + 1].races())
        return (j, frozenset(keep))

    while todo:
        st = todo.pop(0)
        for l in letters:
            nxt = step(st, l)
            if nxt not in ids:
                ids[nxt] = len(ids); todo.append(nxt)
            delta[(ids[st], l)] = ids[nxt]

    def name(st):
        if st == "V": return "violated"
        j, pending = st
        if not pending: return f"level {j} complied"
        return f"level {j} pending: " + ", ".join(sorted(f"{w} before {l}" for w, l in pending))

    out = {i: ((m + 1, True) if st == "V" else (st[0], not st[1])) for st, i in ids.items()}
    return Moore(atoms, letters, 0, delta, out, {i: name(st) for st, i in ids.items()})


def print_table(mach, label_out=str):
    def lname(l): return " & ".join(sorted(map(str, l))) if l else "other"
    cols = sorted(mach.letters, key=lname)
    print(f"{'state':<7}{'output':<10}" + "".join(f"{lname(c):<22}" for c in cols) + "meaning")
    for s in mach.states:
        print(f"s{s:<6}{label_out(mach.out[s]):<10}"
              + "".join(f"{'s' + str(mach.delta[(s, c)]):<22}" for c in cols) + mach.names[s])


# ---------------------------------------------------------------------------
# 5. The CVD statements
# ---------------------------------------------------------------------------

PATCH = Ev("patch", (("coverage", "=", "full"),))
MITIG = Ev("mitigation")
ADVIS = Ev("advisory")
DISC = Ev("disclosure")
GRACE = Ev("grace_end")

# Embargo: no advisory before disclosure.
N_EMBARGO = Chain((Forb(ADVIS, DISC),))
# Patch duty: full patch before disclosure; otherwise mitigation immediately and full patch before grace end.
N_PATCH = Chain((Obl(PATCH, DISC),
                 Both((Obl(COr(MITIG, PATCH), TOP), Obl(PATCH, GRACE)))))

def rec(t, **kw): return {"type": t, **kw}

TRACE_A = [rec("notify"), rec("ack"), rec("patch", coverage="full"), rec("disclosure"), rec("grace_end")]
TRACE_B = [rec("notify"), rec("ack"), rec("disclosure"), rec("mitigation"),
           rec("patch", coverage="full"), rec("grace_end")]
TRACE_C = [rec("notify"), rec("ack"), rec("disclosure"), rec("grace_end")]

# LTLf characterisation of the three verdict classes of N_PATCH (Section 3.3, Remark)
p, d, mi, g = At(PATCH), At(DISC), At(MITIG), At(GRACE)
PHI_COMPLIED = W(Not(d), p)
PHI_REPAIRED = U(And(Not(p), Not(d)),
                 And(d, Not(p), WX(And(Or(mi, p), W(Not(g), p)))))
PHI_VIOLATED = And(Not(PHI_COMPLIED), Not(PHI_REPAIRED))
PHI_EMBARGO = W(Not(At(ADVIS)), At(DISC))

# Conformance and data-predicate statements (two-valued)
PHI_ACK = G(Or(Not(At(Ev("notify"))), F(At(Ev("ack")))))          # every notification is acknowledged
PHI_COVER = G(Or(Not(At(Ev("patch"))), At(PATCH)))                   # every released patch has full coverage


def closed_cvd(trace):
    """A vendor slice is closed if it contains exactly one disclosure and, after it, exactly one grace_end."""
    d = [i for i, r in enumerate(trace) if r["type"] == "disclosure"]
    g = [i for i, r in enumerate(trace) if r["type"] == "grace_end"]
    return len(d) == 1 and len(g) == 1 and d[0] < g[0]


def to_dot(mach, label_out):
    def lname(l): return " & ".join(sorted(map(str, l))) if l else "other"
    lines = ["digraph M {", "  rankdir=LR; node [shape=box, style=rounded, fontname=Helvetica]; edge [fontname=Helvetica, fontsize=10];",
             "  start [shape=point]; start -> s%d;" % mach.init]
    for q in mach.states:
        lines.append('  s%d [label="s%d\n%s"];' % (q, q, label_out(mach.out[q])))
    for q in mach.states:
        by_target = {}
        for l in mach.letters:
            by_target.setdefault(mach.delta[(q, l)], []).append(lname(l))
        for t, ls in by_target.items():
            lab = "*" if len(ls) == len(mach.letters) else "\n".join(sorted(ls))
            lines.append('  s%d -> s%d [label="%s"];' % (q, t, lab))
    return "\n".join(lines + ["}"])


def md_table(mach, label_out):
    def lname(l): return " & ".join(sorted(map(str, l))) if l else "other"
    cols = sorted(mach.letters, key=lname)
    rows = ["| state | output | " + " | ".join(lname(c) for c in cols) + " | meaning |",
            "|" + "---|" * (len(cols) + 3)]
    for q in mach.states:
        rows.append(f"| s{q} | {label_out(mach.out[q])} | "
                    + " | ".join(f"s{mach.delta[(q, c)]}" for c in cols) + f" | {mach.names[q]} |")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# 6. Self-check
# ---------------------------------------------------------------------------

RECORD_KINDS = [rec("notify"), rec("ack"), rec("patch", coverage="full"), rec("patch", coverage="partial"),
                rec("mitigation"), rec("advisory"), rec("disclosure"), rec("grace_end")]


def all_traces(max_len, kinds=RECORD_KINDS):
    for n in range(1, max_len + 1):
        yield from product(kinds, repeat=n)


def random_chain(rng, conds):
    def basic():
        parts = []
        for _ in range(rng.randint(1, 3)):
            a, b = rng.choice(conds), rng.choice(conds + [TOP])
            parts.append(rng.choice([Obl, Forb])(a, b))
        return parts[0] if len(parts) == 1 else Both(tuple(parts))
    return Chain(tuple(basic() for _ in range(rng.randint(1, 4))))



VNAME = {0: "complied", 1: "repaired", 2: "violated"}
def out_patch(o): return VNAME[o[0]] + ("" if o[1] else " (open)")
def out_emb(o): return {0: "complied", 1: "violated"}[o[0]] + ("" if o[1] else " (open)")


def self_check(max_len=6, write_files=True):
    print("== CVD patch norm:", N_PATCH)
    raw = compile_chain(N_PATCH)
    mon = raw.minimise()
    print(f"states: {len(raw.states)} raw, {len(mon.states)} minimal; "
          f"letters: {len(mon.letters)}; partially ordered: {mon.is_partially_ordered()}")
    print(md_table(mon, out_patch))
    for nm, tr in (("A", TRACE_A), ("B", TRACE_B), ("C", TRACE_C)):
        o, path = mon.run(tr)
        print(f"trace {nm}: semantics={verdict(N_PATCH, tr):<9} monitor={out_patch(o):<9} "
              f"path={' '.join('s' + str(q) for q in path)} | embargo={verdict(N_EMBARGO, tr)} "
              f"| ack={ltlf_holds(PHI_ACK, tr)} | cover={ltlf_holds(PHI_COVER, tr)}")

    print("\n== CVD embargo norm:", N_EMBARGO)
    emb = compile_chain(N_EMBARGO).minimise()
    print(md_table(emb, out_emb))

    dfa_c, dfa_r = ltlf_to_dfa(PHI_COMPLIED).minimise(), ltlf_to_dfa(PHI_REPAIRED).minimise()
    dfa_e = ltlf_to_dfa(PHI_EMBARGO).minimise()
    dfa_a, dfa_v = ltlf_to_dfa(PHI_ACK).minimise(), ltlf_to_dfa(PHI_COVER).minimise()
    print(f"\nLTLf DFAs (minimal): complied {len(dfa_c.states)}, repaired {len(dfa_r.states)}, "
          f"embargo {len(dfa_e.states)}, ack {len(dfa_a.states)}, cover {len(dfa_v.states)} states")

    n = n_closed = 0
    for tr in all_traces(max_len):
        n += 1
        r = rank(N_PATCH, tr)
        assert mon.run(tr)[0] == (r, settled(N_PATCH, tr)), tr           # Theorem 4.1 on N_PATCH
        assert ltlf_holds(PHI_COMPLIED, tr) == (r == 0), tr              # formulas of Section 3.3 (Proposition 3.2)
        assert ltlf_holds(PHI_REPAIRED, tr) == (r == 1), tr
        assert ltlf_holds(PHI_VIOLATED, tr) == (r == 2), tr
        assert dfa_c.run(tr)[0] == (r == 0) and dfa_r.run(tr)[0] == (r == 1), tr   # progression DFA
        e = rank(N_EMBARGO, tr)
        assert emb.run(tr)[0] == (e, settled(N_EMBARGO, tr)), tr
        assert ltlf_holds(PHI_EMBARGO, tr) == (e == 0) == dfa_e.run(tr)[0], tr
        assert dfa_a.run(tr)[0] == ltlf_holds(PHI_ACK, tr) and dfa_v.run(tr)[0] == ltlf_holds(PHI_COVER, tr), tr
        if closed_cvd(tr):                                               # Lemma 3.2: closed => settled
            n_closed += 1
            assert settled(N_PATCH, tr) and settled(N_EMBARGO, tr), tr
    print(f"exhaustive check passed on {n} traces (length <= {max_len}, {len(RECORD_KINDS)} record kinds); "
          f"{n_closed} of them closed, all settled")

    rng = random.Random(2026)
    conds = [PATCH, MITIG, ADVIS, DISC, GRACE, Ev("patch"), COr(MITIG, PATCH), CNot(DISC)]
    sizes, checked = [], 0
    for _ in range(300):
        ch = random_chain(rng, conds)
        raw_c = compile_chain(ch); mm = raw_c.minimise()
        assert raw_c.is_partially_ordered() and mm.is_partially_ordered()
        bound = sum(2 ** len(l.races()) for l in ch.levels) + 1
        assert len(raw_c.states) <= bound, (str(ch), len(raw_c.states), bound)
        sizes.append((len(raw_c.states), len(mm.states), bound))
        for _ in range(400):
            tr = [rng.choice(RECORD_KINDS) for _ in range(rng.randint(1, 9))]
            want = (rank(ch, tr), settled(ch, tr))
            assert raw_c.run(tr)[0] == want and mm.run(tr)[0] == want, (str(ch), tr)
            if want[1]:                                                  # Lemma 3.1: settled => final
                ext = tr + [rng.choice(RECORD_KINDS) for _ in range(rng.randint(1, 4))]
                assert rank(ch, ext) == want[0] and settled(ch, ext), (str(ch), tr, ext)
            checked += 1
    print(f"random check passed: 300 random chains x 400 random traces = {checked} runs; "
          f"largest raw monitor {max(x[0] for x in sizes)} states, largest minimal {max(x[1] for x in sizes)}; "
          f"state bound sum(2^races)+1 held for all")

    if write_files:
        open("monitor_patch.dot", "w").write(to_dot(mon, out_patch))
        open("monitor_embargo.dot", "w").write(to_dot(emb, out_emb))


if __name__ == "__main__":
    self_check()
