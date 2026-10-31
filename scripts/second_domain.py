#!/usr/bin/env python3
"""Second domain of the thesis (Chapter 3, end): a supply contract with a penalty, checked on the reference model.

  scripts/second_domain.py            -> results/second_domain.json, summary on stdout

The buyer must pay by the due date, and otherwise pay with the agreed penalty by the final notice:
    N_pay = O(payment <= due)  (x)  O(payment[penalty = paid] <= final_notice)
This is a reparation chain like the patch norm. The script (1) gives the verdict, rank and settled flag of five slices,
(2) compiles the chain into its monitor and reports the number of states and table entries, and (3) compares the
monitor with the semantics on every slice of up to five records over the five record kinds. Reference model only: the
statement is not run through the prover or the protocol. Needs nothing but reference/code/audit_ref.py."""
import importlib.util, json, os, sys
from itertools import product

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location('audit_ref', f'{ROOT}/reference/code/audit_ref.py')
m = importlib.util.module_from_spec(spec)
sys.modules['audit_ref'] = m
spec.loader.exec_module(m)

PAY = m.Ev('payment')
PAY_PEN = m.Ev('payment', (('penalty', '=', 'paid'),))
DUE = m.Ev('due')
FINAL = m.Ev('final_notice')
N_PAY = m.Chain((m.Obl(PAY, DUE), m.Obl(PAY_PEN, FINAL)))
rec = m.rec

SLICES = {
    'on time': [rec('invoice'), rec('payment'), rec('due'), rec('final_notice')],
    'late, penalty paid': [rec('invoice'), rec('due'), rec('payment', penalty='paid'), rec('final_notice')],
    'late, no penalty': [rec('invoice'), rec('due'), rec('payment'), rec('final_notice')],
    'late, penalty paid, no final notice yet': [rec('invoice'), rec('due'), rec('payment', penalty='paid')],
    'nothing after the due date': [rec('invoice'), rec('due')],
}
verdicts = {}
for name, tr in SLICES.items():
    verdicts[name] = {'verdict': m.verdict(N_PAY, tr), 'rank': m.rank(N_PAY, tr), 'settled': m.settled(N_PAY, tr)}
    print(f'{name:42s} {verdicts[name]}')

mach = m.compile_chain(N_PAY)
states = len({s for (s, _l) in mach.delta})
entries = len(mach.delta)
print('atoms:', [str(a) for a in mach.atoms], '| letters:', len(mach.letters), '| states:', states, '| table entries:', entries)

kinds = [rec('invoice'), rec('payment'), rec('payment', penalty='paid'), rec('due'), rec('final_notice')]
total = bad = 0
for n in range(0, 6):
    for tr in product(kinds, repeat=n):
        tr = list(tr)
        total += 1
        st = mach.init
        for r in tr:
            st = mach.delta[(st, m.letter_of(r, mach.atoms))]
        if mach.out[st] != (m.rank(N_PAY, tr), m.settled(N_PAY, tr)):
            bad += 1
print(f'slices of up to 5 records compared: {total}, mismatches: {bad}')

os.makedirs(f'{ROOT}/results', exist_ok=True)
json.dump({'norm': str(N_PAY), 'verdicts': verdicts, 'states': states, 'table_entries': entries,
           'slices_compared': total, 'mismatches': bad, 'max_length': 5,
           'scope': 'reference model only (audit_ref.py); not run through the prover'},
          open(f'{ROOT}/results/second_domain.json', 'w'), indent=1)
sys.exit(1 if bad else 0)
