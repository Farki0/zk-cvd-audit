//! Shared logic of the prototype: formats of PROTOTYPE_SPEC.md section 2, the guest program (Algorithm 5.1)
//! and the checks of the auditor that do not need a zkVM (checks 2, 3, 5, 6, 7).
//! The same code runs inside the zkVM guest and natively in the host.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

// ----------------------------------------------------------------------------- hash and formats

/// A hash as its 64 lowercase hex characters, on the stack (no allocation inside the zkVM).
#[derive(Clone, Copy)]
pub struct Hx([u8; 64]);
impl Hx {
    pub fn as_str(&self) -> &str { unsafe { std::str::from_utf8_unchecked(&self.0) } } // ASCII hex digits only
}
impl std::ops::Deref for Hx { type Target = str; fn deref(&self) -> &str { self.as_str() } }

/// H(p1..pk): SHA-256 over len(4 bytes, big endian) || bytes for every part; lowercase hex.
/// Small inputs are assembled in a stack buffer and hashed with one call (a call costs far more than a block).
pub fn hh(parts: &[&str]) -> Hx {
    let total: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut s = Sha256::new();
    if total <= 256 {
        let mut buf = [0u8; 256];
        let mut i = 0;
        for p in parts {
            buf[i..i + 4].copy_from_slice(&(p.len() as u32).to_be_bytes());
            buf[i + 4..i + 4 + p.len()].copy_from_slice(p.as_bytes());
            i += 4 + p.len();
        }
        s.update(&buf[..i]);
    } else {
        for p in parts {
            s.update((p.len() as u32).to_be_bytes());
            s.update(p.as_bytes());
        }
    }
    let d = s.finalize();
    let mut o = [0u8; 64];
    for i in 0..32 {
        let p = HEX[d[i] as usize];
        o[2 * i] = p[0];
        o[2 * i + 1] = p[1];
    }
    Hx(o)
}

pub fn h(parts: &[&str]) -> String { hh(parts).as_str().to_owned() }
const fn hex_table() -> [[u8; 2]; 256] {
    let d = b"0123456789abcdef";
    let mut t = [[0u8; 2]; 256];
    let mut i = 0;
    while i < 256 { t[i] = [d[i >> 4], d[i & 15]]; i += 1; }
    t
}
static HEX: [[u8; 2]; 256] = hex_table();

pub fn hex(b: &[u8]) -> String {
    let mut o = vec![0u8; b.len() * 2];
    for (i, x) in b.iter().enumerate() {
        let p = HEX[*x as usize];
        o[2 * i] = p[0];
        o[2 * i + 1] = p[1];
    }
    // only ASCII hex digits were written
    unsafe { String::from_utf8_unchecked(o) }
}
/// enc(r): sorted keys, `,` and `:` separators, ASCII only (as Python json.dumps(sort_keys, separators)).
/// Only used on the host side and in tests: the guest never re-encodes.
pub fn enc(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap(); // serde_json maps are sorted (no preserve_order)
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            o.push(c);
        } else {
            let mut b = [0u16; 2];
            for u in c.encode_utf16(&mut b) {
                o.push_str(&format!("\\u{:04x}", u));
            }
        }
    }
    o
}

/// The genesis head H('slice', instance, org, salt0). `salt0` is private and fresh per slice: without it the genesis
/// head would be computable from public data, and a first message's pre-head would tell the auditor whether an
/// internal record precedes that message.
pub fn genesis(instance: &str, org: &str, salt0: &str) -> String { h(&["slice", instance, org, salt0]) }
pub fn link(head: &str, c: &str) -> String { h(&["link", head, c]) }
pub fn rec_commit(salt: &str, enc_rec: &str) -> String { h(&["rec", salt, enc_rec]) }
fn step(head: &Hx, salt: &str, enc_rec: &str) -> Hx { hh(&["link", head, &hh(&["rec", salt, enc_rec])]) }
pub fn iface_commit(instance: &str, s: &str, r: &str, kind: &str, nonce: &str, body: &str) -> String {
    h(&["iface", instance, s, r, kind, nonce, &h(&["body", body])])
}
pub fn pdigest(participants_canonical: &str) -> String { h(&["participants", participants_canonical]) }
pub fn statement_id(canonical: &str) -> String { h(&["statement", canonical]) }

/// Message kinds of the CVD choreography: kind -> (sender role, receiver role). Part of the public layer.
pub fn schema(kind: &str) -> Option<(&'static str, &'static str)> {
    match kind {
        "notify" | "disclosure" | "grace_end" => Some(("maintainer", "vendor")),
        "ack" => Some(("vendor", "maintainer")),
        _ => None,
    }
}

// ----------------------------------------------------------------------------- statement tables

#[derive(Deserialize)]
pub struct Atom {
    #[serde(rename = "type")]
    pub ty: String,
    pub pred: Vec<(String, String, Value)>,
}

#[derive(Deserialize)]
pub struct Norm {
    pub m: u32,
    pub atoms: Vec<Atom>,
    pub letter_of_mask: Vec<i64>,
    pub init: usize,
    pub delta: Vec<Vec<usize>>,
    pub out: Vec<(u32, bool)>,
}

#[derive(Deserialize)]
pub struct Statement {
    pub role: String,
    pub norms: Vec<Norm>,
}

fn cmp_ord<T: PartialOrd>(a: T, op: &str, b: T) -> bool {
    match op {
        "=" => a == b, "!=" => a != b, "<" => a < b, "<=" => a <= b, ">" => a > b, ">=" => a >= b,
        _ => false,
    }
}

/// A field value of a record. A comparison needs the same JSON type on both sides (as `type(a) is type(b)`).
enum Val<'a> { Str(Cow<'a, str>), Int(i64), Float(f64), Bool(bool), Other }

/// A parsed record. Records are flat JSON objects as produced by enc(); a hand-written scanner reads them
/// without allocating per field, and anything it does not understand (escapes, nesting, whitespace) goes
/// through serde_json instead, so every valid JSON object is accepted.
struct Rec<'a> { f: Vec<(Cow<'a, str>, Val<'a>)> }

impl<'a> Rec<'a> {
    fn get(&self, k: &str) -> Option<&Val<'a>> { self.f.iter().rev().find(|(x, _)| x == k).map(|(_, v)| v) }
    fn str(&self, k: &str) -> Option<&str> { match self.get(k) { Some(Val::Str(s)) => Some(s), _ => None } }
}

fn scan(e: &str) -> Option<Rec<'_>> {
    let b = e.as_bytes();
    if b.first() != Some(&b'{') || b.last() != Some(&b'}') { return None; }
    let mut f = Vec::with_capacity(8);
    let mut i = 1;
    let n = b.len() - 1;
    if i == n { return Some(Rec { f }); }
    let quoted = |i: usize| -> Option<(&str, usize)> {      // "..." without escapes; returns content and next index
        if b.get(i) != Some(&b'"') { return None; }
        let mut j = i + 1;
        while j < n {
            match b[j] { b'"' => return Some((&e[i + 1..j], j + 1)), b'\\' => return None, _ => j += 1 }
        }
        None
    };
    loop {
        let (k, j) = quoted(i)?;
        if b.get(j) != Some(&b':') { return None; }
        i = j + 1;
        let v = match *b.get(i)? {
            b'"' => { let (s, j) = quoted(i)?; i = j; Val::Str(Cow::Borrowed(s)) }
            b'-' | b'0'..=b'9' => {
                let s = i;
                while i < n && !matches!(b[i], b',' | b'}') { i += 1; }
                let t = &e[s..i];
                if t.bytes().all(|c| c == b'-' || c.is_ascii_digit()) { Val::Int(t.parse().ok()?) } else { return None }
            }
            b't' if e[i..].starts_with("true") => { i += 4; Val::Bool(true) }
            b'f' if e[i..].starts_with("false") => { i += 5; Val::Bool(false) }
            _ => return None,
        };
        f.push((Cow::Borrowed(k), v));
        if i == n { return Some(Rec { f }); }
        if b[i] != b',' { return None; }
        i += 1;
    }
}

fn parse_rec(e: &str) -> Result<Rec<'_>, String> {
    if let Some(r) = scan(e) { return Ok(r); }
    let v: Value = serde_json::from_str(e).map_err(|x| x.to_string())?;
    let Value::Object(m) = v else { return Err("record is not a JSON object".into()) };
    let f = m.into_iter().map(|(k, v)| {
        let v = match v {
            Value::String(s) => Val::Str(Cow::Owned(s)),
            Value::Bool(b) => Val::Bool(b),
            Value::Number(n) => match n.as_i64() { Some(i) => Val::Int(i), None => n.as_f64().map(Val::Float).unwrap_or(Val::Other) },
            _ => Val::Other,
        };
        (Cow::Owned(k), v)
    }).collect();
    Ok(Rec { f })
}

/// An atom holds on a record whose type matches and whose every comparison holds. A missing field, a field of
/// another JSON type, or an order comparison on strings makes it false (as `holds` in vectors.py).
fn holds(a: &Atom, rec: &Rec) -> bool {
    if rec.str("type") != Some(a.ty.as_str()) { return false; }
    for (f, op, c) in &a.pred {
        let Some(x) = rec.get(f) else { return false };
        let ok = match (x, c) {
            (Val::Str(x), Value::String(c)) => matches!(op.as_str(), "=" | "!=") && cmp_ord(&**x, op, c.as_str()),
            (Val::Bool(x), Value::Bool(c)) => cmp_ord(*x, op, *c),
            (Val::Int(x), Value::Number(c)) => match c.as_i64() { Some(c) => cmp_ord(*x, op, c), None => false },
            (Val::Float(x), Value::Number(c)) => if c.is_f64() { cmp_ord(*x, op, c.as_f64().unwrap()) } else { false },
            _ => false,
        };
        if !ok { return false; }
    }
    true
}
// ----------------------------------------------------------------------------- journal and guest

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IfaceEntry {
    pub msg: String,
    pub dir: String,
    pub peer: String,
    pub own_pre: String,
    pub peer_pre: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Journal {
    pub sid: String,
    pub instance: String,
    pub org: String,
    pub pdigest: String,
    pub head: String,
    pub iface: Vec<IfaceEntry>,
    pub verdict: Option<String>,
    pub settled: bool,
}

/// The canonical order of the interface entries in a journal: partner, direction, commitment.
pub fn sort_iface(iface: &mut [IfaceEntry]) {
    iface.sort_by(|a, b| (&a.peer, &a.dir, &a.msg).cmp(&(&b.peer, &b.dir, &b.msg)));
}

/// Guest variants. `Chain`: only the hash chain; `Iface`: chain + interface checks; `Full`: + monitors.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Variant { Chain, Iface, Full }

pub fn rank_of(v: &str) -> u8 { match v { "violated" => 0, "repaired" => 1, _ => 2 } }
fn label(rank: u32, m: u32) -> &'static str {
    if rank == 0 { "complied" } else if rank <= m { "repaired" } else { "violated" }
}
fn aggregate<'a>(v: impl Iterator<Item = &'a str>) -> &'a str { v.min_by_key(|x| rank_of(x)).unwrap() }

fn str_field<'a>(rec: &'a Rec, k: &str) -> Result<&'a str, String> {
    rec.str(k).ok_or_else(|| format!("record field `{k}` missing or not a string"))
}

/// Private input as raw bytes: per entry, u32 LE length + enc(r), u32 LE length + salt. Avoids the cost of a
/// generic serde decoding inside the zkVM.
pub fn encode_entries(entries: &[(String, String)]) -> Vec<u8> {
    let mut o = Vec::new();
    for (e, s) in entries {
        for x in [e, s] { o.extend_from_slice(&(x.len() as u32).to_le_bytes()); o.extend_from_slice(x.as_bytes()); }
    }
    o
}

pub fn decode_entries(blob: &[u8]) -> Result<Vec<(&str, &str)>, String> {
    let mut v = Vec::new();
    let mut i = 0;
    let next = |i: &mut usize| -> Result<&str, String> {
        let n = u32::from_le_bytes(blob.get(*i..*i + 4).ok_or("truncated entries")?.try_into().unwrap()) as usize;
        let s = blob.get(*i + 4..*i + 4 + n).ok_or("truncated entries")?;
        *i += 4 + n;
        std::str::from_utf8(s).map_err(|e| e.to_string())
    };
    while i < blob.len() { let e = next(&mut i)?; let s = next(&mut i)?; v.push((e, s)); }
    Ok(v)
}

/// Algorithm 5.1. `entries` are (enc(r); the encoded string is hashed exactly as given.
/// An `Err` is an abort: in the zkVM it is a panic, so no proof exists.
pub fn guest(variant: Variant, stmt_canonical: &str, instance: &str, participants_canonical: &str, org: &str,
             salt0: &str, entries: &[(&str, &str)]) -> Result<Journal, String> {
    let participants: BTreeMap<String, String> = serde_json::from_str(participants_canonical).map_err(|e| e.to_string())?;
    let role = participants.get(org).ok_or("organisation is not a participant")?;
    let stmt: Statement = serde_json::from_str(stmt_canonical).map_err(|e| e.to_string())?;
    let norms: &[Norm] = if variant == Variant::Full && *role == stmt.role { &stmt.norms } else { &[] };
    let mut q: Vec<usize> = norms.iter().map(|n| n.init).collect();
    let mut head = hh(&["slice", instance, org, salt0]);
    let mut iface = Vec::new();
    for (e, salt) in entries {
        if variant == Variant::Chain {
            head = step(&head, salt, e);
            continue;
        }
        let rec = parse_rec(e)?;
        let ty = str_field(&rec, "type")?;
        let has_msg = rec.get("msg").is_some();
        if variant != Variant::Chain && schema(ty).is_some() && !has_msg {
            return Err("a shared event was recorded without a hand-off".into());
        }
        if has_msg {
            let peer = str_field(&rec, "peer")?;
            let dir = str_field(&rec, "dir")?;
            let (s, t) = if dir == "send" { (org, peer) } else { (peer, org) };
            let allowed = match (schema(ty), participants.get(s), participants.get(t)) {
                (Some((a, b)), Some(x), Some(y)) => a == x && b == y,
                _ => false,
            };
            if !allowed { return Err("message kind not allowed between these roles".into()); }
            let msg = str_field(&rec, "msg")?;
            if msg != iface_commit(instance, s, t, ty, str_field(&rec, "nonce")?, str_field(&rec, "body")?) {
                return Err("record type or peer does not match the interface commitment".into());
            }
            iface.push(IfaceEntry { msg: msg.into(), dir: dir.into(), peer: peer.into(), own_pre: head.as_str().to_owned(),
                                    peer_pre: str_field(&rec, "peer_head")?.into() });
        }
        head = step(&head, salt, e);
        for (i, n) in norms.iter().enumerate() {
            let mask = n.atoms.iter().enumerate().fold(0usize, |m, (j, a)| m | ((holds(a, &rec) as usize) << j));
            let letter = *n.letter_of_mask.get(mask).ok_or("mask out of range")?;
            if letter < 0 { return Err("inconsistent letter".into()); }
            q[i] = *n.delta.get(q[i]).and_then(|r| r.get(letter as usize)).ok_or("bad table")?;
        }
    }
    // output order: by partner, direction and commitment, not by record. The record order would show how the
    // organisation interleaved its partners (which vendor the maintainer served first), which the model does not fix.
    sort_iface(&mut iface);
    let verdicts: Vec<&str> = norms.iter().zip(&q).map(|(n, &qi)| label(n.out[qi].0, n.m)).collect();
    let settled = norms.iter().zip(&q).all(|(n, &qi)| n.out[qi].1);
    Ok(Journal {
        sid: statement_id(stmt_canonical), instance: instance.into(), org: org.into(), pdigest: pdigest(participants_canonical),
        head: head.as_str().to_owned(), iface,
        // an organisation that is not settled outputs no verdict, only settled = false (Def. 3.10: 'open')
        verdict: if verdicts.is_empty() || !settled { None } else { Some(aggregate(verdicts.iter().copied()).into()) },
        settled,
    })
}

// ----------------------------------------------------------------------------- auditor checks 2, 3, 5, 6, 7

#[derive(Debug, Clone)]
pub struct Reject { pub check: u8, pub reason: String }
fn rej<T>(check: u8, reason: &str) -> Result<T, Reject> { Err(Reject { check, reason: reason.into() }) }

pub struct Checked {
    pub heads: BTreeMap<String, String>,
    pub per_org: BTreeMap<String, String>,
    pub verdict: String,
}

/// Checks 2 and 3 (on every journal) and 5, 6, 7. Check 4 needs the published commitments and is done by the
/// caller between check 3 and check 5 (see `check_all` in the host) -- the order is only observable in which
/// number is reported when a manipulation violates several checks.
pub fn check_2_3(sid: &str, instance: &str, participants_canonical: &str, js: &[Journal]) -> Result<BTreeMap<String, String>, Reject> {
    let pd = pdigest(participants_canonical);
    for j in js {
        if j.sid != sid || j.instance != instance { return rej(2, "wrong statement or instance"); }
        if j.pdigest != pd { return rej(2, "proof assumes another participant set"); }
    }
    let participants: BTreeMap<String, String> = serde_json::from_str(participants_canonical).unwrap_or_default();
    let mut orgs: Vec<&str> = js.iter().map(|j| j.org.as_str()).collect();
    orgs.sort();
    let want: Vec<&str> = participants.keys().map(String::as_str).collect();
    if orgs != want { return rej(3, "full participation fails: the provers are not exactly the participant set"); }
    Ok(participants)
}

pub fn check_5_6_7(participants: &BTreeMap<String, String>, js: &[Journal]) -> Result<Checked, Reject> {
    let mut send = BTreeMap::new();
    let mut recv = BTreeMap::new();
    for j in js {
        for e in &j.iface {
            let side = if e.dir == "send" { &mut send } else { &mut recv };
            if side.insert(e.msg.clone(), (j.org.clone(), e.clone())).is_some() {
                return rej(5, "interface commitment used twice");
            }
        }
    }
    if send.keys().collect::<BTreeSet<_>>() != recv.keys().collect::<BTreeSet<_>>() {
        return rej(5, "interface: a message is missing on one side");
    }
    for (k, (s_org, s)) in &send {
        let (r_org, r) = &recv[k];
        if &s.peer != r_org || &r.peer != s_org { return rej(5, "interface: wrong peer"); }
        if s.own_pre != r.peer_pre || r.own_pre != s.peer_pre {
            return rej(5, "interface: heads at the hand-off do not match (history rewritten around a message)");
        }
    }
    let mut per_org = BTreeMap::new();
    for j in js {
        if participants.get(&j.org).map(String::as_str) == Some("vendor") {
            let v = match (&j.verdict, j.settled) { (Some(v), true) => v.clone(), _ => "open".to_string() };
            per_org.insert(j.org.clone(), v);
        }
    }
    let verdict = if per_org.values().any(|v| v == "open") { "open".to_string() }
        else { aggregate(per_org.values().map(String::as_str)).to_string() };
    let heads = js.iter().map(|j| (j.org.clone(), j.head.clone())).collect();
    Ok(Checked { heads, per_org, verdict })
}

// ----------------------------------------------------------------------------- aggregation guest (C7)

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AggJournal {
    pub sid: String,
    pub instance: String,
    pub guest_id: String,
    /// Digest of the participant set (names and roles) that the aggregation guest used for checks 2, 3 and 7; the
    /// auditor compares it with the digest of the public participant set (check 2), as it does for every organisation
    /// journal. Without it an aggregator could give the guest other roles than the public ones.
    pub pdigest: String,
    pub heads: BTreeMap<String, String>,
    pub verdict: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes() {
        assert_eq!(h(&["a"]), "72ff6b02949dad95006c343e3db3150090d3afb49f6bbdb92fdc17607997a85c");
        assert_eq!(h(&["a", "bc"]), "b534ce16ac9c8b36823f39a395ce8e0e3c7ad9605b82b5444f18cadacd217a5d");
    }
}
