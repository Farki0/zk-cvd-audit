use audit_core::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use methods::*;
use risc0_circuit_recursion::control_id::{POSEIDON2_CONTROL_IDS, SHA256_CONTROL_IDS};
use risc0_zkvm::{default_prover, sha::Sha256, ExecutorEnv, FakeReceipt, InnerReceipt, ProverOpts, Receipt, ReceiptClaim};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

// ----------------------------------------------------------------------------- inputs

pub struct Stmt { pub name: String, pub canonical: String, pub id: String, pub disclosure: String }

impl Stmt {
    pub fn load(p: &Path) -> Stmt {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let s = Stmt { name: v["name"].as_str().unwrap().into(), canonical: v["canonical"].as_str().unwrap().into(),
                       id: v["id"].as_str().unwrap().into(), disclosure: v["disclosure"].as_str().unwrap().into() };
        assert_eq!(statement_id(&s.canonical), s.id, "statement id of {}", s.name);
        s
    }
}

#[derive(Clone, Deserialize)]
pub struct Pub { pub head: String, pub pubkey: String, pub sig: String }

pub struct Scn {
    pub instance: String,
    pub pcanon: String,
    pub participants: BTreeMap<String, String>,
    pub slices: BTreeMap<String, Vec<(String, String)>>,
    /// genesis salt of each slice (private input of the guest, like the slices; absent in the auditor's public file)
    pub gsalts: BTreeMap<String, String>,
    pub published: BTreeMap<String, Pub>,
    pub length: Option<u64>,
}

impl Scn {
    pub fn load(p: &Path) -> Scn { Scn::from_value(&serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()) }
    pub fn from_value(v: &Value) -> Scn {
        let participants: BTreeMap<String, String> = serde_json::from_value(v["participants"].clone()).unwrap();
        let pcanon = enc(&v["participants"]);
        if let Some(c) = v.get("participants_canonical").and_then(Value::as_str) { assert_eq!(c, pcanon, "participants_canonical"); }
        Scn { instance: v["instance"].as_str().unwrap().into(), pcanon, participants,
              slices: serde_json::from_value(v.get("slices").cloned().unwrap_or(json!({}))).unwrap(),
              gsalts: serde_json::from_value(v.get("genesis_salts").cloned().unwrap_or(json!({}))).unwrap(),
              published: serde_json::from_value(v.get("published").cloned().unwrap_or(json!({}))).unwrap(),
              length: v.get("length").and_then(Value::as_u64) }
    }
    /// The genesis salt of `org`'s slice; only the prover has it.
    pub fn gsalt(&self, org: &str) -> &str {
        self.gsalts.get(org).map(String::as_str).unwrap_or_else(|| panic!("scenario has no genesis salt for {org}"))
    }
}

pub fn load_receipt(p: &Path) -> Receipt { bincode::deserialize(&std::fs::read(p).unwrap()).unwrap() }

// ----------------------------------------------------------------------------- environment

pub fn refuse_dev_mode() {
    if let Ok(v) = std::env::var("RISC0_DEV_MODE") {
        if !matches!(v.as_str(), "" | "0" | "false") {
            eprintln!("RISC0_DEV_MODE is set: proofs would be fake. Refusing to run.");
            std::process::exit(2);
        }
    }
    // default_prover() of risc0-zkvm 3.0.6 proves remotely when BONSAI_API_URL and BONSAI_API_KEY are set, and
    // RISC0_PROVER selects another prover; every measurement must come from the local r0vm (CPU)
    let remote = std::env::var("BONSAI_API_URL").is_ok() && std::env::var("BONSAI_API_KEY").is_ok();
    let other = std::env::var("RISC0_PROVER").map(|v| !matches!(v.as_str(), "" | "ipc")).unwrap_or(false);
    if remote || other {
        eprintln!("BONSAI_API_URL/BONSAI_API_KEY or RISC0_PROVER is set: proofs would not come from the local r0vm. Refusing to run.");
        std::process::exit(2);
    }
}

fn sh(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

fn rss_mb(field: &str) -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines().find(|l| l.starts_with(field)).and_then(|l| l.split_whitespace().nth(1)).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0) / 1024.0
}

pub fn env_info() -> Value {
    let cpu = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = cpu.lines().find(|l| l.starts_with("model name")).and_then(|l| l.split(':').nth(1)).unwrap_or("").trim().to_string();
    let logical = cpu.lines().filter(|l| l.starts_with("processor")).count();
    let mem = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let ram_kb: f64 = mem.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let pretty = os.lines().find(|l| l.starts_with("PRETTY_NAME")).unwrap_or("").trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string();
    json!({
        "cpu_model": model, "logical_threads": logical, "ram_mb": (ram_kb / 1024.0).round(),
        "os": pretty, "kernel": sh("uname", &["-r"]), "rustc_host": sh("rustc", &["--version"]),
        "zkvm": "RISC Zero", "risc0_zkvm_crate": risc0_zkvm::VERSION, "r0vm": sh("r0vm", &["--version"]),
        // the host is built without the `prove` feature, so default_prover() runs the r0vm binary as a child
        // process (ExternalProver); bench.py's peak memory (wait4 on the host) covers that child
        "prover_backend": "CPU: r0vm child process (risc0-zkvm ExternalProver 'ipc'; no cuda/metal)",
        "risc0_server_path_env": std::env::var("RISC0_SERVER_PATH").ok(),
        "dev_mode_env": std::env::var("RISC0_DEV_MODE").ok(),
        "dev_mode_off": std::env::var("RISC0_DEV_MODE").map(|v| matches!(v.as_str(), "" | "0" | "false")).unwrap_or(true),
        "guest_image_ids": {
            "full": hex(&words_to_bytes(&G_FULL_ID)), "iface": hex(&words_to_bytes(&G_IFACE_ID)),
            "chain": hex(&words_to_bytes(&G_CHAIN_ID)), "agg": hex(&words_to_bytes(&G_AGG_ID)),
        },
    })
}

fn words_to_bytes(w: &[u32; 8]) -> Vec<u8> { w.iter().flat_map(|x| x.to_le_bytes()).collect() }

// ----------------------------------------------------------------------------- hash examples

pub fn hashes(dir: &Path) -> i32 {
    let ex: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("hash_examples.json")).unwrap()).unwrap();
    let rec = json!({"type": "patch", "coverage": "full"});
    let salt = h(&["salt", "example"]);
    let salt0 = h(&["salt0", "example"]);
    let h0 = genesis("CVD-2026-0001", "vendorA", &salt0);
    let c = rec_commit(&salt, &enc(&rec));
    let pairs: Vec<(&str, String)> = vec![
        ("H('a')", h(&["a"])),
        ("H('a','bc')", h(&["a", "bc"])),
        ("H('ab','c')", h(&["ab", "c"])),
        ("enc(record)", enc(&rec)),
        ("salt", salt.clone()),
        ("commit = H('rec', salt, enc(record))", c.clone()),
        ("salt0 = H('salt0', 'example')", salt0.clone()),
        ("genesis = H('slice', 'CVD-2026-0001', 'vendorA', salt0)", h0.clone()),
        ("link = H('link', genesis, commit)", link(&h0, &c)),
        ("iface = H('iface','I','maintainer','vendorA','disclosure', nonce='n', H('body',''))",
         iface_commit("I", "maintainer", "vendorA", "disclosure", "n", "")),
        ("pdigest({'maintainer':'maintainer','vendorA':'vendor'})",
         pdigest(&enc(&json!({"maintainer": "maintainer", "vendorA": "vendor"})))),
    ];
    let mut bad = 0;
    for (k, got) in &pairs {
        let want = ex[*k].as_str().unwrap_or_else(|| panic!("missing key {k}"));
        let ok = want == got;
        bad += !ok as i32;
        println!("{} {k}", if ok { "ok  " } else { "FAIL" });
        if !ok { println!("   want {want}\n   got  {got}"); }
    }
    assert_eq!(ex.as_object().unwrap().len(), pairs.len(), "every example must be covered");
    println!("{} of {} hash examples reproduced", pairs.len() as i32 - bad, pairs.len());
    (bad != 0) as i32
}

// ----------------------------------------------------------------------------- proving

pub struct Proof { pub receipt: Receipt, pub cycles: u64, pub user_cycles: u64, pub segments: usize, pub prove_s: f64, pub rss_mb: f64 }

/// Executor environment; PROTO_PO2 (optional) sets the segment size limit (log2 cycles), default 20.
fn builder<'a>() -> risc0_zkvm::ExecutorEnvBuilder<'a> {
    let mut b = ExecutorEnv::builder();
    if let Ok(p) = std::env::var("PROTO_PO2") { b.segment_limit_po2(p.parse().unwrap()); }
    b
}

/// The receipt kind of the protocol (D11): a composite receipt holds one proof per segment, so its size reveals the
/// slice length; the auditor accepts only succinct receipts (check 1).
pub const PROTOCOL_KIND: &str = "succinct";

pub fn parse_variant(s: &str) -> Variant {
    match s { "full" => Variant::Full, "iface" => Variant::Iface, "chain" => Variant::Chain, _ => panic!("variant") }
}
pub fn parse_kind(s: &str) -> ProverOpts {
    match s { "composite" => ProverOpts::composite(), "succinct" => ProverOpts::succinct(), "groth16" => ProverOpts::groth16(), _ => panic!("kind") }
}

fn elf_and_id(variant: Variant) -> (&'static [u8], [u32; 8]) {
    match variant { Variant::Full => (G_FULL_ELF, G_FULL_ID), Variant::Iface => (G_IFACE_ELF, G_IFACE_ID), Variant::Chain => (G_CHAIN_ELF, G_CHAIN_ID) }

    
}
pub fn variant_name(v: Variant) -> &'static str { match v { Variant::Full => "full", Variant::Iface => "iface", Variant::Chain => "chain" } }
pub fn full_image_id() -> [u32; 8] { G_FULL_ID }

pub fn receipt_kind(r: &Receipt) -> &'static str {
    match &r.inner {
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Succinct(_) => "succinct",
        InnerReceipt::Groth16(_) => "groth16",
        InnerReceipt::Fake(_) => "FAKE",
        _ => "other",
    }
}

fn run_prover(env: ExecutorEnv<'_>, elf: &[u8], opts: &ProverOpts) -> Result<Proof, String> {
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, elf, opts).map_err(|e| format!("{e:#}"))?;
    let prove_s = t.elapsed().as_secs_f64();
    if receipt_kind(&info.receipt) == "FAKE" { return Err("a fake receipt was produced (dev mode)".into()); }
    Ok(Proof { cycles: info.stats.total_cycles, user_cycles: info.stats.user_cycles, segments: info.stats.segments,
               receipt: info.receipt, prove_s, rss_mb: rss_mb("VmHWM") })
}

/// One organisation's proof. An abort in the guest is a panic, so this returns `Err` and no receipt exists.
/// The guest's input, in the order methods/guest/src/lib.rs reads it: statement, instance, participants and org
/// (public), then the genesis salt and the entries (private).
fn org_env<'a>(mut b: risc0_zkvm::ExecutorEnvBuilder<'a>, stmt: &str, instance: &str, pcanon: &str, org: &str, salt0: &str,
               entries: &[(String, String)]) -> Result<ExecutorEnv<'a>, String> {
    let blob = encode_entries(entries);
    b.write(&stmt.to_string()).unwrap().write(&instance.to_string()).unwrap().write(&pcanon.to_string()).unwrap()
        .write(&org.to_string()).unwrap().write(&salt0.to_string()).unwrap()
        .write(&(blob.len() as u32)).unwrap().write_slice(&blob);
    b.build().map_err(|e| e.to_string())
}

pub fn prove_org(variant: Variant, kind: &str, stmt: &str, instance: &str, pcanon: &str, org: &str, salt0: &str,
                 entries: &[(String, String)]) -> Result<Proof, String> {
    // A succinct receipt names the recursion program that made it last (`control_id`, public). For a single segment
    // that is the lift program of the segment's size, lift_rv32im_v2_<po2>, which reveals the slice length band;
    // with two or more segments it is join.zkr, the same for every length. So a slice that fits one segment is split
    // into two by halving the segment limit (the cost is one extra join).
    let mut po2 = None;
    if kind == "succinct" {
        let s = exec_org(variant, stmt, instance, pcanon, org, salt0, entries)?;
        if s["segments"] == 1 { po2 = Some(s["po2"][0].as_u64().unwrap() as u32 - 1); }
    }
    let mut b = builder();
    if let Some(p) = po2 { b.segment_limit_po2(p); }
    let env = org_env(b, stmt, instance, pcanon, org, salt0, entries)?;
    run_prover(env, elf_and_id(variant).0, &parse_kind(kind))
}

/// The name of the recursion program behind a succinct receipt's control id (e.g. "join.zkr").
pub fn control_program(r: &Receipt) -> Option<&'static str> {
    let id = r.inner.succinct().ok()?.control_id;
    POSEIDON2_CONTROL_IDS.iter().chain(SHA256_CONTROL_IDS.iter()).find(|(_, d)| *d == id).map(|(n, _)| *n)
}

/// Executor only: cycles and segments without a proof.
pub fn exec_org(variant: Variant, stmt: &str, instance: &str, pcanon: &str, org: &str, salt0: &str,
                entries: &[(String, String)]) -> Result<Value, String> {
    let env = org_env(builder(), stmt, instance, pcanon, org, salt0, entries)?;
    let t = Instant::now();
    let s = risc0_zkvm::default_executor().execute(env, elf_and_id(variant).0).map_err(|e| format!("{e:#}"))?;
    Ok(json!({"variant": variant_name(variant), "segments": s.segments.len(), "cycles": s.cycles(), "padded_cycles": s.segments.iter().map(|x| 1u64 << x.po2).sum::<u64>(), "po2": s.segments.iter().map(|x| x.po2).collect::<Vec<_>>(), "exec_s": t.elapsed().as_secs_f64(),
              "journal_bytes": s.journal.bytes.len(), "journal": serde_json::from_slice::<Value>(&s.journal.bytes).unwrap_or(Value::Null)}))
}

/// Executor only, every organisation of a scenario in one process (differential tests run thousands of slices):
/// {"orgs": org -> {"journal", "cycles", "padded_cycles"} or {"aborted": reason}, "audit": output of checks 2-7
/// on the journals, or {"rejected": check}; no audit if a guest aborted}.
pub fn exec_all(st: &Stmt, sc: &Scn) -> Value {
    let mut orgs = serde_json::Map::new();
    let mut js = Vec::new();
    for (org, entries) in &sc.slices {
        orgs.insert(org.clone(), match exec_org(Variant::Full, &st.canonical, &sc.instance, &sc.pcanon, org, sc.gsalt(org), entries) {
            Ok(m) => {
                if let Ok(j) = serde_json::from_value::<Journal>(m["journal"].clone()) { js.push(j); }
                json!({"journal": m["journal"], "cycles": m["cycles"], "padded_cycles": m["padded_cycles"]})
            }
            Err(e) => json!({"aborted": e}),
        });
    }
    let audit = if js.len() == sc.slices.len() {
        match audit_journals(st, sc, &sc.published, &js) { Ok(o) => o, Err(r) => json!({"rejected": r.check, "reason": r.reason}) }
    } else { Value::Null };
    json!({"orgs": orgs, "audit": audit})
}

/// Native baseline: Algorithm 5.1 of the same core library, run on the host CPU without a zkVM. Returns the
/// median of `reps` runs in seconds and the journal (which must equal the zkVM's).
pub fn native_org(stmt: &str, sc: &Scn, org: &str, reps: usize) -> Result<Value, String> {
    let blob = encode_entries(&sc.slices[org]);
    let mut times = Vec::new();
    let mut j = None;
    for _ in 0..reps.max(1) {
        let t = Instant::now();
        let entries = decode_entries(&blob)?;
        let r = guest(Variant::Full, stmt, &sc.instance, &sc.pcanon, org, sc.gsalt(org), &entries)?;
        times.push(t.elapsed().as_secs_f64());
        j = Some(r);
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Ok(json!({"org": org, "records": sc.slices[org].len(), "reps": times.len(), "native_s_median": times[times.len() / 2],
              "native_s_min": times[0], "native_s_max": times[times.len() - 1], "journal": j}))
}

/// Executor-only cost of the aggregation guest. The receipts it verifies are placeholders (the executor only
/// matches claims; the proofs of the assumptions are resolved when proving), so this gives the guest's own
/// cycles, which do not depend on the machine. It is NOT a measurement of proving the aggregate.
pub fn exec_agg(st: &Stmt, sc: &Scn) -> Result<Value, String> {
    let eng = Engine(None);
    let mut journals = Vec::new();
    for org in sc.participants.keys() {
        journals.push(eng.run(Variant::Full, "composite", &st.canonical, &sc.instance, &sc.pcanon, org, sc.gsalt(org), &sc.slices[org])?.journal);
    }
    let mut b = builder();
    b.write(&st.canonical).unwrap().write(&sc.instance).unwrap().write(&sc.pcanon).unwrap().write(&G_FULL_ID).unwrap().write(&journals).unwrap();
    for j in &journals {
        let claim = ReceiptClaim::ok(G_FULL_ID, j.clone());
        b.add_assumption(Receipt::new(InnerReceipt::Fake(FakeReceipt::new(claim)), j.clone()));
    }
    let t = Instant::now();
    let s = risc0_zkvm::default_executor().execute(b.build().map_err(|e| e.to_string())?, G_AGG_ELF).map_err(|e| format!("{e:#}"))?;
    Ok(json!({"variant": "agg", "statement": st.name, "n": sc.participants.len() - 1, "L": sc.length, "n_inputs": journals.len(),
              "segments": s.segments.len(), "cycles": s.cycles(), "padded_cycles": s.segments.iter().map(|x| 1u64 << x.po2).sum::<u64>(),
              "journal_bytes": s.journal.bytes.len(), "exec_s": t.elapsed().as_secs_f64(),
              "journal": serde_json::from_slice::<Value>(&s.journal.bytes).unwrap_or(Value::Null)}))
}

/// The aggregate proof. With `composite` the receipt carries the organisations' receipts as unresolved
/// assumption receipts (risc0-zkvm 3.0.6, `CompositeReceipt::assumption_receipts`), so whoever receives it also
/// receives their claims; with `succinct` the prover resolves the assumptions and the auditor gets one
/// receipt whose only claim is the aggregation guest's. The protocol therefore uses `succinct` (Section 5.3).
pub fn prove_agg(st: &Stmt, sc: &Scn, receipts: &[Receipt], kind: &str) -> Result<Proof, String> {
    let journals: Vec<Vec<u8>> = receipts.iter().map(|r| r.journal.bytes.clone()).collect();
    let mut b = builder();
    b.write(&st.canonical).unwrap().write(&sc.instance).unwrap().write(&sc.pcanon).unwrap().write(&G_FULL_ID).unwrap().write(&journals).unwrap();
    for r in receipts { b.add_assumption(r.clone()); }
    run_prover(b.build().map_err(|e| e.to_string())?, G_AGG_ELF, &parse_kind(kind))
}

/// `prove_agg` (succinct) with the proof cache of the acceptance test: the receipt and its proving metrics are kept
/// next to the organisations' receipts, keyed by the aggregation guest's image id and its inputs, so that resuming
/// acceptance_prove.sh does not prove the aggregates again (the `prove_s` then is the one of the first run).
pub fn prove_agg_cached(dir: &Path, st: &Stmt, sc: &Scn, receipts: &[Receipt]) -> Result<Proof, String> {
    let image = hex(&words_to_bytes(&G_AGG_ID));
    let full = hex(&words_to_bytes(&G_FULL_ID));
    let js: Vec<String> = receipts.iter().map(|r| String::from_utf8_lossy(&r.journal.bytes).into_owned()).collect();
    let mut parts: Vec<&str> = vec!["agg", "succinct", &image, &full, &st.canonical, &sc.instance, &sc.pcanon];
    parts.extend(js.iter().map(String::as_str));
    let key = h(&parts);
    let (f, meta) = (dir.join(format!("{key}.receipt")), dir.join(format!("{key}.json")));
    if f.exists() && meta.exists() {
        let m: Value = serde_json::from_str(&std::fs::read_to_string(&meta).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        return Ok(Proof { receipt: load_receipt(&f), cycles: m["cycles"].as_u64().unwrap_or(0), user_cycles: m["user_cycles"].as_u64().unwrap_or(0),
                          segments: m["segments"].as_u64().unwrap_or(0) as usize, prove_s: m["prove_s"].as_f64().unwrap_or(f64::NAN), rss_mb: 0.0 });
    }
    let p = prove_agg(st, sc, receipts, "succinct")?;
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(&f, bincode::serialize(&p.receipt).unwrap()).unwrap();
    std::fs::write(&meta, json!({"prove_s": p.prove_s, "cycles": p.cycles, "user_cycles": p.user_cycles, "segments": p.segments}).to_string()).unwrap();
    Ok(p)
}

/// EQ2 for the aggregated mode: which organisation journals can be read out of the aggregate receipt the auditor
/// receives (byte search in its serialised form), and how many assumption receipts it embeds.
pub fn agg_leak(agg: &Receipt, org_receipts: &[Receipt]) -> Value {
    let bytes = bincode::serialize(agg).unwrap();
    // a journal can be present as its bytes or as its SHA-256 digest inside a claim
    let found: Vec<String> = org_receipts.iter()
        .filter(|r| contains(&bytes, &r.journal.bytes) || contains(&bytes, risc0_zkvm::sha::Impl::hash_bytes(&r.journal.bytes).as_bytes()))
        .filter_map(|r| serde_json::from_slice::<Journal>(&r.journal.bytes).ok().map(|j| j.org)).collect();
    let embedded = match &agg.inner { InnerReceipt::Composite(c) => c.assumption_receipts.len(), _ => 0 };
    json!({"receipt_kind": receipt_kind(agg), "embedded_assumption_receipts": embedded, "control_id": control_id(agg),
           "control_program": control_program(agg),
           "org_journals_readable": found, "leaks": !found.is_empty() || embedded > 0})
}

/// The control id of a succinct receipt (public; it names the recursion program that produced the receipt).
pub fn control_id(r: &Receipt) -> Option<String> {
    r.inner.succinct().ok().map(|s| format!("{}", s.control_id))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool { !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle) }

pub fn metrics(p: &Proof, st: &Stmt, sc: &Scn, org: &str, variant: &str, kind: &str) -> Value {
    let id = if variant == "agg" { G_AGG_ID } else { elf_and_id(parse_variant(variant)).1 };
    let t = Instant::now();
    let v = p.receipt.verify(id);
    let verify_s = t.elapsed().as_secs_f64();
    assert!(v.is_ok(), "own receipt does not verify");
    let role = sc.participants.get(org).cloned().unwrap_or_else(|| "aggregator".into());
    json!({
        "statement": st.name, "n": sc.participants.len() - 1, "L": sc.length, "org": org, "role": role,
        "records": sc.slices.get(org).map(|s| s.len()), "variant": variant,
        "cycles": p.cycles, "user_cycles": p.user_cycles, "segments": p.segments, "prove_s": p.prove_s,
        "host_vmhwm_mb": p.rss_mb, "receipt_kind": receipt_kind(&p.receipt), "requested_kind": kind,
        "receipt_bytes": bincode::serialize(&p.receipt).unwrap().len(), "journal_bytes": p.receipt.journal.bytes.len(),
        "verify_s": verify_s, "control_id": control_id(&p.receipt), "control_program": control_program(&p.receipt),
    })
}

/// Runs the guest for one organisation. With a cache directory it produces real proofs, cached on disk by input so
/// that the acceptance and attack tests do not prove the same slice twice (measurements never use the cache);
/// without one (`--exec-only`) it only executes the guest in the zkVM executor, which is enough to test the logic.
pub struct Engine(pub Option<PathBuf>);

pub struct Run { pub journal: Vec<u8>, pub receipt: Option<Receipt> }

impl Engine {
    pub fn run(&self, variant: Variant, kind: &str, stmt: &str, instance: &str, pcanon: &str, org: &str, salt0: &str,
               entries: &[(String, String)]) -> Result<Run, String> {
        let Some(dir) = &self.0 else {
            let env = org_env(builder(), stmt, instance, pcanon, org, salt0, entries)?;
            let s = risc0_zkvm::default_executor().execute(env, elf_and_id(variant).0).map_err(|e| format!("{e:#}"))?;
            return Ok(Run { journal: s.journal.bytes, receipt: None });
        };
        // the cache key includes the guest's image id, so a rebuilt guest never reuses an old receipt
        let image = hex(&words_to_bytes(&elf_and_id(variant).1));
        let mut parts: Vec<&str> = vec![variant_name(variant), kind, &image, stmt, instance, pcanon, org, salt0];
        for (e, s) in entries { parts.push(e); parts.push(s); }
        let f = dir.join(format!("{}.receipt", h(&parts)));
        let r = if f.exists() { load_receipt(&f) } else {
            let p = prove_org(variant, kind, stmt, instance, pcanon, org, salt0, entries)?;
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(&f, bincode::serialize(&p.receipt).unwrap()).unwrap();
            p.receipt
        };
        Ok(Run { journal: r.journal.bytes.clone(), receipt: Some(r) })
    }
}

// ----------------------------------------------------------------------------- auditor (C5)

fn rej<T>(check: u8, reason: &str) -> Result<T, Reject> { Err(Reject { check, reason: reason.into() }) }

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Check 4: the head equals the published one and the Ed25519 signature over instance || head verifies.
pub fn check_4(instance: &str, heads: &BTreeMap<String, String>, published: &BTreeMap<String, Pub>) -> Result<(), Reject> {
    for (org, head) in heads {
        let Some(p) = published.get(org) else { return rej(4, "no published slice commitment") };
        if &p.head != head { return rej(4, "proof is not about the slice it committed to at closure"); }
        let ok = (|| {
            let pk: [u8; 32] = unhex(&p.pubkey)?.try_into().ok()?;
            let sig: [u8; 64] = unhex(&p.sig)?.try_into().ok()?;
            VerifyingKey::from_bytes(&pk).ok()?.verify(format!("{instance}{head}").as_bytes(), &Signature::from_bytes(&sig)).ok()
        })();
        if ok.is_none() { return rej(4, "bad signature on the slice commitment"); }
    }
    Ok(())
}

fn verified(r: &Receipt, id: [u32; 8]) -> bool { receipt_kind(r) != "FAKE" && r.verify(id).is_ok() }

/// Check 1 also requires the protocol's receipt kind (D11).
fn check_kind(r: &Receipt, program: &str) -> Result<(), Reject> {
    if receipt_kind(r) != PROTOCOL_KIND { return rej(1, "receipt is not succinct (a composite receipt reveals its segment count, D11)"); }
    // the control id must name a program whose identity does not depend on the slice length (see prove_org)
    if control_program(r) != Some(program) { return rej(1, "succinct receipt not finished by the expected recursion program (a lift program reveals the segment size)"); }
    Ok(())
}

/// Checks 1-7 in this order, stopping at the first failure (mode 'verdict, responsible', and the per-organisation
/// receipts of mode 'verdict').
pub fn audit(st: &Stmt, sc: &Scn, published: &BTreeMap<String, Pub>, receipts: &[Receipt], image: &[u32; 8]) -> Result<Value, Reject> {
    let mut js = Vec::new();
    for r in receipts {
        if !verified(r, *image) { return rej(1, "receipt does not verify against the guest's program identifier"); }
        check_kind(r, "join.zkr")?;
        match serde_json::from_slice::<Journal>(&r.journal.bytes) {
            Ok(j) => js.push(j),
            Err(_) => return rej(1, "malformed journal"),
        }
    }
    audit_journals(st, sc, published, &js)
}

/// Checks 2-7 on journals whose proofs were verified (or, in exec-only tests, only executed).
pub fn audit_journals(st: &Stmt, sc: &Scn, published: &BTreeMap<String, Pub>, js: &[Journal]) -> Result<Value, Reject> {
    let parts = check_2_3(&st.id, &sc.instance, &sc.pcanon, js)?;
    check_4(&sc.instance, &js.iter().map(|j| (j.org.clone(), j.head.clone())).collect(), published)?;
    let c = check_5_6_7(&parts, js)?;
    Ok(if st.disclosure == "verdict+responsible" { json!({"verdict": c.verdict, "per_org": c.per_org}) } else { json!({"verdict": c.verdict}) })
}

/// Audit over runs of the engine: real receipts (check 1 included) or, in exec-only mode, their journals.
pub fn audit_runs(st: &Stmt, sc: &Scn, published: &BTreeMap<String, Pub>, runs: &[Run]) -> Result<Value, Reject> {
    if runs.iter().all(|r| r.receipt.is_some()) {
        let rs: Vec<Receipt> = runs.iter().map(|r| r.receipt.clone().unwrap()).collect();
        return audit(st, sc, published, &rs, &G_FULL_ID);
    }
    let js: Vec<Journal> = runs.iter().filter_map(|r| serde_json::from_slice(&r.journal).ok()).collect();
    audit_journals(st, sc, published, &js)
}

/// Auditor in mode 'verdict' with the aggregation guest: one receipt, heads and verdict only; check 4 on the heads.
pub fn audit_agg(st: &Stmt, sc: &Scn, published: &BTreeMap<String, Pub>, r: &Receipt) -> Result<Value, Reject> {
    if !verified(r, G_AGG_ID) { return rej(1, "aggregate receipt does not verify"); }
    check_kind(r, "resolve.zkr")?;
    let Ok(a) = serde_json::from_slice::<AggJournal>(&r.journal.bytes) else { return rej(1, "malformed journal") };
    audit_agg_journal(st, sc, published, &a)
}

/// The checks of `audit_agg` after receipt verification (also used on executor-only aggregate journals).
pub fn audit_agg_journal(st: &Stmt, sc: &Scn, published: &BTreeMap<String, Pub>, a: &AggJournal) -> Result<Value, Reject> {
    if a.guest_id != hex(&words_to_bytes(&G_FULL_ID)) { return rej(1, "aggregate was built over another guest program"); }
    if a.sid != st.id || a.instance != sc.instance { return rej(2, "wrong statement or instance"); }
    if a.pdigest != pdigest(&sc.pcanon) { return rej(2, "aggregate assumes another participant set"); }
    let want: Vec<&String> = sc.participants.keys().collect();
    if a.heads.keys().collect::<Vec<_>>() != want { return rej(3, "heads are not exactly the participant set"); }
    check_4(&sc.instance, &a.heads, published)?;
    Ok(json!({"verdict": a.verdict}))
}

// ----------------------------------------------------------------------------- acceptance test (EQ1, items 2 and 3)

fn read_json(p: PathBuf) -> Value { serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}"))).unwrap() }

/// A reference journal with its interface entries in the guest's output order (`sort_iface`); the reference model
/// lists them in record order. Everything else is compared as given.
fn canonical_journal(v: &Value) -> Value {
    match serde_json::from_value::<Journal>(v.clone()) {
        Ok(mut j) => { sort_iface(&mut j.iface); serde_json::to_value(j).unwrap() }
        Err(_) => v.clone(),
    }
}

fn stmts(vdir: &Path) -> BTreeMap<String, Stmt> {
    (1..=5).map(|i| (format!("Q{i}"), Stmt::load(&vdir.join(format!("statements/Q{i}.json"))))).collect()
}

pub fn accept(vdir: &Path, cache: Option<&Path>, out: &Path, with_agg: bool, scenarios: &[String]) -> i32 {
    let st = stmts(vdir);
    let eng = Engine(cache.map(|c| c.to_path_buf()));
    let real = cache.is_some();
    let mut rows = Vec::new();
    let (mut journals_ok, mut journals_n, mut audits_ok, mut audits_n) = (0, 0, 0, 0);
    let (mut aggs_ok, mut aggs_n) = (0, 0);
    for sname in scenarios {
        let sname = sname.as_str();
        let raw = read_json(vdir.join(format!("scenarios/{sname}.json")));
        let sc = Scn::from_value(&raw);
        for (qname, q) in &st {
            let exp = &raw["expected"][qname];
            let mut runs = Vec::new();
            let mut per_org = Vec::new();
            for org in sc.participants.keys() {
                let t = Instant::now();
                let r = eng.run(Variant::Full, PROTOCOL_KIND, &q.canonical, &sc.instance, &sc.pcanon, org, sc.gsalt(org), &sc.slices[org]);
                journals_n += 1;
                let r = match r { Ok(r) => r, Err(e) => { println!("GUEST FAILED {sname} {qname} {org}: {e}"); per_org.push(json!({"org": org, "journal_equal": false, "error": e})); continue; } };
                let got: Value = serde_json::from_slice(&r.journal).unwrap();
                let eq = got == canonical_journal(&exp["journals"][org]);
                journals_ok += eq as i32;
                if !eq { println!("JOURNAL MISMATCH {sname} {qname} {org}\n got  {got}\n want {}", canonical_journal(&exp["journals"][org])); }
                per_org.push(json!({"org": org, "journal_equal": eq, "records": sc.slices[org].len(), "seconds": t.elapsed().as_secs_f64()}));
                runs.push(r);
            }
            let res = audit_runs(q, &sc, &sc.published, &runs);
            let want = &exp["audit"];
            let (got, ok) = match &res { Ok(o) => (o.clone(), o == want), Err(r) => (json!({"rejected": r.check, "reason": r.reason}), false) };
            audits_n += 1; audits_ok += ok as i32;
            let mut row = json!({"scenario": sname, "statement": qname, "audit_expected": want, "audit_got": got, "audit_equal": ok, "orgs": per_org});
            if with_agg && q.disclosure == "verdict" {
                // the aggregate journal is compared with the vectors in both modes; real proofs add the receipt
                // (succinct, so the assumptions are resolved) and the check that it carries no organisation journal
                let e = &exp["aggregate_journal"];
                let res: Result<(Value, Value), String> = if real {
                    let rs: Vec<Receipt> = runs.iter().map(|r| r.receipt.clone().unwrap()).collect();
                    prove_agg_cached(cache.unwrap(), q, &sc, &rs).map(|p| {
                        let j: Value = serde_json::from_slice(&p.receipt.journal.bytes).unwrap();
                        let ar = audit_agg(q, &sc, &sc.published, &p.receipt);
                        (j, json!({"auditor_output": ar.map_err(|r| r.check).ok(), "prove_s": p.prove_s, "cycles": p.cycles,
                                   "receipt_kind": receipt_kind(&p.receipt), "receipt_bytes": bincode::serialize(&p.receipt).unwrap().len(),
                                   "leak": agg_leak(&p.receipt, &rs)}))
                    })
                } else {
                    exec_agg(q, &sc).map(|m| {
                        let j = m["journal"].clone();
                        let ar = serde_json::from_value::<AggJournal>(j.clone()).map_err(|e| e.to_string())
                            .and_then(|a| audit_agg_journal(q, &sc, &sc.published, &a).map_err(|r| r.reason));
                        (j, json!({"auditor_output": ar.ok(), "cycles": m["cycles"]}))
                    })
                };
                row["aggregate"] = match res {
                    Ok((j, mut info)) => {
                        let same = ["sid", "instance", "heads", "verdict"].iter().all(|k| j[*k] == e[*k]);
                        let out_ok = info["auditor_output"] == *want;
                        let leak = info["leak"]["leaks"] == true;
                        let agg_ok = same && out_ok && !leak;
                        aggs_n += 1; aggs_ok += agg_ok as i32;
                        println!("   aggregate {sname} {qname}: journal equal {same}, auditor output equal {out_ok}{}",
                                 if real { format!(", leaks {leak}") } else { String::new() });
                        info["journal_equal"] = json!(same); info["auditor_output_equal"] = json!(out_ok); info["pass"] = json!(agg_ok);
                        info["journal"] = j;
                        info
                    }
                    Err(e) => { aggs_n += 1; json!({"error": e, "pass": false}) }
                };
            }
            println!("{sname} {qname:<3} journals ok {}/{}  audit {}  {}", per_org.iter().filter(|o| o["journal_equal"] == true).count(), per_org.len(),
                     if ok { "OK" } else { "MISMATCH" }, got);
            rows.push(row);
        }
    }
    println!("journals equal: {journals_ok}/{journals_n}; audit outputs equal: {audits_ok}/{audits_n}; aggregates as expected: {aggs_ok}/{aggs_n}  ({})", if real { "real proofs" } else { "executor only, NOT proved" });
    std::fs::write(out, serde_json::to_string_pretty(&json!({"real_proofs": real, "scenarios": scenarios,
        "journals_equal": journals_ok, "journals_total": journals_n,
        "audits_equal": audits_ok, "audits_total": audits_n, "aggregates_ok": aggs_ok, "aggregates_total": aggs_n, "rows": rows})).unwrap()).unwrap();
    (journals_ok != journals_n || audits_ok != audits_n || aggs_ok != aggs_n) as i32
}

// ----------------------------------------------------------------------------- attacks (EQ1, item 4)

fn allowed_checks(expected_check: &str) -> Vec<u8> {
    let head = expected_check.split(',').next().unwrap_or("");
    head.split(|c: char| !c.is_ascii_digit()).filter_map(|s| s.parse().ok()).collect()
}

pub fn attacks(vdir: &Path, cache: Option<&Path>, out: &Path) -> i32 {
    let st = stmts(vdir);
    let eng = Engine(cache.map(|c| c.to_path_buf()));
    let a = read_json(vdir.join("attacks.json"));
    let base_raw = read_json(vdir.join("scenarios/S1.json"));
    let base = Scn::from_value(&base_raw);
    let mut rows = Vec::new();
    let mut bad = 0;
    for c in a["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let q = &st[c["statement"].as_str().unwrap()];
        let exp = &c["expected"];
        // the input of the case
        let (sc, only_changed) = if c.get("slices").is_some() {
            (Scn::from_value(c), false)                                       // limit case: complete inputs
        } else if c.get("instance").is_some() {
            let mut s = Scn::from_value(c);                                   // embargo cases: one slice, guest only
            s.slices = serde_json::from_value(c["slices_changed"].clone()).unwrap();
            (s, true)
        } else {
            let mut s = Scn::from_value(&base_raw);
            let ch: BTreeMap<String, Vec<(String, String)>> = serde_json::from_value(c["slices_changed"].clone()).unwrap();
            let pc: BTreeMap<String, Pub> = serde_json::from_value(c["published_changed"].clone()).unwrap();
            s.slices.extend(ch); s.published.extend(pc);
            (s, false)
        };
        let orgs: Vec<String> = sc.slices.keys().cloned().collect();
        let mut runs = Vec::new();
        let mut guest_fail = None;
        for org in &orgs {
            if name == "one participant withholds its proof" && org == "vendorC" { continue; }
            let qq = if name == "proof for an easier statement" && org == "vendorC" { &st["Q1"] } else { q };
            match eng.run(Variant::Full, PROTOCOL_KIND, &qq.canonical, &sc.instance, &sc.pcanon, org, sc.gsalt(org), &sc.slices[org]) {
                Ok(r) => runs.push(r),
                Err(e) => { guest_fail = Some(e); break; }
            }
        }
        let (got, ok, detail): (Value, bool, String) = if let Some(e) = guest_fail {
            (json!({"rejected_by": "guest"}), exp["rejected_by"] == "guest", e)
        } else if only_changed {
            (json!({"accepted": "a proof exists"}), false, String::new())
        } else {
            match audit_runs(q, &sc, &sc.published, &runs) {
                Ok(o) => (json!({"accepted": o.clone()}), exp.get("accepted") == Some(&o), String::new()),
                Err(r) => {
                    let allowed = allowed_checks(c["expected_check"].as_str().unwrap_or(""));
                    (json!({"rejected_by": "auditor", "check": r.check}),
                     exp["rejected_by"] == "auditor" && allowed.contains(&r.check), r.reason)
                }
            }
        };
        bad += !ok as i32;
        println!("{} {name:<62} expected {:<28} got {} {}", if ok { "ok  " } else { "FAIL" },
                 c["expected_check"].as_str().unwrap_or("accepted"), got, detail);
        rows.push(json!({"name": name, "expected_check": c["expected_check"], "expected": exp, "got": got, "reason": detail, "pass": ok}));
    }
    if cache.is_some() {
        // extra case, not in attacks.json: check 1 (a receipt of another guest program)
        let sc = &base;
        let q = &st["Q3"];
        let mut runs = Vec::new();
        for org in sc.participants.keys() {
            let variant = if org == "vendorC" { Variant::Iface } else { Variant::Full };
            runs.push(eng.run(variant, PROTOCOL_KIND, &q.canonical, &sc.instance, &sc.pcanon, org, sc.gsalt(org), &sc.slices[org]).unwrap());
        }
        let r = audit_runs(q, sc, &sc.published, &runs);
        let ok = matches!(&r, Err(x) if x.check == 1);
        bad += !ok as i32;
        println!("{} {:<62} expected 1 (extra case)   got {:?}", if ok { "ok  " } else { "FAIL" }, "receipt of another guest program", r.as_ref().err().map(|e| e.check));
        rows.push(json!({"name": "receipt of another guest program (extra)", "expected_check": "1", "pass": ok}));
    }
    println!("{} of {} cases as expected ({})", rows.len() as i32 - bad, rows.len(), if cache.is_some() { "real proofs" } else { "executor only, NOT proved" });
    std::fs::write(out, serde_json::to_string_pretty(&json!({"real_proofs": cache.is_some(), "rows": rows, "failures": bad})).unwrap()).unwrap();
    (bad != 0) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_journal_rejects_another_participant_set() {
        let participants: BTreeMap<String, String> = [
            ("maintainer".to_string(), "maintainer".to_string()),
            ("vendorA".to_string(), "vendor".to_string()),
        ].into();
        let sc = Scn {
            instance: "I".into(),
            pcanon: enc(&json!(participants)),
            participants,
            slices: BTreeMap::new(),
            gsalts: BTreeMap::new(),
            published: BTreeMap::new(),
            length: None,
        };
        let st = Stmt { name: "Q2".into(), canonical: "{}".into(), id: "sid".into(), disclosure: "verdict".into() };
        let a = AggJournal {
            sid: st.id.clone(),
            instance: sc.instance.clone(),
            guest_id: hex(&words_to_bytes(&G_FULL_ID)),
            pdigest: "another participant set".into(),
            heads: BTreeMap::new(),
            verdict: "complied".into(),
        };
        let err = audit_agg_journal(&st, &sc, &sc.published, &a).unwrap_err();
        assert_eq!(err.check, 2);
        assert!(err.reason.contains("participant set"));
    }
}
