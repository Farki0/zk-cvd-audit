//! Prover host (C4), auditor (C5), acceptance tests, attack tests and single-proof measurement (for C8).
mod lib_host;
use lib_host::*;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the environment (for section 5.1).
    Env,
    /// Reproduce vectors/hash_examples.json.
    Hashes { #[arg(long)] vectors: PathBuf },
    /// Prove one organisation's slice for one statement; print one JSON line of metrics.
    Prove {
        #[arg(long)] stmt: PathBuf,
        #[arg(long)] scenario: PathBuf,
        #[arg(long)] org: String,
        #[arg(long, default_value = "full")] variant: String,
        #[arg(long, default_value = "succinct")] kind: String,
        #[arg(long)] out: Option<PathBuf>,
    },
    /// Audit: verify receipts and check them (checks 1-7); print one JSON line (declared output, audit_s).
    Audit {
        #[arg(long)] stmt: PathBuf,
        #[arg(long)] scenario: PathBuf,
        #[arg(long, num_args = 1.., required = true)] receipts: Vec<PathBuf>,
    },
    /// Acceptance tests 2 and 3 (and aggregation guest): S1-S3 x Q1-Q5 with real proofs.
    Accept {
        #[arg(long)] vectors: PathBuf,
        /// directory of the proof cache; without it the guest is only executed, not proved
        #[arg(long)] cache: Option<PathBuf>,
        #[arg(long)] out: PathBuf,
        #[arg(long, default_value_t = false)] no_agg: bool,
        /// scenarios to run (the reduced real-proof acceptance runs S1 only)
        #[arg(long, num_args = 1.., default_values_t = ["S1".to_string(), "S2".to_string(), "S3".to_string()])]
        scenarios: Vec<String>,
    },
    /// Acceptance test 4: the attack cases and the limit case.
    Attacks {
        #[arg(long)] vectors: PathBuf,
        #[arg(long)] cache: Option<PathBuf>,
        #[arg(long)] out: PathBuf,
    },
    /// Execute without proving (cycle counts only).
    Exec {
        #[arg(long)] stmt: PathBuf,
        #[arg(long)] scenario: PathBuf,
        #[arg(long)] org: String,
        #[arg(long, default_value = "full")] variant: String,
    },
    /// Aggregation guest (C7): prove the aggregate of the receipts of every organisation; print metrics.
    Agg {
        #[arg(long)] stmt: PathBuf,
        #[arg(long)] scenario: PathBuf,
        #[arg(long, num_args = 1.., required = true)] receipts: Vec<PathBuf>,
        #[arg(long)] out: Option<PathBuf>,
        /// succinct (the protocol: assumptions resolved) or composite (embeds the organisations' receipts)
        #[arg(long, default_value = "succinct")] kind: String,
    },
    /// Executor-only cycle count of the aggregation guest (placeholder receipts, no proof).
    AggExec {
        #[arg(long)] stmt: PathBuf,
        #[arg(long)] scenario: PathBuf,
    },
    /// Verify an aggregate receipt and check the heads (auditor in mode 'verdict').
    AuditAgg {
        #[arg(long)] stmt: PathBuf,
        #[arg(long)] scenario: PathBuf,
        #[arg(long)] agg: PathBuf,
    },
    /// Executor only, every organisation of the scenario: org -> journal and cycles, or the abort reason.
    ExecAll {
        #[arg(long)] stmt: PathBuf,
        #[arg(long)] scenario: PathBuf,
    },
    /// Native baseline: Algorithm 5.1 on the host CPU without the zkVM; median time of --reps runs.
    Native {
        #[arg(long)] stmt: PathBuf,
        #[arg(long)] scenario: PathBuf,
        #[arg(long)] org: String,
        #[arg(long, default_value_t = 21)] reps: usize,
    },
}

fn main() {
    refuse_dev_mode();
    match Cli::parse().cmd {
        Cmd::Env => println!("{}", env_info()),
        Cmd::Hashes { vectors } => std::process::exit(hashes(&vectors)),
        Cmd::Prove { stmt, scenario, org, variant, kind, out } => {
            let st = Stmt::load(&stmt);
            let sc = Scn::load(&scenario);
            let p = prove_org(parse_variant(&variant), &kind, &st.canonical, &sc.instance, &sc.pcanon, &org,
                              sc.gsalt(&org), &sc.slices[&org]).unwrap_or_else(|e| { eprintln!("PROVING FAILED: {e}"); std::process::exit(3) });
            let m = metrics(&p, &st, &sc, &org, &variant, &kind);
            if let Some(o) = out { std::fs::write(o, bincode::serialize(&p.receipt).unwrap()).unwrap(); }
            println!("{m}");
        }
        Cmd::Audit { stmt, scenario, receipts } => {
            let st = Stmt::load(&stmt);
            let sc = Scn::load(&scenario);
            let rs: Vec<_> = receipts.iter().map(|p| load_receipt(p)).collect();
            let t = std::time::Instant::now();
            let res = audit(&st, &sc, &sc.published, &rs, &full_image_id());
            let audit_s = t.elapsed().as_secs_f64();
            match res {
                Ok(o) => println!("{}", json!({"ok": true, "output": o, "audit_s": audit_s, "receipts": rs.len()})),
                Err(r) => { println!("{}", json!({"ok": false, "check": r.check, "reason": r.reason, "audit_s": audit_s})); std::process::exit(4) }
            }
        }
        Cmd::Accept { vectors, cache, out, no_agg, scenarios } =>
            std::process::exit(accept(&vectors, cache.as_deref(), &out, !no_agg, &scenarios)),
        Cmd::Attacks { vectors, cache, out } => std::process::exit(attacks(&vectors, cache.as_deref(), &out)),
        Cmd::Exec { stmt, scenario, org, variant } => {
            let st = Stmt::load(&stmt);
            let sc = Scn::load(&scenario);
            match exec_org(parse_variant(&variant), &st.canonical, &sc.instance, &sc.pcanon, &org, sc.gsalt(&org), &sc.slices[&org]) {
                Ok(m) => println!("{m}"),
                Err(e) => { println!("{}", json!({"aborted": e})); std::process::exit(3) }
            }
        }
        Cmd::Agg { stmt, scenario, receipts, out, kind } => {
            let st = Stmt::load(&stmt);
            let sc = Scn::load(&scenario);
            let rs: Vec<_> = receipts.iter().map(|p| load_receipt(p)).collect();
            let p = prove_agg(&st, &sc, &rs, &kind).unwrap_or_else(|e| { eprintln!("AGGREGATION FAILED: {e}"); std::process::exit(3) });
            let mut m = metrics(&p, &st, &sc, "aggregator", "agg", &kind);
            m["n_inputs"] = json!(rs.len());
            m["leak"] = agg_leak(&p.receipt, &rs);
            if let Some(o) = out { std::fs::write(o, bincode::serialize(&p.receipt).unwrap()).unwrap(); }
            println!("{m}");
        }
        Cmd::AggExec { stmt, scenario } => {
            let st = Stmt::load(&stmt);
            let sc = Scn::load(&scenario);
            match exec_agg(&st, &sc) {
                Ok(m) => println!("{m}"),
                Err(e) => { println!("{}", json!({"aborted": e})); std::process::exit(3) }
            }
        }
        Cmd::ExecAll { stmt, scenario } => {
            let st = Stmt::load(&stmt);
            println!("{}", exec_all(&st, &Scn::load(&scenario)));
        }
        Cmd::Native { stmt, scenario, org, reps } => {
            let st = Stmt::load(&stmt);
            match native_org(&st.canonical, &Scn::load(&scenario), &org, reps) {
                Ok(m) => println!("{m}"),
                Err(e) => { println!("{}", json!({"aborted": e})); std::process::exit(3) }
            }
        }
        Cmd::AuditAgg { stmt, scenario, agg } => {
            let st = Stmt::load(&stmt);
            let sc = Scn::load(&scenario);
            let r = load_receipt(&agg);
            let t = std::time::Instant::now();
            let res = audit_agg(&st, &sc, &sc.published, &r);
            let audit_s = t.elapsed().as_secs_f64();
            match res {
                Ok(o) => println!("{}", json!({"ok": true, "output": o, "audit_s": audit_s, "receipts": 1})),
                Err(r) => { println!("{}", json!({"ok": false, "check": r.check, "reason": r.reason})); std::process::exit(4) }
            }
        }
    }
    let _: Option<Value> = None;
}
