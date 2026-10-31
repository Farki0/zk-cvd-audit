//! Aggregation guest program (mode "verdict"): verifies the organisations' receipts inside the zkVM
//! (as assumptions), runs checks 2, 3, 5, 6, 7 on their journals and outputs only the heads and the verdict.
use audit_core::{check_2_3, check_5_6_7, hex, pdigest, statement_id, AggJournal, Journal};
use risc0_zkvm::guest::env;
use std::collections::BTreeMap;

fn main() {
    let stmt: String = env::read();
    let instance: String = env::read();
    let participants: String = env::read();
    let guest_id: [u32; 8] = env::read();
    let journals: Vec<Vec<u8>> = env::read();
    let mut js = Vec::new();
    for b in &journals {
        env::verify(guest_id, b).expect("receipt of an organisation does not verify");
        js.push(serde_json::from_slice::<Journal>(b).expect("malformed journal"));
    }
    let sid = statement_id(&stmt);
    let parts = check_2_3(&sid, &instance, &participants, &js).unwrap_or_else(|e| panic!("check {}: {}", e.check, e.reason));
    let c = check_5_6_7(&parts, &js).unwrap_or_else(|e| panic!("check {}: {}", e.check, e.reason));
    let mut gid = Vec::new();
    for w in guest_id { gid.extend_from_slice(&w.to_le_bytes()); }
    let out = AggJournal { sid, instance, guest_id: hex(&gid), pdigest: pdigest(&participants), heads: c.heads, verdict: c.verdict };
    let _: &BTreeMap<String, String> = &out.heads;
    env::commit_slice(&serde_json::to_vec(&out).unwrap());
}