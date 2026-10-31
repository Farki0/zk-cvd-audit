use audit_core::{decode_entries, guest, Variant};
use risc0_zkvm::guest::env;

/// Reads the public parameters (statement, instance, participants, org) and the private input (the genesis salt and
/// the entries), runs Algorithm 5.1 and writes the journal. An abort is a panic: execution fails, so no proof exists.
pub fn run(variant: Variant) {
    let stmt: String = env::read();
    let instance: String = env::read();
    let participants: String = env::read();
    let org: String = env::read();
    let salt0: String = env::read();
    let n: u32 = env::read();
    let mut blob = vec![0u8; n as usize];
    env::read_slice(&mut blob);
    let entries = decode_entries(&blob).unwrap_or_else(|e| panic!("abort: {e}"));
    let j = guest(variant, &stmt, &instance, &participants, &org, &salt0, &entries).unwrap_or_else(|e| panic!("abort: {e}"));
    env::commit_slice(&serde_json::to_vec(&j).unwrap());
}