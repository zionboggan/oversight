//! Standalone helper for cross-language ML-KEM-768 hybrid KEM conformance.
//!
//! This is a test aid, not a shipped CLI surface. It exposes the Rust
//! `hybrid_wrap_dek` / `hybrid_unwrap_dek` / `mlkem768_generate_keypair` to a
//! shell so `tests/conformance_hybrid_kem.py` can drive both sides of a
//! Python <-> Rust round trip.
//!
//! Usage:
//!   hybrid_kem_cli keygen
//!     -> stdout: {"x_pub":hex,"x_priv":hex,"mlkem_pub":hex,"mlkem_seed":hex}
//!   hybrid_kem_cli wrap <x_pub_hex> <mlkem_pub_hex> <dek_hex>
//!     -> stdout: HybridEnvelope JSON
//!   hybrid_kem_cli unwrap <env_json_file> <x_priv_hex> <mlkem_seed_hex>
//!     -> stdout: recovered dek hex

use std::env;

use oversight_crypto::{
    hybrid_unwrap_dek, hybrid_wrap_dek, mlkem768_generate_keypair, ClassicIdentity, HybridEnvelope,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args
        .get(1)
        .expect("usage: keygen | wrap <x_pub> <mlkem_pub> <dek> | unwrap <env_file> <x_priv> <mlkem_seed>");

    match cmd.as_str() {
        "keygen" => {
            let id = ClassicIdentity::generate();
            let (mlkem_pub, mlkem_seed) = mlkem768_generate_keypair();
            println!(
                "{{\"x_pub\":\"{}\",\"x_priv\":\"{}\",\"mlkem_pub\":\"{}\",\"mlkem_seed\":\"{}\"}}",
                hex::encode(id.x25519_pub),
                hex::encode(&id.x25519_priv[..]),
                hex::encode(&mlkem_pub),
                hex::encode(mlkem_seed),
            );
        }
        "wrap" => {
            let x_pub = hex::decode(args.get(2).expect("missing x_pub")).expect("x_pub hex");
            let mlkem_pub =
                hex::decode(args.get(3).expect("missing mlkem_pub")).expect("mlkem_pub hex");
            let dek = hex::decode(args.get(4).expect("missing dek")).expect("dek hex");
            let env = hybrid_wrap_dek(&dek, &x_pub, &mlkem_pub).expect("hybrid_wrap_dek");
            println!("{}", serde_json::to_string(&env).unwrap());
        }
        "unwrap" => {
            let env_json =
                std::fs::read_to_string(args.get(2).expect("missing env_file")).expect("read env");
            let env: HybridEnvelope =
                serde_json::from_str(&env_json).expect("parse HybridEnvelope");
            let x_priv = hex::decode(args.get(3).expect("missing x_priv")).expect("x_priv hex");
            let mlkem_seed =
                hex::decode(args.get(4).expect("missing mlkem_seed")).expect("mlkem_seed hex");
            let dek = hybrid_unwrap_dek(&env, &x_priv, &mlkem_seed).expect("hybrid_unwrap_dek");
            println!("{}", hex::encode(&*dek));
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    }
}
